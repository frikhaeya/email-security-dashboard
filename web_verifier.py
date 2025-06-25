# === IMPORTS ===
from flask import Flask, render_template
import google.generativeai as genai
import os.path, base64, time, json, io, re, threading
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import PyPDF2
import docx

# === GLOBAL VARIABLES & SETUP ===
# A thread-safe way to store our alerts for the web page
alerts_history = []
alerts_lock = threading.Lock()

# Initialize Flask App
app = Flask(__name__)

# --- GEMINI API SETUP ---
try:
    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key: raise ValueError("GOOGLE_API_KEY environment variable not found.")
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel('gemini-1.5-flash-latest')
except Exception as e:
    print(f"🚨 Error configuring Gemini API: {e}"); exit()

# --- GMAIL API FUNCTION ---
GMAIL_SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

def get_full_email_data():
    creds = None
    if os.path.exists("token.json"): creds = Credentials.from_authorized_user_file("token.json", GMAIL_SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token: creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", GMAIL_SCOPES)
            creds = flow.run_local_server(port=0)
        with open("token.json", "w") as token: token.write(creds.to_json())
    try:
        service = build("gmail", "v1", credentials=creds)
        results = service.users().messages().list(userId="me", labelIds=['SENT'], maxResults=1).execute()
        messages = results.get('messages', [])
        if not messages: return None
        message_id = messages[0]['id']
        msg = service.users().messages().get(userId="me", id=message_id, format='full').execute()
        payload = msg['payload']
        headers = payload.get('headers', [])
        subject = "No Subject Found"
        recipients = []
        for header in headers:
            name = header.get('name')
            value = header.get('value')
            if name == 'Subject': subject = value
            if name in ['To', 'Cc', 'Bcc']:
                found_emails = re.findall(r'[\w\.\-]+@[\w\.\-]+', value)
                recipients.extend(found_emails)
        attachments = []
        if 'parts' in payload:
            for part in payload['parts']:
                if part.get('filename'):
                    if 'data' in part['body']: attachment_data = part['body']['data']
                    else:
                        att_id = part['body']['attachmentId']
                        att = service.users().messages().attachments().get(userId='me', messageId=message_id, id=att_id).execute()
                        attachment_data = att['data']
                    file_data = base64.urlsafe_b64decode(attachment_data.encode('UTF-8'))
                    attachments.append({'filename': part.get('filename'), 'data': file_data})
        return {'subject': subject, 'recipients': list(set(recipients)), 'attachments': attachments}
    except HttpError as error:
        print(f"🚨 An error occurred with the Gmail API: {error}"); return None

# --- "TRANSLATOR" & "BRAIN" FUNCTIONS ---
def read_file_content(filename, file_data):
    file_extension = os.path.splitext(filename)[1].lower()
    text = ""
    try:
        if file_extension in [".txt", ".csv", ".py", ".js", ".html", ".css"]: text = file_data.decode('utf-8', errors='ignore')
        elif file_extension == ".pdf":
            reader = PyPDF2.PdfReader(io.BytesIO(file_data))
            for page in reader.pages: text += page.extract_text()
        elif file_extension == ".docx":
            doc = docx.Document(io.BytesIO(file_data))
            for para in doc.paragraphs: text += para.text + "\n"
        else: return None
        return text
    except Exception as e: return None

def find_sensitive_data(file_content, filename):
    prompt = f"""You are a security analyst. Your task is to scan the following text for sensitive information. Look for these categories: "Email Address", "Phone Number", "Credit Card Number", "API Key", "Password", "Personal Address". Analyze the text provided below. If you find any sensitive data, return a JSON object with a key "contains_sensitive_data" set to true, and a "findings" array. Each object in the "findings" array should contain a "type" and the "value" you found. If you find no sensitive data, return a JSON object with the key "contains_sensitive_data" set to false and an empty "findings" array. Only return the JSON object, with no other text or explanations. TEXT TO ANALYZE: --- {file_content} ---"""
    try:
        generation_config = genai.types.GenerationConfig(response_mime_type="application/json")
        response = model.generate_content(prompt, generation_config=generation_config)
        return json.loads(response.text)
    except Exception as e: return {"contains_sensitive_data": False, "findings": []}

def analyze_recipients_for_suspicion(recipient_list):
    prompt = f"""You are a cybersecurity expert. Analyze the following list of email recipients. Identify any that look suspicious. A suspicious email could be: 1. From a public or disposable email service (e.g., mailinator.com) when the context seems professional. 2. A personal email address (e.g., @gmail.com) mixed with corporate emails. 3. A misspelled version of a common corporate domain (typosquatting). 4. An address that seems randomly generated. Return a JSON object with a key "is_suspicious" (true/false) and a key "findings" which is an array of objects. Each object in "findings" should have the "email" and a short "reason" for the suspicion. If nothing is suspicious, "is_suspicious" should be false and "findings" should be an empty array. Only return the JSON object. RECIPIENT LIST: {", ".join(recipient_list)}"""
    try:
        generation_config = genai.types.GenerationConfig(response_mime_type="application/json")
        response = model.generate_content(prompt, generation_config=generation_config)
        return json.loads(response.text)
    except Exception as e: return {"is_suspicious": False, "findings": []}

# === THE BACKGROUND WORKER THREAD ===
def background_worker():
    """This function runs in the background, checking email and adding alerts."""
    print("🚀 Background worker started. Checking for emails...")
    last_checked_email_subject = None

    while True:
        email_data = get_full_email_data()
        
        if email_data and email_data.get('subject') != last_checked_email_subject:
            print(f"\n🧐 Worker found new email: '{email_data['subject']}'")
            last_checked_email_subject = email_data['subject']
            
            # --- RECIPIENT CHECK ---
            if email_data.get('recipients'):
                recipient_report = analyze_recipients_for_suspicion(email_data['recipients'])
                if recipient_report.get("is_suspicious"):
                    with alerts_lock:
                        alerts_history.insert(0, {
                            'type': 'Recipient', 
                            'subject': email_data['subject'], 
                            'findings': recipient_report.get("findings", [])
                        })

            # --- ATTACHMENT DATA SCAN ---
            if email_data.get('attachments'):
                for attachment in email_data['attachments']:
                    content = read_file_content(attachment['filename'], attachment['data'])
                    if content:
                        data_report = find_sensitive_data(content, attachment['filename'])
                        if data_report.get("contains_sensitive_data"):
                            with alerts_lock:
                                alerts_history.insert(0, {
                                    'type': 'Data', 
                                    'subject': email_data['subject'], 
                                    'filename': attachment['filename'],
                                    'findings': data_report.get("findings", [])
                                })
        
        time.sleep(15)

# === THE WEB INTERFACE (FLASK ROUTES) ===
@app.route('/')
def home():
    """This function is called when a user visits the website."""
    print("🌐 Web page requested. Sending alerts.")
    with alerts_lock:
        # We pass a copy of the alerts to the HTML template
        return render_template('index.html', alerts=list(alerts_history))

# === MAIN ENTRY POINT ===
if __name__ == "__main__":
    # 1. Start the background worker in a separate thread
    worker_thread = threading.Thread(target=background_worker, daemon=True)
    worker_thread.start()
    
    # 2. Start the Flask web server
    print("🌍 Starting web server. Open http://127.0.0.1:5000 in your browser.")
    app.run(host='0.0.0.0', port=5000)
