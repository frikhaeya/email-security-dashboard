# Email Security Dashboard

This project is a real-time email security monitoring tool built with Python. It automatically analyzes emails as they are sent from a Gmail account, scanning for suspicious recipients and sensitive data within attachments. Alerts are displayed on a clean, local web dashboard powered by Flask.


## Features

- **Suspicious Recipient Detection**: Uses the Google Gemini API to analyze recipient lists for disposable email addresses (e.g., mailinator.com), personal emails mixed with corporate ones, or other anomalies.
- **Sensitive Data Scanning**: Scans the content of attachments (`.txt`, `.pdf`, `.docx`) for patterns like passwords, API keys, credit card numbers, and more, powered by Gemini.
- **Real-time Web Dashboard**: A simple Flask-based web interface that automatically updates with the latest security alerts.
- **Secure Google Authentication**: Uses OAuth 2.0 to securely access the Gmail API in a read-only fashion.

## Tech Stack

- **Backend**: Python
- **Web Framework**: Flask
- **AI/LLM**: Google Gemini 1.5 Flash
- **APIs**: Google Gmail API, Google Generative AI API
- **File Parsing**: PyPDF2, python-docx


## Prerequisites

Before you begin, ensure you have the following installed:
- [Python 3.8+](https://www.python.org/downloads/)
- `pip` (Python package installer)
- A Google Account

---

## Setup and Installation

Follow these steps to get the project running on your local machine.

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/your-repo-name.git
cd your-repo-name


2. Configure Google Cloud & Gmail API
This is the most important step. You need to authorize the application to read your Gmail messages.
Go to the Google Cloud Console.
Create a new project.
Go to APIs & Services > Library and search for and enable the "Gmail API".
Go to APIs & Services > OAuth consent screen.
Choose External user type.
Fill in the required app information (app name, user support email).
On the Scopes page, click Add or Remove Scopes and add the .../auth/gmail.readonly scope.
Add your email address as a Test user.
Go to APIs & Services > Credentials.
Click Create Credentials > OAuth client ID.
Select Desktop app as the Application type.
Click Create, and then Download JSON.
Rename the downloaded file to credentials.json and place it in the root of your project directory.
3. Get Your Google Gemini API Key
Go to Google AI Studio.
Click Create API key and copy your new key.
4. Set Up Python Environment & Dependencies
It is highly recommended to use a virtual environment.
Generated bash
# Create a virtual environment
python3 -m venv venv

# Activate it (Linux/macOS)
source venv/bin/activate
# Or on Windows
# venv\Scripts\activate

# Install the required packages
pip install -r requirements.txt
Use code with caution.
Bash
5. Set Environment Variable
You need to set your Gemini API key as an environment variable.
Generated bash
# For Linux/macOS
export GOOGLE_API_KEY='YOUR_GEMINI_API_KEY_HERE'

# For Windows (Command Prompt)
set GOOGLE_API_KEY='YOUR_GEMINI_API_KEY_HERE'
Use code with caution.
Bash
6. Run the Application
Now you are ready to start the server!
Generated bash
python3 web_verifier.py
Use code with caution.
Bash
The first time you run this, a browser window will open asking you to log in to your Google Account and grant the app permission. You must complete this step.
A token.json file will be created, storing your login for future sessions.
Open a web browser and navigate to http://127.0.0.1:5000 to see the dashboard.
How to Use
The application works by monitoring the Sent folder of the Gmail account you authenticated.
Keep the web_verifier.py script running.
From your authenticated Gmail account, send a new email.
To test recipient alerts: Send an email to a suspicious address like test@mailinator.com.
To test data alerts: Attach a .txt or .docx file containing text like My password is: supersecret123.
Wait about 15-20 seconds and refresh the dashboard at http://127.0.0.1:5000. Any new alerts will appear at the top.
Project Structure
Generated code
/
├── templates/
│   └── index.html      # The HTML template for the dashboard
├── .gitignore          # Tells Git which files to ignore
├── README.md           # This file
├── requirements.txt    # List of Python dependencies
└── web_verifier.py     # The main Python application script
