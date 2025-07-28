# 🔐 dynamicIAM

AI-Driven Just-In-Time AWS IAM Access Request Portal

[![Streamlit](https://img.shields.io/badge/Built%20with-Streamlit-ff4b4b?logo=streamlit)](https://streamlit.io)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python)](https://www.python.org/)
[![Dockerized](https://img.shields.io/badge/Containerized-Docker-blue?logo=docker)](https://www.docker.com/)

## 🚀 Overview

DynamicIAM is a secure, user-friendly Streamlit app that empowers users to request time-limited AWS IAM credentials using natural language prompts, with:
- Auto-generated IAM policies via OpenAI
- Risk scoring (low, medium, high, critical)
- Auto-approval for low-risk requests
- Manual approval, with required business justification, for higher-risk access
- Just-in-time AWS credentials via STS AssumeRole or delegation to a Lambda backend

Perfect for security-conscious teams seeking flexible, auditable AWS access control.

---

## ✨ Features

- 🔍 Describe your AWS access needs in natural language
- 🤖 Uses GPT-4 to automatically generate precise IAM policies
- 🟢 Auto-approve low-risk requests and deliver session credentials instantly
- 🟠 Manual approval flow with Change Case submission for high/critical
- 📝 Risk scores, explanation notes, and IAM policy output in human-friendly UI
- 🔐 Temporary credentials issued via AWS STS or Lambda backend
- 🌘 Native dark/light theme toggle (built-in)
- 📡 Slack webhook integration for audit notifications

---

## 📦 Project Structure

| File                            | Description                                |
|---------------------------------|--------------------------------------------|
| `dynamicIAM_web.py`             | Streamlit UI with direct AWS STS usage     |
| `dynamicIAM_lambda.py`          | UI that calls a backend Lambda function    |
| `lambda_credential_issuer.py`   | Backend Lambda to perform AssumeRole       |
| `requirements.txt`              | Python dependencies                        |
| `Dockerfile`                    | Containerized build for `dynamicIAM_web.py`|
| `.env`                          | Local environment variables                |

---

## ⚙️ Requirements

- Python 3.8+
- OpenAI API key for GPT-4 (set in `.env`)
- AWS credentials (for local STS calls or Lambda invoke)
- Environment variables saved in `.env` or in Lambda configuration

### Python dependencies (in `requirements.txt`)
streamlit
boto3
openai
python-dotenv
requests


---

## 🧪 Getting Started (Local Dev)

### Clone repo
`git clone https://github.com/tupacalypse187/dynamicIAM.git
cd dynamicIAM`

### Create virtual environment
`python3 -m venv venvsource venv/bin/activate`

### Install requirements
`pip install -r requirements.txt`

### Set local environment variables (create .env)
```
cat > .env <<EOF
OPENAI_API_KEY=your_openai_key
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/…
EOF
```

### Run the app
`streamlit run dynamicIAM_web.py`

Then open [http://localhost:8501](http://localhost:8501) in your browser.

---

## 🐳 Run with Docker

### Build Docker image
`docker build -t dynamiciam .`

### Run container (port 8501)
`docker run -p 8501:8501 –env-file .env dynamiciam`

To access: [http://localhost:8501](http://localhost:8501)

---

## 🧠 How It Works
┌──────────────┐     Request     ┌─────────────┐       ┌────────────────────┐
│   Web App    │ ─────────────▶ │ GPT-4 / LLM │──────▶│ IAM Policy + Risk  │
└──────────────┘                 └─────────────┘       └────────────────────┘
     │                                                         │
     │             (Auto or Manual Approval)                   │
     └────────────────────────────────────────────────────────▶ 
                         AWS STS / Lambda
                       Temporary Credentials


- Streamlit receives user text input and session duration
- LLM generates IAM policy + Risk + Explanation
- Depending on mode:
  - App assumes role locally (STS) **OR**
  - Sends to Lambda for credential execution

---

## 🔐 App Variants

| File                          | Purpose                                  |
|-------------------------------|------------------------------------------|
| dynamicIAM_web.py             | Streamlit app (assume-role locally)      |
| dynamicIAM_lambda.py          | Streamlit app using Lambda backend       |
| lambda_credential_issuer.py   | Lambda handler that runs STS + LLM       |

---

## 📡 Slack Approval Notifications

To enable Slack auditing:

- Go to [Slack Webhooks](https://api.slack.com/messaging/webhooks)
- Generate a webhook for your channel
- Add it to `.env` or Lambda env:

`SLACK_WEBHOOK_URL=https://hooks.slack.com/services/…`


---

## 📜 Example Request

`I would like to list all S3 buckets in my account, and upload files to one.`


Outcome:
- GPT-4 generates IAM policy with `s3:ListBucket`, `PutObject`, etc.
- Risk is evaluated
- If `low`, credentials issued instantly
- If `high/critical`, requires justification and approval button

---

## 🎯 Roadmap Ideas

- Slack emoji approval workflow
- Native approval delegation and roles
- CI/CD ephemeral access flows
- Integration with ITSM (Jira, SNOW)
- Approval history/logging dashboard

---

## 🛡️ Security

This tool encourages:
- Zero standing privilege
- Principle of least privilege (PLP)
- Explicit access duration with clear expiry
- Audit notifications via Slack or logging

---

## 🙏 Acknowledgments

Built by [@tupacalypse187](https://github.com/tupacalypse187) with ❤️ on Streamlit, OpenAI, AWS STS, and Lambda.

---

## 📄 License

MIT © 2024

