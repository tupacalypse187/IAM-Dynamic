'''
streamlit run dynamicIAM_web_main.py --server.address 0.0.0.0

I would like to view the existing s3 buckets, create a new bucket if the one I want doesn't exist, and then upload a file to the bucket.

I would like to view the contents of the s3 bucket named chads-devops-ami-bucket2 , and then upload files to the bucket.
'''
import os
import json
import openai
import boto3
import streamlit as st
import requests
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")
ACCOUNT_ID = os.getenv("AWS_ACCOUNT_ID")
ROLE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:role/AgentPOCSessionRole"
sts_client = boto3.client("sts")

# Configure OpenAI client
try:
    if OPENAI_API_KEY:
        openai.api_key = OPENAI_API_KEY
except Exception:
    openai = None

def init_session_state():
    defaults = {
        "policy": None,
        "risk": None,
        "explanation": None,
        "approver_note": None,
        "creds": None,
        "auto_approved": False,
        "needs_approval": False,
        "change_case": "",
        "req_text": "",
        "duration": 2,
        "approval_submitted": False,
        "stage": "request",  # can be 'request', 'review', or 'completed'
    }
    for key, default in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = default

init_session_state()

def send_slack(message: str):
    if SLACK_WEBHOOK_URL:
        try:
            requests.post(SLACK_WEBHOOK_URL, json={"text": message})
        except Exception:
            pass

def extract_json(text: str):
    stack = []
    start = -1
    json_texts = []
    for i, c in enumerate(text):
        if c == '{':
            if not stack:
                start = i
            stack.append(c)
        elif c == '}' and stack:
            stack.pop()
            if not stack:
                json_texts.append(text[start:i+1])
                start = -1
    for candidate in json_texts:
        try:
            return json.loads(candidate)
        except Exception:
            continue
    raise ValueError("No JSON object found")

def color_badge(text, color):
    return f'<span style="background-color:{color}; padding:7px 18px; border-radius:20px; color:#fff; font-weight:700; font-size:1.1em;">{text.upper()}</span>'

def risk_color(risk: str):
    colors = {
        "low": "#22c55e",
        "medium": "#facc15",
        "high": "#f97316",
        "critical": "#dc2626",
    }
    return colors.get((risk or "").lower(), "#64748b")

def parse_llm_response(text: str):
    policy = extract_json(text)
    tail = text.split(json.dumps(policy))[-1]
    risk = "unknown"
    explanation = ""
    approver_note = ""
    for line in tail.splitlines():
        l = line.strip()
        if l.lower().startswith("risk score:"):
            risk = l.split(":", 1)[1].strip()
        elif l.lower().startswith("explanation:"):
            explanation = l.split(":", 1)[1].strip()
        elif l.lower().startswith("approver:"):
            approver_note = l.split(":", 1)[1].strip()
    return policy, risk, explanation, approver_note

def call_llm(nl_request: str) -> str:
    prompt = f"""
You are a security agent that writes AWS IAM policies from user requests.
- ALWAYS create a policy that grants what is requested, scoped to least privilege.
- Respond with a JSON IAM policy, then:
  Risk score: <low|medium|high|critical>
  Explanation: <two sentences describing the risk and limitations>
  Approver: <two sentences recommending approval or denial>
Request: "{nl_request}"
"""
    if not openai:
        st.error("OpenAI client not initialized.")
        return ""
    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2,
    )
    return response.choices[0].message.content.strip()

def risk_max_duration(risk: str) -> int:
    return {"low": 8, "medium": 4, "high": 2, "critical": 1}.get(risk.lower(), 2)

def assume_role(policy, duration_hours):
    resp = sts_client.assume_role(
        RoleArn=ROLE_ARN,
        RoleSessionName="jit-session",
        DurationSeconds=int(duration_hours * 3600),
        Policy=json.dumps(policy),
    )
    creds = resp["Credentials"]
    # Ensure Expiration is timezone-aware UTC
    if creds["Expiration"].tzinfo is None:
        creds["Expiration"] = creds["Expiration"].replace(tzinfo=timezone.utc)
    return creds

def slack_message(auto_approved, req, risk, duration, approver=None):
    base = ":unlock: AWS Temporary Credentials issued for request:\n"
    if auto_approved:
        msg = f"{base}AUTO-APPROVED\n`{req}`\nRisk Score: {risk.upper()}\nDuration: {duration} hour(s)"
    else:
        msg = (
            f"{base}MANUAL APPROVAL\n`{req}`\n"
            f"Approved By: {approver}\nRisk Score: {risk.upper()}\nDuration: {duration} hour(s)"
        )
    return msg

def reset_all_state():
    st.session_state.policy = None
    st.session_state.risk = None
    st.session_state.explanation = None
    st.session_state.approver_note = None
    st.session_state.creds = None
    st.session_state.auto_approved = False
    st.session_state.needs_approval = False
    st.session_state.change_case = ""
    st.session_state.req_text = ""
    st.session_state.duration = 2
    st.session_state.approval_submitted = False
    st.session_state.stage = "request"

# --- UI ---

st.set_page_config(
    page_title="AI-Powered AWS Access Portal",
    page_icon="🔐",
    layout="centered",
)

st.markdown('<h1 style="color:#7c3aed;">AI-Powered AWS Access Portal</h1>', unsafe_allow_html=True)

with st.expander("Instructions"):
    st.markdown(
        """
- Describe what AWS access you need.
- Choose session duration.
- Submit your request.
- Low risk requests get auto-approved.
- Medium/high/critical risk requests require approval.
- For high/critical, enter a Change Case or justification.
"""
    )

# Step 1: Request form

if st.session_state.stage == "request":
    with st.form("request_form"):
        req = st.text_area(
            "Describe your AWS access request",
            height=120,
            value=st.session_state.req_text,
            key="req_input"
        )
        dur = st.selectbox(
            "Desired duration (hours)",
            options=[0.5, 1, 2, 4, 6, 8, 12],
            index=[0.5, 1, 2, 4, 6, 8, 12].index(st.session_state.duration)
        )
        submit = st.form_submit_button("Generate Policy")

    if submit:
        st.session_state.req_text = req
        st.session_state.duration = dur

        with st.spinner("Contacting AI to generate IAM policy and risk assessment..."):
            raw = call_llm(req)
            if not raw:
                st.error("Failed to get response from AI.")
            else:
                try:
                    pol, risk, explanation, approver_note = parse_llm_response(raw)
                    st.session_state.policy = pol
                    st.session_state.risk = risk
                    st.session_state.explanation = explanation
                    st.session_state.approver_note = approver_note
                    st.session_state.auto_approved = (risk.lower() == "low")
                    st.session_state.needs_approval = (risk.lower() != "low")
                    st.session_state.change_case = ""
                    st.session_state.creds = None
                    st.session_state.approval_submitted = False
                    st.session_state.stage = "review"
                except Exception as e:
                    st.error(f"Failed to parse AI response: {e}")
                    st.text_area("Raw AI output:", raw, height=250)

# Step 2: Review & Approve

if st.session_state.stage == "review":
    st.markdown("### Your access request:")
    st.markdown(f"> {st.session_state.req_text}")
    st.markdown(f"**Duration Requested:** {st.session_state.duration} hour(s)")

    # Show IAM policy prettily
    st.markdown("### Generated IAM Policy")
    policy_str = json.dumps(st.session_state.policy, indent=2)
    # st.markdown(f'<div style="background:#eef4ff; padding:16px; border-radius:12px; white-space: pre; font-family: monospace;">{policy_str}</div>', unsafe_allow_html=True)
    st.code(policy_str, language="json")

    risk_color_hex = risk_color(st.session_state.risk)
    st.markdown(f"**Risk Score:** <span style='background-color:{risk_color_hex}; color:#fff; border-radius:15px; padding:5px 12px;'>{st.session_state.risk.upper()}</span>", unsafe_allow_html=True)
    st.markdown(f"**Explanation:** {st.session_state.explanation}")
    if st.session_state.approver_note:
        st.markdown(f"**Approver Note:** {st.session_state.approver_note}")

    dur_cap = risk_max_duration(st.session_state.risk)
    display_duration = min(dur_cap, st.session_state.duration)
    if display_duration < st.session_state.duration:
        st.warning(f"Duration capped at {dur_cap} hour(s) for risk level '{st.session_state.risk.title()}'.")

    # Auto approve low risk
    if st.session_state.auto_approved and st.session_state.creds is None:
        with st.spinner("Auto-approving and issuing credentials..."):
            try:
                creds = assume_role(st.session_state.policy, display_duration)
                st.session_state.creds = creds
                st.success("Low risk request auto-approved and credentials issued.")
                slack_msg = slack_message(True, st.session_state.req_text, st.session_state.risk, display_duration)
                send_slack(slack_msg)
            except Exception as e:
                st.error(f"Failed to issue credentials: {e}")

    # Require approval for others
    elif st.session_state.needs_approval and st.session_state.creds is None:
        requirement = "Please provide a Change Case or justification." if st.session_state.risk.lower() in ["high", "critical"] else "Approval is required."
        st.warning(f"This request requires manual approval. {requirement}")
        justification = st.text_input("Change Case / Justification (required for high/critical)", st.session_state.change_case)
        st.session_state.change_case = justification

        button_enabled = True
        if st.session_state.risk.lower() in ["high", "critical"] and not justification.strip():
            button_enabled = False

        if st.button("Approve and Generate Credentials", disabled=not button_enabled or st.session_state.creds is not None):
            with st.spinner("Issuing credentials after manual approval..."):
                try:
                    creds = assume_role(st.session_state.policy, display_duration)
                    st.session_state.creds = creds
                    st.success("Credentials approved and issued.")
                    approver = "Approver Name"  # Replace with current user if available
                    slack_msg = slack_message(False, st.session_state.req_text, st.session_state.risk, display_duration, approver=approver)
                    send_slack(slack_msg)
                except Exception as e:
                    st.error(f"Failed to issue credentials: {e}")

    if st.session_state.creds:
        if st.button("Submit Another Request"):
            reset_all_state()
            st.rerun()

# Step 3: Show Credentials (also shown after approval above)
if st.session_state.creds:
    st.markdown("---")
    creds = st.session_state.creds
    expiration = creds["Expiration"]
    now = datetime.now(timezone.utc)
    remaining_hours = (expiration - now).total_seconds() / 3600
    st.markdown(f"### 🛂 Your Temporary AWS Credentials (expires in approx. {remaining_hours:.2f} hours at {expiration.strftime('%Y-%m-%d %H:%M:%S UTC')})")
    st.markdown("Copy these commands in your shell to use them:")

    st.code(f"""export AWS_ACCESS_KEY_ID="{creds['AccessKeyId']}"
export AWS_SECRET_ACCESS_KEY="{creds['SecretAccessKey']}"
export AWS_SESSION_TOKEN="{creds['SessionToken']}"
# Now run your AWS CLI commands, e.g. 'aws sts get-caller-identity'""", language="bash")

    st.code(f"""$Env:AWS_ACCESS_KEY_ID="{creds['AccessKeyId']}"
$Env:AWS_SECRET_ACCESS_KEY="{creds['SecretAccessKey']}"
$Env:AWS_SESSION_TOKEN="{creds['SessionToken']}"
# In PowerShell, run AWS CLI commands""", language="powershell")

    st.code(f"""aws configure set aws_access_key_id {creds['AccessKeyId']} --profile jit-session
aws configure set aws_secret_access_key {creds['SecretAccessKey']} --profile jit-session
aws configure set aws_session_token {creds['SessionToken']} --profile jit-session
# Use AWS CLI with --profile jit-session""", language="bash")

    st.info("These credentials are temporary and expire automatically after the duration.")

st.markdown("---")
st.markdown('<div style="text-align:center; color:#78787d; font-size:0.9em;">🔒 Powered by AI-driven IAM; all activity logged for audit.</div>', unsafe_allow_html=True)

