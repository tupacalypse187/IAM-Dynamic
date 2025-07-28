'''
streamlit run dynamicIAM_lambda_main.py --server.address 0.0.0.0

I would like to view the existing s3 buckets, create a new bucket if the one I want doesn't exist, and then upload a file to the bucket.

I would like to view the contents of the s3 bucket named chads-devops-ami-bucket2 , and then upload files to the bucket.
'''
import os
import json
import openai
import streamlit as st
import requests
import boto3
from dotenv import load_dotenv
from datetime import datetime, timezone

load_dotenv()

OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL")

try:
    if OPENAI_API_KEY:
        openai.api_key = OPENAI_API_KEY
except Exception:
    openai = None

def init_state():
    defaults = dict(
        policy=None,
        risk=None,
        explanation=None,
        approver_note=None,
        creds=None,
        auto_approved=False,
        needs_approval=False,
        change_case="",
        req_text="",
        duration=2,
        approval_submitted=False,
        stage="request",  # 'request', 'review'
    )
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

init_state()

def send_slack(message: str):
    if SLACK_WEBHOOK_URL:
        try:
            requests.post(SLACK_WEBHOOK_URL, json={"text": message})
        except Exception:
            pass

def extract_json(text: str):
    stack, start, jsons = [], -1, []
    for i, c in enumerate(text):
        if c == '{':
            if not stack: start = i
            stack.append(c)
        elif c == '}' and stack:
            stack.pop()
            if not stack and start != -1:
                jsons.append(text[start:i+1])
                start = -1
    for candidate in jsons:
        try:
            return json.loads(candidate)
        except:
            continue
    raise ValueError("No JSON object found")

def color_badge(text, color="#22c55e"):
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

def policy_from_openai(nl_request: str) -> str:
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
        st.error("OpenAI not configured properly.")
        return ""
    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2
    )
    return response.choices[0].message.content.strip()

def policy_from_bedrock(nl_request: str) -> str:
    # (Implement as needed. For now, just use OpenAI branch.)
    return policy_from_openai(nl_request)

def risk_max_duration(risk: str) -> int:
    return {"low":8, "medium":4, "high":2, "critical":1}.get(risk.lower(), 2)

def assume_role_with_policy_via_lambda(policy_json, duration_hours, requester="web-user", description=""):
    lambda_client = boto3.client('lambda')
    payload = {
        'policy': policy_json,
        'duration_hours': duration_hours,
        'requester': requester,
        'request_description': description
    }
    try:
        response = lambda_client.invoke(
            FunctionName='credential-issuer',
            InvocationType='RequestResponse',
            Payload=json.dumps(payload)
        )
        lambda_result = json.loads(response['Payload'].read())
        if response.get('StatusCode') != 200 or lambda_result.get('statusCode') != 200:
            body = lambda_result.get('body')
            error_info = None
            try:
                error_info = json.loads(body) if body else body
            except Exception:
                error_info = body
            error_text = error_info.get('error') if error_info and isinstance(error_info, dict) else str(error_info)
            raise RuntimeError(f"Lambda error: {error_text}")
        creds_body = json.loads(lambda_result['body'])
        credentials = creds_body['credentials']
        metadata = creds_body.get('metadata', {})
        credentials['Expiration'] = datetime.fromisoformat(credentials['Expiration'].replace('Z', '+00:00'))
        return credentials, metadata
    except Exception as e:
        raise RuntimeError(f"Failed to invoke credential issuer Lambda: {e}")

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

# Card CSS for IAM policy
st.markdown("""
<style>
.card-json {
    background-color: #e5eafe !important;
    color: #18181b !important;
    padding: 16px 10px 14px 10px !important;
    border-radius: 11px;
    font-family: Menlo, 'Fira Mono', 'Liberation Mono', monospace !important;
    font-size: 1.07em !important;
    margin-bottom: 18px !important;
    overflow-x: auto;
    border: 1px solid #d1d5db;
}
[data-theme="dark"] .card-json {
    background-color: #181e32 !important;
    color: #e4e4e7 !important;
    border: 1px solid #324059;
}
</style>
""", unsafe_allow_html=True)

st.title("AI-Powered AWS Access (via Lambda)")

with st.expander("Instructions", expanded=True):
    st.markdown(
        """
- Enter what AWS access you need and session duration.
- After submitting, review risk and IAM policy details.
- Low risk = auto-approved; others require approval (and justification for high/critical).
- Submit another request any time.
"""
    )

# Page/step logic

if st.session_state.stage == "request":
    with st.form("lambda_access_form"):
        req = st.text_area(
            "Describe your AWS access request",
            height=120,
            value=st.session_state.req_text,
            key="req_input_lambda"
        )
        dur = st.selectbox(
            "Session Duration (hours)",
            options=[0.5, 1, 2, 4, 6, 8, 12],
            index=[0.5, 1, 2, 4, 6, 8, 12].index(st.session_state.duration)
        )
        llm_engine = st.radio("AI Engine", ["OpenAI"], index=0)
        submit = st.form_submit_button("Generate Policy")
    if submit:
        st.session_state.req_text = req
        st.session_state.duration = dur
        with st.spinner("Generating IAM policy & risk assessment..."):
            if llm_engine == "OpenAI":
                raw = policy_from_openai(req)
            else:
                raw = policy_from_bedrock(req)
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
                st.text_area("Raw AI Output:", raw, height=300)

if st.session_state.stage == "review":
    st.markdown("### Your Access Request:")
    st.markdown(f"> {st.session_state.req_text}")
    st.markdown(f"**Duration Requested:** {st.session_state.duration} hour(s)")

    st.markdown("### Generated IAM Policy")
    policy_str = json.dumps(st.session_state.policy, indent=2)
    st.code(policy_str, language="json")
    # st.markdown(f'<div class="card-json"><pre>{policy_str}</pre></div>', unsafe_allow_html=True)

    risk_color_hex = risk_color(st.session_state.risk)
    st.markdown(f"**Risk Score:** <span style='background-color:{risk_color_hex}; color:#fff; border-radius:15px; padding:5px 12px;'>{st.session_state.risk.upper()}</span>", unsafe_allow_html=True)
    st.markdown(f"**Explanation:** {st.session_state.explanation}")
    if st.session_state.approver_note:
        st.markdown(f"**Approver Note:** {st.session_state.approver_note}")

    dur_cap = risk_max_duration(st.session_state.risk)
    display_duration = min(dur_cap, st.session_state.duration)
    if display_duration < st.session_state.duration:
        st.warning(f"Duration capped at {dur_cap} hour(s) for risk level '{st.session_state.risk.title()}'.")

    # Approval/credential logic
    if st.session_state.auto_approved and st.session_state.creds is None:
        with st.spinner("Auto-approving and calling Lambda for credentials..."):
            try:
                creds, _ = assume_role_with_policy_via_lambda(
                    st.session_state.policy,
                    display_duration,
                    requester="web-user",
                    description=st.session_state.req_text[:100],
                )
                st.session_state.creds = creds
                st.success("Low risk request auto-approved and credentials issued.")
                slack_msg = slack_message(True, st.session_state.req_text, st.session_state.risk, display_duration)
                send_slack(slack_msg)
            except Exception as e:
                st.error(f"Failed to issue credentials via Lambda: {e}")

    elif st.session_state.needs_approval and st.session_state.creds is None:
        st.info("This request requires manual approval.")
        need_just = st.session_state.risk.lower() in ["high", "critical"]
        justification = ""
        if need_just:
            justification = st.text_input("Change Case / Justification (required)", st.session_state.change_case)
            st.session_state.change_case = justification
            approve_btn_enabled = bool(justification.strip())
        else:
            approval_label = "Approve and Generate Credentials"
            approve_btn_enabled = True

        # For medium risk: approve directly, for high/critical require justification
        if st.button("Approve and Generate Credentials", disabled=not approve_btn_enabled or st.session_state.creds is not None):
            with st.spinner("Issuing credentials via Lambda after approval..."):
                try:
                    creds, _ = assume_role_with_policy_via_lambda(
                        st.session_state.policy,
                        display_duration,
                        requester="web-user",
                        description=st.session_state.req_text[:100]
                    )
                    st.session_state.creds = creds
                    st.success("Credentials approved and issued.")
                    approver = "Approver Name"
                    slack_msg = slack_message(False, st.session_state.req_text, st.session_state.risk, display_duration, approver=approver)
                    send_slack(slack_msg)
                except Exception as e:
                    st.error(f"Failed to issue credentials via Lambda: {e}")

    if st.session_state.creds:
        if st.button("Submit Another Request"):
            reset_all_state()
            st.rerun()

if st.session_state.creds:
    st.markdown("---")
    creds = st.session_state.creds
    expiration = creds["Expiration"]
    now = datetime.now(timezone.utc)
    remaining_hours = (expiration - now).total_seconds() / 3600
    st.markdown(f"### 🛂 Your Temporary AWS Credentials (expires in ~{remaining_hours:.2f} hours at {expiration.strftime('%Y-%m-%d %H:%M:%S UTC')})")
    st.markdown("Copy and paste these commands in your shell:")

    st.code(f"""export AWS_ACCESS_KEY_ID="{creds['AccessKeyId']}"
export AWS_SECRET_ACCESS_KEY="{creds['SecretAccessKey']}"
export AWS_SESSION_TOKEN="{creds['SessionToken']}"
# aws s3 ls""", language="bash")

    st.code(f"""$Env:AWS_ACCESS_KEY_ID="{creds['AccessKeyId']}"
$Env:AWS_SECRET_ACCESS_KEY="{creds['SecretAccessKey']}"
$Env:AWS_SESSION_TOKEN="{creds['SessionToken']}"
# aws s3 ls""", language="powershell")

    st.code(f"""aws configure set aws_access_key_id {creds['AccessKeyId']} --profile jit-session
aws configure set aws_secret_access_key {creds['SecretAccessKey']} --profile jit-session
aws configure set aws_session_token {creds['SessionToken']} --profile jit-session
# aws s3 ls --profile jit-session""", language="bash")

    st.info("These credentials are temporary and expire automatically.")

st.markdown("---")
st.markdown('<div style="text-align:center;color:#78787d;font-size:0.9em;">🔒 Powered by AI-driven IAM; all activity logged for audit.</div>', unsafe_allow_html=True)

