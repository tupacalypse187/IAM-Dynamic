import os
import re
import json
import requests
import streamlit as st
import boto3
from dotenv import load_dotenv
from datetime import datetime, timezone

# Load environment variables from .env
load_dotenv()

# Configuration
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL")
ACCOUNT_ID = "467266701745"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:role/AgentPOCSessionRole"

# Setup AWS clients
sts_client = boto3.client("sts")
try:
    bedrock_runtime = boto3.client("bedrock-runtime", region_name="us-east-1")
except Exception:
    bedrock_runtime = None

try:
    import openai
    if OPENAI_API_KEY:
        openai.api_key = OPENAI_API_KEY
except ImportError:
    openai = None

# --- Utility Functions ---

def send_slack(message):
    if not SLACK_WEBHOOK_URL:
        st.warning("Slack webhook URL not configured. Skipping Slack notification.")
        return
    try:
        resp = requests.post(SLACK_WEBHOOK_URL, json={"text": message})
        if resp.status_code != 200:
            st.warning(f"Slack webhook failed with status {resp.status_code}: {resp.text}")
    except Exception as e:
        st.warning(f"Slack notification error: {e}")

def extract_json_from_text(text):
    """Extract the first valid JSON object from text, tolerant of extra content."""
    matches = []
    brace_stack = []
    start_idx = None
    for i, ch in enumerate(text):
        if ch == '{':
            if not brace_stack:
                start_idx = i
            brace_stack.append(ch)
        elif ch == '}':
            if brace_stack:
                brace_stack.pop()
                if not brace_stack and start_idx is not None:
                    matches.append(text[start_idx:i+1])
                    start_idx = None

    for m in matches:
        try:
            parsed = json.loads(m)
            return parsed
        except json.JSONDecodeError:
            continue
    raise ValueError("No valid JSON object found in the input text.")

def restrict_policy_to_account(policy, account_id):
    """Post-process IAM policy to restrict resource ARNs to the specified account."""

    def restrict_arn(arn):
        if arn in ("*", "arn:aws:s3:::*", "arn:aws:s3:::*/*"):
            return f"arn:aws:s3:::{account_id}-*"
        if "arn:aws:" in arn and account_id not in arn:
            parts = arn.split(':')
            if len(parts) > 4:
                parts[4] = account_id
                return ':'.join(parts)
        return arn

    if not policy or "Statement" not in policy:
        return policy
    for stmt in policy["Statement"]:
        resource = stmt.get("Resource")
        if resource:
            if isinstance(resource, str):
                stmt["Resource"] = restrict_arn(resource)
            elif isinstance(resource, list):
                stmt["Resource"] = [restrict_arn(r) for r in resource]
    return policy


# --- LLM Calls ---

def policy_from_openai(nl_request: str) -> str:
    if openai is None or OPENAI_API_KEY is None:
        st.error("OpenAI not configured properly.")
        return ""
    prompt = f"""
You are a security agent that writes AWS IAM policies from user requests.
- ALWAYS scope the Resource ARNs to only allow access to resources in AWS Account {ACCOUNT_ID}.
- ALWAYS create a policy that gives what is requested, but scope down to the least privilege needed.
- Respond firstly with a valid JSON IAM policy ONLY, with no extra commentary or explanation.
- Then, after the JSON block, on a new line, write: "Risk score: X" where X is low, medium, high, critical.
- Then, on the next line, write: "Explanation: ..." with two sentence explanation explaining the risk and what can't be done based on the risk.

Given request: "{nl_request}"
"""
    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2
    )
    return response.choices[0].message.content.strip()


def policy_from_bedrock(nl_request: str) -> str:
    if not bedrock_runtime:
        st.error("Bedrock client not available.")
        return ""
    prompt = f"""
You are a security agent that writes AWS IAM policies from user requests.
- ALWAYS scope the Resource ARNs to only allow access to resources in AWS Account {ACCOUNT_ID}.
- ALWAYS create a policy that gives what is requested, but scope down to the least privilege needed.
- Respond firstly with a valid JSON IAM policy ONLY, with no extra commentary or explanation.
- Then, after the JSON block, on a new line, write: "Risk score: X" where X is low, medium, high, critical.
- Then, on the next line, write: "Explanation: ..." with two sentence explanation explaining the risk and what can't be done based on the risk.

Given request: "{nl_request}"
"""
    response = bedrock_runtime.invoke_model(
        body=json.dumps({"prompt": prompt, "max_tokens_to_sample": 500}),
        modelId="anthropic.claude-v2",
        accept="application/json",
        contentType="application/json"
    )
    result = json.loads(response["body"].read())
    return result.get("completion", "").strip()


def parse_policy_response(text: str):
    """Extract the IAM policy JSON, risk score, and explanation from LLM response."""
    try:
        policy = extract_json_from_text(text)
    except Exception as ex:
        raise ValueError(f"Failed to extract JSON policy: {ex}")

    after_json = text.split(json.dumps(policy))[-1]
    risk = "Unknown"
    explanation = "No explanation provided."
    for line in after_json.splitlines():
        line = line.strip()
        if line.lower().startswith("risk score:"):
            risk = line.split(':', 1)[1].strip()
        elif line.lower().startswith("explanation:"):
            explanation = line.split(':', 1)[1].strip()
    return policy, risk, explanation


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

# --- Streamlit UI ---

st.title("AI-Driven AWS Temporary Access Request Demo")

nl_request = st.text_area("Describe your AWS access need:", height=120)
duration = st.selectbox("Session Duration (hours):", [0.5, 1, 2, 4, 6, 8, 12], index=2)
llm_choice = st.radio("Choose LLM backend:", ['OpenAI (GPT-4)', 'Amazon Bedrock'])
submit = st.button("Submit Access Request")

if "policy" not in st.session_state:
    st.session_state.policy = None
if "risk" not in st.session_state:
    st.session_state.risk = None
if "explanation" not in st.session_state:
    st.session_state.explanation = None
if "credentials" not in st.session_state:
    st.session_state.credentials = None

def reset_session_state():
    st.session_state.policy = None
    st.session_state.risk = None
    st.session_state.explanation = None
    st.session_state.credentials = None

if submit and nl_request.strip():
    reset_session_state()
    with st.spinner("Calling LLM to generate IAM policy and risk assessment..."):
        if llm_choice == 'OpenAI (GPT-4)':
            llm_response = policy_from_openai(nl_request)
        else:
            llm_response = policy_from_bedrock(nl_request)
    try:
        policy, risk, explanation = parse_policy_response(llm_response)
        policy = restrict_policy_to_account(policy, ACCOUNT_ID)
        st.session_state.policy = policy
        st.session_state.risk = risk
        st.session_state.explanation = explanation
        st.session_state.credentials = None
    except Exception as e:
        st.error(f"Error parsing LLM response: {e}")
        st.text_area("Raw LLM Output (for debugging):", llm_response, height=200)
        st.stop()

if st.session_state.policy:
    st.subheader("Generated IAM Policy")
    st.json(st.session_state.policy)
    st.write(f"**Risk Score:** {st.session_state.risk}")
    st.write(f"**Explanation:** {st.session_state.explanation}")

    def get_max_duration_for_risk(risk_label: str) -> float:
        risk_map = {
            "low": 8,
            "medium": 4,
            "high": 2,
            "critical": 1
        }
        return risk_map.get(risk_label.lower(), 12)

    if st.button("Approve and Generate Temporary Credentials"):
        with st.spinner("Calling Lambda to generate credentials..."):
            try:
                risk_label = st.session_state.risk
                max_duration = get_max_duration_for_risk(risk_label)
                session_duration = duration
                if session_duration > max_duration:
                    st.warning(
                        f"Because this request is '{risk_label.upper()}' risk, "
                        f"the session is capped at {max_duration} hour(s)."
                    )
                    session_duration = max_duration

                creds, metadata = assume_role_with_policy_via_lambda(
                    st.session_state.policy,
                    session_duration,
                    requester="web-user",
                    description=nl_request[:100]
                )
                st.session_state.credentials = creds

                expiration = creds["Expiration"]
                now = datetime.now(timezone.utc)
                remaining_seconds = (expiration - now).total_seconds()
                remaining_hours = remaining_seconds / 3600

                st.success("Temporary AWS Credentials generated via Lambda!")
                st.write(
                    f"Your session is valid for approximately: **{remaining_hours:.2f} hours** "
                    f"(until {expiration.strftime('%Y-%m-%d %H:%M:%S %Z')} UTC)"
                )
                st.markdown("### Use these credentials in your environment:")

                # Bash
                st.code(f"""export AWS_ACCESS_KEY_ID="{creds['AccessKeyId']}"
export AWS_SECRET_ACCESS_KEY="{creds['SecretAccessKey']}"
export AWS_SESSION_TOKEN="{creds['SessionToken']}"
# aws s3 ls""", language="bash")

                # PowerShell
                st.code(f"""$Env:AWS_ACCESS_KEY_ID="{creds['AccessKeyId']}"
$Env:AWS_SECRET_ACCESS_KEY="{creds['SecretAccessKey']}"
$Env:AWS_SESSION_TOKEN="{creds['SessionToken']}"
# aws s3 ls""", language="powershell")

                # AWS CLI named profile
                st.code(f"""aws configure set aws_access_key_id {creds['AccessKeyId']} --profile temporary-session
aws configure set aws_secret_access_key {creds['SecretAccessKey']} --profile temporary-session
aws configure set aws_session_token {creds['SessionToken']} --profile temporary-session
# aws s3 ls --profile temporary-session""", language="bash")

                send_slack(f":unlock: AWS Temporary Credentials issued for request:\n> {nl_request}\nRisk Score: {st.session_state.risk}\nDuration: {session_duration} hour(s)")

            except Exception as e:
                st.error(f"Error issuing credentials via Lambda: {e}")


if st.session_state.credentials:
    st.info("Use these credentials in your AWS CLI or SDK environment variables to access AWS.")

st.markdown("---")
st.write("App developed by AI Assistant | Adjust ACCOUNT_ID and ROLE_ARN in source code before use.")

