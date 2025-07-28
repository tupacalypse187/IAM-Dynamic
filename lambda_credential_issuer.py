import json
import boto3
from datetime import datetime, timezone

def lambda_handler(event, context):
    """
    Lambda function to issue temporary AWS credentials
    Expected input: {
        "policy": <IAM policy JSON object>,
        "duration_hours": <float>,
        "requester": <optional string>,
        "request_description": <optional string>
    }
    """
    
    try:
        # Parse input
        policy = event.get('policy')
        duration_hours = event.get('duration_hours', 1)
        requester = event.get('requester', 'unknown')
        request_description = event.get('request_description', '')
        
        if not policy:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'Policy is required'})
            }
        
        # Configuration - use environment variables in production
        ACCOUNT_ID = "467266701745"  # Replace with your account ID
        ROLE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:role/AgentPOCSessionRole"
        
        # Create STS client
        sts_client = boto3.client('sts')
        
        # Assume role with session policy
        response = sts_client.assume_role(
            RoleArn=ROLE_ARN,
            RoleSessionName=f"lambda-issued-{requester}",
            DurationSeconds=int(duration_hours * 3600),
            Policy=json.dumps(policy)
        )
        
        credentials = response['Credentials']
        
        # Calculate expiration info
        expiration = credentials['Expiration']
        now = datetime.now(timezone.utc)
        remaining_seconds = (expiration - now).total_seconds()
        remaining_hours = remaining_seconds / 3600
        
        # Return credentials and metadata
        return {
            'statusCode': 200,
            'body': json.dumps({
                'credentials': {
                    'AccessKeyId': credentials['AccessKeyId'],
                    'SecretAccessKey': credentials['SecretAccessKey'],
                    'SessionToken': credentials['SessionToken'],
                    'Expiration': credentials['Expiration'].isoformat()
                },
                'metadata': {
                    'remaining_hours': round(remaining_hours, 2),
                    'expiration_utc': expiration.strftime('%Y-%m-%d %H:%M:%S %Z'),
                    'issued_by': 'lambda',
                    'requester': requester,
                    'request_description': request_description
                }
            }, default=str)
        }
        
    except Exception as e:
        # Log error (CloudWatch)
        print(f"Error issuing credentials: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': f'Failed to issue credentials: {str(e)}'})
        }

