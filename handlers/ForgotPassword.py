import json
import boto3
import uuid
import datetime

# Initialize DynamoDB client
dynamodb = boto3.resource('dynamodb')
users_table = dynamodb.Table('cms-users')

def forgotPassword(event, context):
    try:
        # Extract email from the path parameters or query string
        email = event['queryStringParameters']['email']

        # Generate a unique token for password reset
        reset_token = str(uuid.uuid4())
        token_expiration = datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # Token valid for 1 hour

        # Update the user with the reset token and expiration time
        response = users_table.update_item(
            Key={'email': email},
            UpdateExpression="set resetToken = :t, tokenExpiration = :e",
            ExpressionAttributeValues={
                ':t': reset_token,
                ':e': token_expiration.strftime("%Y-%m-%dT%H:%M:%SZ")
            },
            ReturnValues="UPDATED_NEW"
        )

        # Check if the update was successful
        if 'Attributes' not in response:
            return {
                "statusCode": 404,
                "body": json.dumps({"error": "Email not found"})
            }

        # TODO: integrate method to send the token to the user's email or phone

        # Return success message
        return {
            "statusCode": 200,
            "body": json.dumps({"message": "Reset token generated and sent to email", "token": reset_token})  # Remove token from response in production
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)})
        }