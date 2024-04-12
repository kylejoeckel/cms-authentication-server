import json
import bcrypt
import boto3

# Initialize DynamoDB client
dynamodb = boto3.resource('dynamodb')
users_table = dynamodb.Table('cms-users')

def changePassword(event, context):
    try:
        # Parse incoming event body
        body = json.loads(event['body'])
        user_id = body['userId']
        old_password = body['oldPassword']
        new_password = body['newPassword']
        confirm_new_password = body['confirmNewPassword']

        # Check if new passwords match
        if new_password != confirm_new_password:
            return {"statusCode": 400, "body": json.dumps({"error": "New passwords do not match"})}

        # Retrieve user from the database
        response = users_table.get_item(Key={'userId': user_id})
        if 'Item' not in response:
            return {"statusCode": 404, "body": json.dumps({"error": "User not found"})}
        user = response['Item']

        # Verify old password
        if not bcrypt.checkpw(old_password.encode('utf-8'), user['password'].encode('utf-8')):
            return {"statusCode": 401, "body": json.dumps({"error": "Invalid old password"})}

        # Hash new password
        hashed_new_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Update password in the database
        users_table.update_item(
            Key={'userId': user_id},
            UpdateExpression='SET password = :val',
            ExpressionAttributeValues={':val': hashed_new_password}
        )

        # Return success message
        return {
            "statusCode": 200,
            "body": json.dumps({"success": "Password changed successfully"})
        }

    except Exception as e:
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}