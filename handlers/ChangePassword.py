import json
import boto3
import os
import hashlib

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

        # Verify old password using stored salt and hash
        stored_salt, stored_hash = user['password'].split('$')
        old_hash = hashlib.pbkdf2_hmac('sha256', old_password.encode('utf-8'), bytes.fromhex(stored_salt), 100000)

        if old_hash.hex() != stored_hash:
            return {"statusCode": 401, "body": json.dumps({"error": "Invalid old password"})}

        # Generate new salt and hash new password
        new_salt = os.urandom(16)
        new_hashed_password = hashlib.pbkdf2_hmac('sha256', new_password.encode('utf-8'), new_salt, 100000)
        new_storage_format = f"{new_salt.hex()}${new_hashed_password.hex()}"

        # Update password in the database
        users_table.update_item(
            Key={'userId': user_id},
            UpdateExpression='SET password = :val',
            ExpressionAttributeValues={':val': new_storage_format}
        )

        # Return success message
        return {
            "statusCode": 200,
            "body": json.dumps({"success": "Password changed successfully"})
        }

    except Exception as e:
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}


