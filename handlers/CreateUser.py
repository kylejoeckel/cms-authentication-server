import json
import uuid
import boto3
import os
import hashlib
from botocore.exceptions import ClientError

# Initialize DynamoDB clients
dynamodb = boto3.resource('dynamodb')
users_table = dynamodb.Table('cms-users')
organizations_table = dynamodb.Table('resturant-data-server-dev')

def createUser(event, context):
    try:
        # Parse incoming event body
        body = json.loads(event['body'])
        email = body['email']
        password = body['password']
        password_confirmation = body['passwordConfirmation']
        user_name = body['userName']
        organization_id = body['organizationId']

        # Validate password
        if password != password_confirmation:
            return {"statusCode": 400, "body": json.dumps({"error": "Passwords do not match"})}

        # Check if email already exists
        response = users_table.query(
            IndexName='EmailIndex',  # Make sure this GSI is already created in your DynamoDB table definition
            KeyConditionExpression='email = :email',
            ExpressionAttributeValues={':email': email}
        )
        if response['Items']:
            return {"statusCode": 400, "body": json.dumps({"error": "Email already exists"})}

        # Check if organization exists
        response = organizations_table.get_item(
            Key={'id': organization_id}
        )
        if 'Item' not in response:
            return {"statusCode": 404, "body": json.dumps({"error": "Organization not found"})}

        # Hash password using PBKDF2 HMAC SHA-256
        salt = os.urandom(16)
        hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        storage_format = f"{salt.hex()}${hashed_password.hex()}"

        user_id = str(uuid.uuid4())

        # Store new user
        users_table.put_item(
            Item={
                'userId': user_id,
                'userName': user_name,
                'email': email,
                'password': storage_format,  # Storing salt and hashed password
                'organizationId': organization_id
            }
        )

        # Return username and email
        return {
            "statusCode": 201,
            "body": json.dumps({"userName": user_name, "email": email})
        }

    except Exception as e:
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}
