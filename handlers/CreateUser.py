import json
import bcrypt
import uuid
import boto3
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
            IndexName='EmailIndex',  # Make sure to create this GSI in your DynamoDB table definition
            KeyConditionExpression='email = :email',
            ExpressionAttributeValues={':email': email}
        )
        if response['Items']:
            return {"statusCode": 400, "body": json.dumps({"error": "Email already exists"})}

        # Check if organization exists
        response = organizations_table.get_item(
            Key={'organizationId': id}
        )
        if 'Item' not in response:
            return {"statusCode": 404, "body": json.dumps({"error": "Organization not found"})}

        # Hash password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        user_id = str(uuid.uuid4())

        # Store new user
        users_table.put_item(
            Item={
                'userId': user_id,
                'userName': user_name,
                'email': email,
                'password': hashed_password.decode('utf-8'),
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