import json
import bcrypt
import boto3
import jwt
import datetime

# Initialize DynamoDB client
dynamodb = boto3.resource('dynamodb')
users_table = dynamodb.Table('cms-users')

# Configuration for JWT
SECRET_KEY = "your_secret_key"  # Replace with your secret key
JWT_ALGORITHM = "HS256"
JWT_EXP_DELTA_SECONDS = 600  # Token expiration time

def authenticate(event, context):
    try:
        # Parse incoming event body
        body = json.loads(event['body'])
        user_login = body['userLogin']  # This can be either username or email
        password = body['password']

        # Query the user either by username or email
        response = users_table.scan(
            FilterExpression='email = :login or userName = :login',
            ExpressionAttributeValues={':login': user_login}
        )
        if not response['Items']:
            return {"statusCode": 404, "body": json.dumps({"error": "User not found"})}

        user = response['Items'][0]  # Assuming the first match

        # Check if the provided password matches the stored hash
        if not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            return {"statusCode": 401, "body": json.dumps({"error": "Invalid password"})}

        # Remove password from user data to return
        del user['password']

        # Create JWT token
        payload = {
            "user_id": user['userId'],
            "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=JWT_EXP_DELTA_SECONDS)
        }
        jwt_token = jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)

        # Return JWT token and user data
        return {
            "statusCode": 200,
            "body": json.dumps({"jwt": jwt_token, "user": user})
        }

    except Exception as e:
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}