import json
import boto3
import jwt
import datetime
import hashlib
import os

# Initialize DynamoDB client
dynamodb = boto3.resource('dynamodb')
users_table = dynamodb.Table('cms-users')

# Configuration for JWT
SECRET_KEY = "your_secret_key"  # TODO: Replace with secret key
JWT_ALGORITHM = "HS256"
JWT_EXP_DELTA_SECONDS = 86400  # 24 hours


def verify_token(token):
    try:
        # Decode the token
        decoded = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return decoded
    except jwt.ExpiredSignatureError:
        return "Expired token. Please log in again."
    except jwt.InvalidTokenError:
        return "Invalid token. Please log in again."


def create_token(user):
    """Generate a new JWT for the user."""
    payload = {
        "user_id": user['userId'],
        "organization_id": user['organizationId'],
        "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=JWT_EXP_DELTA_SECONDS)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)


def authenticate(event, context):
    headers = event.get("headers", {})
    auth_header = headers.get("Authorization")
    if auth_header:
        token = auth_header.split(" ")[1]  # Assumes Bearer token
        print(token)
        decoded_token = verify_token(token)
        print(decoded_token)
        if isinstance(decoded_token, str):
            return {"statusCode": 401, "body": json.dumps({"error": decoded_token})}
        # Token is valid, issue a new token
        print(decoded_token['user_id'])
        user_id = decoded_token['user_id']
        organization_id = decoded_token['organization_id']
        response = users_table.get_item(
            Key={'userId': user_id, 'organizationId': organization_id})
        if 'Item' not in response:
            return {"statusCode": 404, "body": json.dumps({"error": "User not found"})}
        user = response['Item']
        new_jwt_token = create_token(user)
        del user['password']  # Remove password before sending response
        return {
            "statusCode": 200,
            "headers": {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": True,
            },
            "body": json.dumps({"jwt": new_jwt_token, "user": user})
        }

    # Fallback to original authentication method if no token is provided
    try:
        body = json.loads(event['body'])
        user_login = body['userLogin']
        password = body['password']

        response = users_table.scan(
            FilterExpression='email = :login or userName = :login',
            ExpressionAttributeValues={':login': user_login}
        )
        if not response['Items']:
            return {"statusCode": 404,
                    "headers": {
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Credentials": True,
                    },
                    "body": json.dumps({"error": "User not found"})}

        user = response['Items'][0]

        stored_salt, stored_hash = user['password'].split('$')
        computed_hash = hashlib.pbkdf2_hmac('sha256', password.encode(
            'utf-8'), bytes.fromhex(stored_salt), 100000)
        if computed_hash.hex() != stored_hash:
            return {"statusCode": 401,
                    "headers": {
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Credentials": True,
                    }, "body": json.dumps({"error": "Invalid password"})}

        del user['password']
        new_jwt_token = create_token(user)

        return {
            "statusCode": 200,
            "headers": {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": True,
            },
            "body": json.dumps({"jwt": new_jwt_token, "user": user})
        }

    except Exception as e:
        return {"statusCode": 500,
                "headers": {
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Credentials": True,
                },
                "body": json.dumps({"error": str(e)})}
