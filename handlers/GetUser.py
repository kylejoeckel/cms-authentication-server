import json
import boto3

# Initialize DynamoDB client
dynamodb = boto3.resource('dynamodb')
users_table = dynamodb.Table('cms-users')

def getUser(event, context):
    try:
        # Extract userId from the path parameters
        user_id = event['pathParameters']['userId']

        # Retrieve user from the database
        response = users_table.get_item(
            Key={'userId': user_id}
        )
        if 'Item' not in response:
            return {
                "statusCode": 404,
                "body": json.dumps({"error": "User not found"})
            }
        user = response['Item']

        # Remove sensitive data
        user.pop('password', None)

        # Return user data
        return {
            "statusCode": 200,
            "body": json.dumps(user)
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)})
        }