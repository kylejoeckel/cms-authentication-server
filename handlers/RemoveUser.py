import json
import boto3

# Initialize DynamoDB client
dynamodb = boto3.resource('dynamodb')
users_table = dynamodb.Table('cms-users')

def removeUser(event, context):
    try:
        # Extract userId from the path parameters
        user_id = event['pathParameters']['userId']

        # Attempt to delete the user from the database
        response = users_table.delete_item(
            Key={'userId': user_id},
            ReturnValues='ALL_OLD'
        )

        # Check if a user was actually deleted
        if 'Attributes' not in response:
            return {
                "statusCode": 404,
                "body": json.dumps({"error": "User not found or already deleted"})
            }

        # Return success message
        return {
            "statusCode": 200,
            "body": json.dumps({"success": "User deleted successfully"})
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)})
        }