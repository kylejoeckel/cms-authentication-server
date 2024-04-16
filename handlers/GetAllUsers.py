import json
import boto3

# Initialize DynamoDB client
dynamodb = boto3.resource('dynamodb')
users_table = dynamodb.Table('Users')

def getAllUsersByOrganization(event, context):
    try:
        # Extract organizationId from the path parameters
        organization_id = event['pathParameters']['organizationId']

        # Query DynamoDB using the GSI on organizationId
        response = users_table.query(
            IndexName='OrganizationIdIndex',  # Ensure this GSI exists in your DynamoDB setup
            KeyConditionExpression='organizationId = :org_id',
            ExpressionAttributeValues={':org_id': organization_id}
        )

        # Check if any users were found
        if not response['Items']:
            return {
                "statusCode": 404,
                "body": json.dumps({"error": "No users found for this organization"})
            }

        # Remove sensitive data from user details
        users = response['Items']
        for user in users:
            user.pop('password', None)  # Remove password field if present

        # Return all user data
        return {
            "statusCode": 200,
            "body": json.dumps(users)
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)})
        }