# disconnect.py
import os, boto3

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(os.environ['CONNECTIONS_TABLE'])

def lambda_handler(event, context):
    conn_id = event['requestContext']['connectionId']

    print(f"🚨 [TRAP] Connection {conn_id} lost! But I saved it from deletion.")
    table.delete_item(Key={'connectionId': conn_id})
    return {'statusCode': 200, 'body': 'disconnected'}
