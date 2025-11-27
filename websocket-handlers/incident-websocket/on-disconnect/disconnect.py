import os
import json
import boto3

CONNECTIONS_TABLE = os.environ["CONNECTIONS_TABLE"]  

dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table(CONNECTIONS_TABLE)

def lambda_handler(event, context):
    print("[onDisconnectIncident] event =", json.dumps(event))

    cid = event["requestContext"]["connectionId"]
    print(f"[onDisconnectIncident] deleting connectionId={cid}")

    try:
        table.delete_item(Key={"connectionId": cid})
        print("[onDisconnectIncident] delete_item OK")
    except Exception as e:
        print("[onDisconnectIncident] delete_item error:", e)

    return {"statusCode": 200, "body": "disconnected"}
