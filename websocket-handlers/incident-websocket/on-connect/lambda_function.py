import os
import json
import time
import boto3
from botocore.exceptions import ClientError

# ===== ENV =====
CONNECTIONS_TABLE = os.environ["CONNECTIONS_TABLE"]  
TTL_HOURS = int(os.getenv("TTL_HOURS", "24"))        

# ===== Clients =====
dynamodb = boto3.resource("dynamodb")
conn_tbl = dynamodb.Table(CONNECTIONS_TABLE)

def lambda_handler(event, context):
    cid = event["requestContext"]["connectionId"]

    now_sec = int(time.time())               
    now_ms  = now_sec * 1000                  
    ttl_val = now_sec + TTL_HOURS * 3600

    print(f"[{os.getenv('AWS_LAMBDA_FUNCTION_NAME','connect')}] "
          f"TTL_HOURS={TTL_HOURS} now={now_sec} ttl={ttl_val} cid={cid}")

    item = {
        "connectionId": cid,
        "createdAt": now_ms,                   
        "ttl": ttl_val,                       
        "clientId": "unknown",
    }

    try:
        conn_tbl.put_item(Item=item)
        print(f"[connect] upsert {cid}")
        try:
            res = conn_tbl.get_item(Key={"connectionId": cid})
            print("[connect] stored item:", res.get("Item"))
        except ClientError as ge:
            print("[connect] get_item skipped/denied:", ge)
    except ClientError as e:
        print("[connect] put error:", e)

    print(":white_check_mark: Lambda finished successfully. Returning response to API Gateway.")

    return {
        "statusCode": 200,
        "body": "Connected"
    }
