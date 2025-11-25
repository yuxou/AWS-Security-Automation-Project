# file: incident_stream_processor.py
import os
import json
import boto3
from decimal import Decimal
from botocore.exceptions import ClientError

# ===== 환경 변수 =====
WS_ENDPOINT = os.environ["WS_ENDPOINT"] 
CONNECTIONS_TABLE = os.environ["CONNECTIONS_TABLE"] 

# ====== CLIENTS ======
apigw = boto3.client("apigatewaymanagementapi", endpoint_url=WS_ENDPOINT)
dynamodb_resource = boto3.resource("dynamodb")
connections_table = dynamodb_resource.Table(CONNECTIONS_TABLE)

class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return int(obj) if obj % 1 == 0 else float(obj)
        return super(DecimalEncoder, self).default(obj)

def _dynamodb_item_to_json(item: dict) -> dict:
    if not item: return {}
    from boto3.dynamodb.types import TypeDeserializer
    deserializer = TypeDeserializer()
    return {k: deserializer.deserialize(v) for k, v in item.items()}

def post_to_all_active_connections(message_data: dict):
    message_json = json.dumps(message_data, cls=DecimalEncoder, ensure_ascii=False).encode("utf-8")
    try:
        response = connections_table.scan(ProjectionExpression='connectionId')
        items = response.get('Items', [])
    except Exception as e:
        print(f"❌ Scan failed: {e}")
        return

    if not items: return

    for item in items:
        cid = item['connectionId']
        try:
            apigw.post_to_connection(ConnectionId=cid, Data=message_json)
        except ClientError as e:
            if e.response['Error']['Code'] in ['GoneException', '410']:
                try: connections_table.delete_item(Key={'connectionId': cid})
                except: pass

def lambda_handler(event, context):
    for record in event['Records']:
        if record['eventName'] not in ['INSERT', 'MODIFY']:
            continue
            
        new_image = record['dynamodb'].get('NewImage')
        if not new_image: continue
            
        try:
            data = _dynamodb_item_to_json(new_image)
            lower_keys = {k.lower(): k for k in data.keys()}
            
            payload = {}

            id_key = lower_keys.get("incident_id") or lower_keys.get("incidentid") or lower_keys.get("id")
            
            if id_key:
                print(f"Security Incident: {data[id_key]}")
                
                real_resource = data.get("arn") or data.get("resource") or data.get("sg") or "-"

                payload = {
                    "kind": "incident_update",
                    "incident_id": data[id_key],
                    "status": data.get("status", "UNKNOWN"),
                    "severity": data.get("severity"),
                    "event_type": data.get("event_type", data.get("type")),
                    "resource": real_resource,
                    "created_at": data.get("created_at"),
                    "updated_at": data.get("updated_at") 
                }

            elif "action" in lower_keys:
                print(f"✅ Remediation Log: {data.get('action')}")
                payload = {
                    "kind": "remediation",
                    "time": data.get("created_at", data.get("timestamp")),
                    "action": data.get("action"),
                    "target": data.get("target", data.get("resource")),
                    "status": data.get("status"),
                    "incident_id": data.get("incident_id")
                }

            if payload:
                post_to_all_active_connections(payload)
            
        except Exception as e:
            print(f"❌ Error: {e}")
            
    return {"statusCode": 200}
