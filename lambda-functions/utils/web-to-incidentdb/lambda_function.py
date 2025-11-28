# file: incident_update_lambda.py  (Python 3.12)
import os
import json
import boto3
from datetime import datetime, timezone
from botocore.exceptions import ClientError

INCIDENT_TABLE = os.environ["INCIDENT_TABLE"]

dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table(INCIDENT_TABLE)

ALLOWED_STATUS = {"NEW", "PROCESSING", "MITIGATED", "CLOSED"}

def lambda_handler(event, context):
    # CORS 기본 헤더
    headers = {
        "Access-Control-Allow-Origin": "*",              # 필요시 특정 도메인으로 변경
        "Access-Control-Allow-Headers": "Content-Type",
        "Access-Control-Allow-Methods": "OPTIONS,POST",
    }

    # CORS 프리플라이트
    if event.get("httpMethod") == "OPTIONS":
        return {"statusCode": 200, "headers": headers, "body": ""}

    try:
        body = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        return {
            "statusCode": 400,
            "headers": headers,
            "body": json.dumps({"message": "invalid json"}),
        }

    incident_id = body.get("incident_id")
    status      = body.get("status")
    note        = body.get("note", "")

    if not incident_id or not status:
        return {
            "statusCode": 400,
            "headers": headers,
            "body": json.dumps({"message": "incident_id, status는 필수입니다."}),
        }

    status = str(status).upper()
    if status not in ALLOWED_STATUS:
        return {
            "statusCode": 400,
            "headers": headers,
            "body": json.dumps({"message": f"status는 {ALLOWED_STATUS} 중 하나여야 합니다."}),
        }

    now_iso = datetime.now(timezone.utc).isoformat()

    # DynamoDB Update
    try:
        resp = table.update_item(
            Key={"incident_id": incident_id},
            UpdateExpression="SET #s = :s, #n = :n, updated_at = :u",
            ExpressionAttributeNames={
                "#s": "status",
                "#n": "note",
            },
            ExpressionAttributeValues={
                ":s": status,
                ":n": note,
                ":u": now_iso,
            },
            ReturnValues="ALL_NEW",
        )
        updated_item = resp.get("Attributes", {})
    except ClientError as e:
        print("DynamoDB update error:", e)
        return {
            "statusCode": 500,
            "headers": headers,
            "body": json.dumps({"message": "DynamoDB update error"}),
        }

    return {
        "statusCode": 200,
        "headers": headers,
        "body": json.dumps({
            "message": "ok",
            "incident": updated_item,
        }),
    }
