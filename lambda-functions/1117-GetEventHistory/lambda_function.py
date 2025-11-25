# file: incident_subscribe.py
import os
import json
import time
from typing import Any, Dict, List

import boto3
from boto3.dynamodb.conditions import Attr
from botocore.exceptions import ClientError

# ===== ENV =====
INCIDENT_TABLE     = os.environ["INCIDENT_TABLE"]                 # Incident
CONNECTIONS_TABLE  = os.environ["CONNECTIONS_TABLE"]              # IncidentWebSocketConnections
WS_ENDPOINT        = os.environ["WS_ENDPOINT"]                    # https://vzt0ffjt3.execute-api.us-east-1.amazonaws.com/prod
TTL_HOURS          = int(os.getenv("TTL_HOURS", "24"))

# ===== Clients =====
dynamodb     = boto3.resource("dynamodb")
incident_tbl = dynamodb.Table(INCIDENT_TABLE)
conn_tbl     = dynamodb.Table(CONNECTIONS_TABLE)
apigw        = boto3.client("apigatewaymanagementapi", endpoint_url=WS_ENDPOINT)

# ===== Helpers =====
def _safe_json_loads(s: str | None) -> Dict[str, Any]:
    if not s:
        return {}
    try:
        return json.loads(s)
    except Exception:
        return {}

def _build_filter_expression(body: Dict[str, Any]):
    fe = None
    cursor = body.get("cursor")
    if cursor:
        fe2 = Attr("created_at").lt(cursor)
        fe = fe2 if fe is None else fe & fe2
    severity = body.get("severity")
    if severity:
        if isinstance(severity, str):
            severity = [severity]
        fe2 = Attr("severity").is_in(severity)
        fe = fe2 if fe is None else fe & fe2
    status = body.get("status")
    if status:
        if isinstance(status, str):
            status = [status]
        fe2 = Attr("status").is_in(status)
        fe = fe2 if fe is None else fe & fe2
    return fe

# ===== Handler =====
def lambda_handler(event, context):
    """
    Route: subscribe
    - 현재 connectionId 를 Connections 테이블에 upsert (TTL 포함)
      * 기존 TTL을 '짧게' 덮어쓰지 않도록 if_not_exists 사용
    - Incident 테이블에서 최근 N건을 조회하여 해당 connectionId로 push
    """
    cid  = event["requestContext"]["connectionId"]
    body = _safe_json_loads(event.get("body"))
    now_sec = int(time.time())
    ttl_val = now_sec + TTL_HOURS * 3600

    print(f"[{os.getenv('AWS_LAMBDA_FUNCTION_NAME','subscribe')}] "
          f"TTL_HOURS={TTL_HOURS} now={now_sec} newTTL={ttl_val} cid={cid}")

    # 1) connection upsert (+ TTL)
    try:
        conn_tbl.update_item(
            Key={"connectionId": cid},
            UpdateExpression="""
              SET #createdAt = if_not_exists(#createdAt, :ca),
                  #ttl       = if_not_exists(#ttl,       :t),
                  #clientId  = if_not_exists(#clientId,  :cl)
            """,
            ExpressionAttributeNames={
                "#createdAt": "createdAt",
                "#ttl": "ttl",              # ✅ 예약어 치환
                "#clientId": "clientId",
            },
            ExpressionAttributeValues={
                ":ca": now_sec * 1000,      # ms
                ":t":  ttl_val,             # ✅ 초 단위 Number
                ":cl": "unknown",
            }
        )
        try:
            res = conn_tbl.get_item(Key={"connectionId": cid})
            print("[subscribe] upserted item:", res.get("Item"))
        except ClientError as ge:
            print("[subscribe] get_item skipped/denied:", ge)
    except ClientError as e:
        print("[subscribe] connection upsert failed:", e)

    # 2) incidents 조회
    try:
        limit = int(body.get("limit") or 50)
    except Exception:
        limit = 50
    limit = max(1, min(limit, 200))

    scan_kwargs: Dict[str, Any] = {}
    fe = _build_filter_expression(body)
    if fe is not None:
        scan_kwargs["FilterExpression"] = fe

    items: List[Dict[str, Any]] = []
    last_key = None
    while True:
        if last_key:
            scan_kwargs["ExclusiveStartKey"] = last_key
        try:
            resp = incident_tbl.scan(**scan_kwargs)
        except ClientError as e:
            print("[subscribe] DynamoDB scan error:", e)
            return {"statusCode": 500, "body": "DynamoDB Scan Failed"}
        items.extend(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key or len(items) >= limit * 3:
            break

    items.sort(key=lambda x: x.get("created_at", 0), reverse=True)
    sliced = items[:limit]
    next_cursor = sliced[-1].get("created_at") if (sliced and len(sliced) == limit) else None

    payload = {
        "kind": "incident_history",
        "incidents": sliced,
        "nextCursor": next_cursor,
    }

    # 3) 해당 connectionId로 push (410일 때만 삭제)
    try:
        apigw.post_to_connection(
            ConnectionId=cid,
            Data=json.dumps(payload, ensure_ascii=False).encode("utf-8")
        )
        print(f"[subscribe] sent history to {cid}, count={len(sliced)}")
    except apigw.exceptions.GoneException:
        print("[subscribe] Gone 410, cleanup:", cid)
        try:
            conn_tbl.delete_item(Key={"connectionId": cid})
        except Exception as de:
            print("[subscribe] delete failed:", de)
    except apigw.exceptions.ForbiddenException as e:
        print("[subscribe] Forbidden on post_to_connection:", e)  # 삭제 금지
    except ClientError as e:
        print("[subscribe] post_to_connection error:", e)          # 삭제 금지

    return {"statusCode": 200, "body": "ok"}
