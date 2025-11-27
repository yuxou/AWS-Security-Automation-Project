import os
import time
import json
import boto3

# 환경 변수 및 DB 연결
CONNECTIONS_TABLE = os.environ["CONNECTIONS_TABLE"]
dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table(CONNECTIONS_TABLE)

def lambda_handler(event, context):
    print("### CONNECT EVENT ###")
    
    # 1. Connection ID 확보
    rc = event.get("requestContext") or {}
    conn_id = (rc.get("connectionId") or "").strip()
    if not conn_id:
        return {"statusCode": 400, "body": "missing connectionId"}

    # 2. 정보 추출 (없으면 없는 대로 진행)
    qs = event.get("queryStringParameters") or {}
    client_id = (qs.get("clientId") or "").strip()
    account   = (qs.get("account") or "").strip()
    region    = (qs.get("region") or "").strip()
    
    identity  = (rc.get("identity") or {})
    source_ip = (identity.get("sourceIp") or "").strip()

    # 3. 저장할 데이터 생성
    # TTL: 24시간 (86400초)
    expire_at = int(time.time()) + 86400 

    item = {
        "connectionId": conn_id,
        "createdAt": int(time.time() * 1000),
        "ttl": expire_at,
    }
    
    # 있으면 넣고, 없으면 만다 (빈 값이라도 에러 안 남)
    if client_id: item["clientId"] = client_id
    if account: item["account"] = account
    if region: item["region"] = region
    if source_ip: item["sourceIp"] = source_ip

    # 4. [핵심] 무조건 저장만 함 (삭제 로직 0줄)
    try:
        table.put_item(Item=item)
        print(f"✅ SAVE SUCCESS: {conn_id} (User: {client_id}, IP: {source_ip})")
    except Exception as e:
        print(f"❌ SAVE FAILED: {e}")
        return {"statusCode": 500, "body": "DB Error"}

    # [중요] 예전 연결 정리(Cleanup) 코드가 아예 없습니다.
    # 따라서 절대 자기 자신을 지울 수 없습니다.

    return {"statusCode": 200, "body": "connected"}