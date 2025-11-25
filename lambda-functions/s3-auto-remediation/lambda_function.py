import json
import os
import boto3
import datetime
import time
import random
from botocore.exceptions import ClientError

# ===============================================
# 환경 변수
# ===============================================
REMEDIATION_WS_ENDPOINT = os.environ.get('REMEDIATION_WS_ENDPOINT')
REGION_WS = os.environ.get('REGION_WS', 'us-east-1')
REGION = os.environ.get('AWS_REGION', 'us-east-1')
REMEDIATION_CONNECTIONS_TABLE = os.environ.get('REMEDIATION_CONNECTIONS_TABLE', 'RemediationWebSocketConnections')
INCIDENT_TABLE = os.environ.get('INCIDENT_TABLE_NAME', 'Incidents')

DYNAMODB_CLIENT = boto3.resource('dynamodb', region_name=REGION)

# ===============================================
# 유틸리티 함수
# ===============================================
def generate_incident_id(prefix="inc"):
    ts = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    rand = random.randint(0, 999)
    return f"{prefix}-{ts}-{rand:03d}"

def get_s3_client(region=REGION):
    return boto3.client('s3', region_name=region)

def get_api_gateway_client(endpoint, region=REGION_WS):
    if not endpoint:
        raise ValueError("WebSocket endpoint 환경 변수가 설정되지 않았습니다.")
    endpoint_url = endpoint.strip()
    if not endpoint_url.startswith("http"):
        endpoint_url = f"https://{endpoint_url}"
    endpoint_url = endpoint_url.rstrip('/')
    return boto3.client('apigatewaymanagementapi', endpoint_url=endpoint_url, region_name=region)

def generate_remediation_json(bucket_name, status, action="보안 정책 삭제", playbook="퍼블릭 정책 제거"):
    time_str = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + 'Z'
    return {
        "time": time_str,
        "action": action,
        "target": bucket_name,
        "playbook": playbook,
        "status": status
    }

# ===============================================
# WebSocket 전송
# ===============================================
def post_remediation_status(json_data):
    if not REMEDIATION_WS_ENDPOINT:
        print("❌ ERROR: REMEDIATION_WS_ENDPOINT 환경 변수가 없습니다.")
        return False

    table = DYNAMODB_CLIENT.Table(REMEDIATION_CONNECTIONS_TABLE)
    try:
        api_client = get_api_gateway_client(REMEDIATION_WS_ENDPOINT)
        message_json = json.dumps(json_data).encode('utf-8')

        response = table.scan(ProjectionExpression='connectionId')
        connection_ids = [item['connectionId'] for item in response.get('Items', [])]

        success_count = 0
        for connection_id in connection_ids:
            try:
                api_client.post_to_connection(ConnectionId=connection_id, Data=message_json)
                success_count += 1
            except api_client.exceptions.GoneException:
                table.delete_item(Key={'connectionId': connection_id})
            except Exception as e:
                if '410' in str(e):
                    table.delete_item(Key={'connectionId': connection_id})
                else:
                    print(f"❌ Failed to post message to {connection_id}: {e}")

        print(f"DEBUG: Remediation Status Sent: {json_data['status']} ({success_count} connections)")
        return True
    except Exception as e:
        print(f"❌ ERROR posting status: {e}")
        return False

# ===============================================
# 인시던트 DB 처리
# ===============================================
def save_incident(ddb, table_name, bucket, severity, event_type, status):
    try:
        table = ddb.Table(table_name)
        inc_id = generate_incident_id("inc")
        now = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        item = {
            "incident_id": inc_id,
            "event_type": event_type,
            "resource": bucket,
            "severity": severity,
            "status": status,
            "note": "운영팀 확인 중",
            "created_at": now,
            "updated_at": now
        }
        table.put_item(Item=item)
        print(f"🟢 인시던트 저장 성공: {inc_id}")
        return inc_id
    except Exception as e:
        print(f"❌ 인시던트 저장 오류: {e}")
        return None

def update_incident_status(ddb, table_name, incident_id, status, note=None):
    try:
        table = ddb.Table(table_name)
        now = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        update_expression = "SET #s=:s, updated_at=:u"
        expr_attr_values = {":s": status, ":u": now}
        expr_attr_names = {"#s": "status"}
        if note:
            update_expression += ", note=:n"
            expr_attr_values[":n"] = note
        table.update_item(
            Key={"incident_id": incident_id},
            UpdateExpression=update_expression,
            ExpressionAttributeNames=expr_attr_names,
            ExpressionAttributeValues=expr_attr_values
        )
        print(f"🟡 인시던트 상태 업데이트: {incident_id} → {status}")
        return True
    except Exception as e:
        print(f"❌ 인시던트 상태 업데이트 오류: {e}")
        return False

# ===============================================
# 퍼블릭 정책 판단
# ===============================================
def is_public_policy(policy):
    try:
        for stmt in policy.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            principal = stmt.get("Principal")
            if principal not in ["*", {"AWS": "*"}]:
                continue
            actions = stmt.get("Action")
            if isinstance(actions, str):
                actions = [actions]
            risky = ["s3:GetObject", "s3:ListBucket", "s3:*"]
            if any(a in actions for a in risky):
                return True
        return False
    except Exception as e:
        print(f"❌ 정책 검사 오류: {e}")
        return False

# ===============================================
# S3 정책 제거
# ===============================================
def delete_bucket_policy(bucket_name, s3_client):
    try:
        s3_client.delete_bucket_policy(Bucket=bucket_name)
        print(f"✅ 정책 제거 성공: {bucket_name}")
        return True
    except ClientError as e:
        print(f"❌ S3 삭제 실패: {bucket_name} - {e}")
        return False
    except Exception as e:
        print(f"❌ UNEXPECTED ERROR for {bucket_name}: {e}")
        return False

# ===============================================
# Lambda 핸들러
# ===============================================
def lambda_handler(event, context):
    print(f"Received S3 event: {json.dumps(event)}")

    # 버킷 이름 추출
    try:
        bucket_name = event['detail']['requestParameters']['bucketName']
    except KeyError:
        print("❌ 이벤트에서 버킷 이름을 추출할 수 없습니다.")
        return {'statusCode': 400, 'body': 'Bucket name missing in event'}

    s3_client = get_s3_client()

    # 인시던트 생성 (PROCESSING)
    inc_id = save_incident(
        DYNAMODB_CLIENT, INCIDENT_TABLE, bucket_name,
        severity="HIGH",
        event_type="퍼블릭 버킷 정책 삭제",
        status="PROCESSING"
    )

    # WebSocket TRIGGERED 전송
    post_remediation_status(generate_remediation_json(bucket_name, status="TRIGGERED"))

    # 정책 확인
    try:
        pol = s3_client.get_bucket_policy(Bucket=bucket_name)
        policy = json.loads(pol["Policy"])
        print("📄 정책 조회 성공")
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
            print("⚠️ 정책 없음 — 종료")
            update_incident_status(DYNAMODB_CLIENT, INCIDENT_TABLE, inc_id, "MITIGATED", note="정책 없음")
            post_remediation_status(generate_remediation_json(bucket_name, status="MITIGATED"))
            return {"statusCode": 200, "body": "No policy"}
        print(f"❌ 정책 조회 오류: {e}")
        update_incident_status(DYNAMODB_CLIENT, INCIDENT_TABLE, inc_id, "FAILED")
        post_remediation_status(generate_remediation_json(bucket_name, status="FAILED"))
        return {"statusCode": 500, "body": "Policy read failed"}

    # 퍼블릭 정책 여부 확인
    if not is_public_policy(policy):
        print("👍 퍼블릭 위험 아님 — 삭제 불필요")
        update_incident_status(DYNAMODB_CLIENT, INCIDENT_TABLE, inc_id, "MITIGATED", note="퍼블릭 아님")
        post_remediation_status(generate_remediation_json(bucket_name, status="MITIGATED"))
        return {"statusCode": 200, "body": "Not public policy"}

    # 정책 삭제
    deleted = delete_bucket_policy(bucket_name, s3_client)
    final_status = "SUCCEEDED" if deleted else "FAILED"

    update_incident_status(DYNAMODB_CLIENT, INCIDENT_TABLE, inc_id,
                           status="MITIGATED" if deleted else "FAILED",
                           note="정책 삭제 완료" if deleted else "삭제 실패")

    # WebSocket SUCCEEDED / FAILED 전송
    post_remediation_status(generate_remediation_json(bucket_name, status=final_status))

    return {"statusCode": 200, "body": json.dumps({"status": final_status})}
