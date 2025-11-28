
import json
import os
import boto3
import datetime
import time
import random

# ===============================================
# 환경 변수
# ===============================================
WS_ENDPOINT = os.environ.get('WS_ENDPOINT')
REGION = os.environ.get('TARGET_REGION', 'us-east-1')
CONNECTIONS_TABLE = os.environ.get('CONNECTIONS_TABLE', 'WebSocketConnections')
ALERT_STATE_TABLE = os.environ.get('ALERT_STATE_TABLE', 'security-alerts-state-v2')
INCIDENT_TABLE_NAME = os.environ.get('INCIDENT_TABLE_NAME')   # 🔥 추가된 부분

# ===============================================
# AWS 클라이언트 초기화
# ===============================================
def get_api_gateway_client():
    return boto3.client(
        'apigatewaymanagementapi',
        endpoint_url=f"https://{WS_ENDPOINT}",
        region_name=REGION
    )

def get_dynamodb_resource():
    return boto3.resource('dynamodb', region_name=REGION)

def get_alert_state_table():
    return get_dynamodb_resource().Table(ALERT_STATE_TABLE)

# ===============================================
# 유틸 함수
# ===============================================
def to_epoch_millis_kst(iso_time):
    try:
        dt = datetime.datetime.fromisoformat(iso_time.replace('Z', '+00:00'))
        dt = dt.astimezone(datetime.timezone(datetime.timedelta(hours=9)))  # KST
        return int(dt.timestamp() * 1000)
    except Exception:
        return int(time.time() * 1000)

def generate_alert_key(resource_name, event_type):
    return f"{resource_name}#{event_type}"

def generate_incident_id(prefix: str = "inc") -> str:
    ts = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    rand = random.randint(0, 999)
    return f"{prefix}-{ts}-{rand:03d}"

# ===============================================
# 웹소켓 전송
# ===============================================
def post_to_all_active_connections(message_data):
    table = get_dynamodb_resource().Table(CONNECTIONS_TABLE)
    api_client = get_api_gateway_client()
    message_json = json.dumps(message_data).encode('utf-8')

    try:
        response = table.scan(ProjectionExpression='connectionId')
        connection_ids = [item['connectionId'] for item in response['Items']]
    except Exception as e:
        print(f"❌ Failed to scan connections: {e}")
        return

    for connection_id in connection_ids:
        try:
            api_client.post_to_connection(ConnectionId=connection_id, Data=message_json)
        except api_client.exceptions.GoneException:
            table.delete_item(Key={'connectionId': connection_id})
        except Exception as e:
            print(f"❌ Failed to send message to {connection_id}: {e}")

# ===============================================
# Incident DB 저장 / 업데이트
# ===============================================
def send_incident_to_db(incident_data: dict, action: str) -> str:
    """
    Incident DB에 인시던트 기록 또는 업데이트 수행
    action: NEW 또는 UPDATE
    """
    if not INCIDENT_TABLE_NAME:
        print("❌ ERROR: INCIDENT_TABLE_NAME 환경 변수가 설정되지 않음")
        return ""

    table = get_dynamodb_resource().Table(INCIDENT_TABLE_NAME)
    now_iso = datetime.datetime.utcnow().isoformat()[:-3] + "Z"

    try:
        if action == "NEW":
            incident_id = generate_incident_id("inc")  # UUID 대신 통일된 ID 사용
            item = {
                'incident_id': incident_id,
                'event_type': incident_data.get('type', 'Unknown'),
                'resource': incident_data.get('sg') or incident_data.get('resource'),
                'severity': incident_data.get('severity', 'LOW'),
                'status': 'NEW',
                'created_at': now_iso,
                'updated_at': now_iso,
                'details': json.dumps(incident_data)
            }
            table.put_item(Item=item)
            print(f"🟢 Incident NEW saved: {incident_id}")
            return incident_id

        elif action == "UPDATE":
            incident_id = incident_data.get('incident_id')
            if not incident_id:
                print("❌ UPDATE 호출 오류: incident_id 없음")
                return ""

            table.update_item(
                Key={'incident_id': incident_id},
                UpdateExpression="SET #s = :status, updated_at = :updated",
                ExpressionAttributeNames={'#s': 'status'},
                ExpressionAttributeValues={
                    ':status': incident_data.get('status', 'PROCESSING'),
                    ':updated': now_iso
                }
            )
            print(f"🟡 Incident UPDATED: {incident_id} → {incident_data.get('status')}")
            return incident_id

        else:
            print(f"❌ Unknown action type: {action}")
            return ""

    except Exception as e:
        print(f"❌ Incident DB Error: {e}")
        return ""

# ===============================================
# S3 이벤트 분석 (CloudTrail 기반)
# ===============================================
def analyze_s3_event(event_detail):
    event_name = event_detail.get('eventName', '')
    request_params = event_detail.get('requestParameters', {}) or {}

    bucket_name = request_params.get('bucketName') or request_params.get('Bucket') or 'UnknownBucket'
    object_key = request_params.get('key') or request_params.get('Key')

    if bucket_name == 'UnknownBucket':
        resources = event_detail.get('resources', [])
        for r in resources:
            if 'ARN' in r:
                arn_parts = r['ARN'].split(':::')
                if len(arn_parts) >= 2:
                    bucket_name = arn_parts[-1]
                    break

    account = event_detail.get('userIdentity', {}).get('accountId', 'UnknownAccount')
    region = event_detail.get('awsRegion', REGION)
    event_time = event_detail.get('eventTime', datetime.datetime.utcnow().isoformat())

    s3_event_map = {
        'PutBucketAcl': ('ACL 직접 변경', 'HIGH'),
        'PutObjectAcl': ('객체 ACL 변경', 'HIGH'),
        'DeleteBucketAcl': ('ACL 제거', 'CRITICAL'),
        'PutBucketPolicy': ('버킷 정책 수정', 'HIGH'),
        'DeleteBucketPolicy': ('버킷 정책 삭제 위험', 'CRITICAL'),
        'PutPublicAccessBlock': ('퍼블릭 액세스 차단 설정 변경', 'HIGH'),
        'PutAccountPublicAccessBlock': ('계정 퍼블릭 액세스 차단 설정 변경', 'HIGH'),
        'PutBucketWebsite': ('정적 웹사이트 설정 활성화', 'HIGH'),
        'PutBucketCors': ('CORS 설정 변경', 'INFO'),
        'PutBucketOwnershipControls': ('ACL 제거 (ACL 비활성화)', 'CRITICAL')
    }

    if event_name not in s3_event_map:
        print(f"⚠️ No relevant S3 security event for {event_name}")
        return None, None

    event_type, severity = s3_event_map[event_name]

    if event_name == "PutAccountPublicAccessBlock":
        resource_path = f"Account-{account}"
        arn_path = f"arn:aws:s3control:::{account}:public-access-block"
    elif object_key:
        resource_path = f"{bucket_name}/{object_key}"
        arn_path = f"arn:aws:s3:::{bucket_name}/{object_key}"
    else:
        resource_path = bucket_name
        arn_path = f"arn:aws:s3:::{bucket_name}"

    if bucket_name == "UnknownBucket":
        resource_path = f"Account-{account}"

    alert = {
        "time": to_epoch_millis_kst(event_time),
        "source": "S3",
        "type": event_type,
        "resource": resource_path,
        "sg": None,
        "arn": arn_path,
        "account": account,
        "region": region,
        "severity": severity
    }

    return alert, f"S3 Security Event Detected: {event_type}"

# ===============================================
# GuardDuty 이벤트 분석
# ===============================================
def analyze_guardduty_event(detail):
    severity_score = detail.get('severity', 3)
    if severity_score >= 7:
        severity = 'HIGH'
    elif severity_score >= 4:
        severity = 'MEDIUM'
    else:
        severity = 'LOW'

    instance_details = detail.get('resource', {}).get('instanceDetails', {})
    resource = instance_details.get('instanceId', detail.get('resource', {}).get('resourceType', 'UnknownResource'))
    sg_list = instance_details.get('securityGroups', [None])
    sg = sg_list[0] if sg_list else None
    arn = detail.get('resource', {}).get('resourceArn', f"arn:aws:guardduty::{REGION}:finding")

    alert = {
        "time": to_epoch_millis_kst(detail.get('createdAt', datetime.datetime.utcnow().isoformat())),
        "source": "GuardDuty",
        "type": detail.get('type', 'UnknownFinding'),
        "resource": resource,
        "sg": sg,
        "arn": arn,
        "account": detail.get('accountId', 'UnknownAccount'),
        "region": detail.get('region', REGION),
        "severity": severity
    }

    return alert, f"GuardDuty Event: {alert['type']}"

# ===============================================
# Config 이벤트 분석
# ===============================================
def analyze_config_event(detail):
    rule_name = detail.get('configRuleName')
    compliance_type = detail.get('newEvaluationResult', {}).get('complianceType')
    resource_id = detail.get('newEvaluationResult', {}).get('evaluationResultIdentifier', {}).get('evaluationResultQualifier', {}).get('ResourceId', 'UnknownBucket')
    region = detail.get('awsRegion', REGION)
    account = detail.get('accountId', 'UnknownAccount')
    event_time = detail.get('notificationCreationTime', datetime.datetime.utcnow().isoformat())

    if compliance_type != 'NON_COMPLIANT':
        print(f"✅ Config rule {rule_name} is COMPLIANT - ignoring")
        return None, None

    s3_event_map = {
        's3-bucket-public-read-prohibited': ('퍼블릭 읽기 차단 위반', 'HIGH'),
        's3-bucket-public-write-prohibited': ('퍼블릭 쓰기 차단 위반', 'HIGH')
    }

    event_type, severity = s3_event_map.get(rule_name, ('S3 Config Rule Violation', 'HIGH'))
    alert = {
        "time": to_epoch_millis_kst(event_time),
        "source": "S3-Config",
        "type": event_type,
        "resource": resource_id,
        "sg": None,
        "arn": f"arn:aws:s3:::{resource_id}",
        "account": account,
        "region": region,
        "severity": severity
    }

    return alert, f"Config Alert: {event_type} for {resource_id}"

# ===============================================
# DynamoDB 저장
# ===============================================
def save_alert_to_dynamodb(alert):
    table = get_alert_state_table()
    alert_key = generate_alert_key(alert['resource'], alert['type'])
    table.put_item(Item={
        'id': alert_key,
        'Timestamp': alert['time'],
        'Severity': alert['severity'],
        'AlertData': alert
    })
    print(f"📝 Saved to DynamoDB: {alert_key}")
    return alert_key

# ===============================================
# Lambda 메인 핸들러
# ===============================================
def lambda_handler(event, context):
    print(f"📥 Received event: {json.dumps(event)}")
    alerts_to_send = []

    detail = event.get('detail', {})
    source = event.get('source', '')

    alert = None

    # 🔹 S3 / S3Control
    if source in ['aws.s3', 'aws.s3control'] and 'eventName' in detail:
        alert, message = analyze_s3_event(detail)

    # 🔹 GuardDuty
    elif source == 'aws.guardduty':
        alert, message = analyze_guardduty_event(detail)

    # 🔹 Config
    elif source == 'aws.config' and detail.get('configRuleName'):
        alert, message = analyze_config_event(detail)

    if not alert:
        return {'statusCode': 200, 'body': 'No alert'}

    # 1) 상태 저장
    save_alert_to_dynamodb(alert)

    # 2) Incident DB에 인시던트 생성
    incident_id = send_incident_to_db(alert, "NEW")
    alert["incident_id"] = incident_id

    # 3) 웹소켓 전송
    alerts_to_send.append(alert)

    for alert_item in alerts_to_send:
        post_to_all_active_connections(alert_item)
        print(f"📡 Broadcasted: {alert_item['type']}")

    return {
        'statusCode': 200,
        'body': json.dumps({'message': 'Processed alerts', 'incident_id': incident_id})
    }
