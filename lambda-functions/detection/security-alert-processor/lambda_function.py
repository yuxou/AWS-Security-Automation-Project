import json
import os
import boto3
import datetime
import uuid
import random
import time
from botocore.exceptions import ClientError

WS_ENDPOINT = os.environ.get('WS_ENDPOINT', 'example.execute-api.ap-northeast-2.amazonaws.com/prod')
REGION = os.environ.get('TARGET_REGION', 'ap-northeast-2')
CONNECTIONS_TABLE = os.environ.get('CONNECTIONS_TABLE', 'WebSocketConnections')
REMEDIATION_LAMBDA_NAME = os.environ.get('REMEDIATION_LAMBDA_NAME', 'SecurityRemediationProcessor')
INCIDENT_TABLE_NAME = os.environ.get('INCIDENT_TABLE_NAME', 'Incident') 

HIGH_RISK_PORTS = [22, 3389, 3306, 5432, 21, 23]
SUSPICIOUS_KEYWORDS = ['test', 'temp', 'open', 'debug']

# ===============================================
# 인시던트 ID 생성 함수
# ===============================================

def generate_incident_id(prefix: str = "inc") -> str:
    """
    현재 UTC 시간과 랜덤 숫자를 기반으로 인시던트 ID를 생성합니다. (예: inc-20251119-111845-123)
    """
    ts = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    rand = random.randint(0, 999)
    return f"{prefix}-{ts}-{rand:03d}"

# ===============================================
# 유틸리티 함수
# ===============================================

def normalize_source(source: str) -> str:
    if not source:
        return "Unknown"

    s = source.lower().strip()

    if "signin" in s or "sts" in s:
        return "AWS Sign-In/STS"

    if "cloudtrail" in s:
        return "CloudTrail"

    if "cloudwatch" in s:
        return "CloudWatch"

    if "s3" in s:
        return "S3"

    if "ec2" in s:
        return "EC2"

    if "lambda" in s:
        return "Lambda"

    if "apigateway" in s:
        return "API Gateway"

    if "dynamodb" in s:
        return "DynamoDB"

    if "kms" in s:
        return "KMS"

    if "iam" in s:
        return "IAM"

    if s.endswith(".amazonaws.com"):
        svc = s.split(".")[0]
        return svc.capitalize()

    return source

def get_ec2_client():
    return boto3.client('ec2', region_name=REGION)

def get_api_gateway_client():
    endpoint_url = f"https://{WS_ENDPOINT}" if WS_ENDPOINT and not WS_ENDPOINT.startswith('http') else WS_ENDPOINT
    return boto3.client(
        'apigatewaymanagementapi',
        endpoint_url=endpoint_url,
        region_name=REGION
    )

def get_dynamodb_resource():
    return boto3.resource('dynamodb', region_name=REGION)

def get_iam_arn_from_identity(user_identity, account_id):
    """userIdentity 정보를 기반으로 IAM ARN을 추출하거나 구성"""

    arn = user_identity.get('arn')
    if arn:
        return arn

    user_type = user_identity.get('type')

    if user_type == 'IAMUser':
        user_name = user_identity.get('userName', 'unknown-user')
        return f"arn:aws:iam::{account_id}:user/{user_name}"

    elif user_type == 'AssumedRole':
        session_issuer = user_identity.get('sessionContext', {}).get('sessionIssuer', {})
        role_arn = session_issuer.get('arn')

        if role_arn:
            return role_arn

        invoked_by = user_identity.get('invokedBy')
        if invoked_by:
            return f"arn:aws:sts::{account_id}:assumed-role/{invoked_by}"

    return f"arn:aws:iam::{account_id}:root"

# ===============================================
# 웹소켓 전송 및 DynamoDB 관리 함수
# ===============================================

def post_to_all_active_connections(message_data):
    """DynamoDB에서 활성 ID를 조회하여 모든 연결에 메시지를 전송"""

    dynamodb = get_dynamodb_resource()

    if not CONNECTIONS_TABLE:
        print("ERROR: CONNECTIONS_TABLE 환경 변수가 설정되지 않았습니다")
        return

    table = dynamodb.Table(CONNECTIONS_TABLE)

    try:
        api_client = get_api_gateway_client()
    except Exception as e:
        print(f"Failed to initialize API Gateway client: {e}")
        return

    try:
        print(f"Scanning table '{CONNECTIONS_TABLE}' in region '{REGION}' for active connections...")
        response = table.scan(ProjectionExpression='connectionId')
        connection_ids = [item['connectionId'] for item in response.get('Items', [])]
        print(f"Found {len(connection_ids)} connections in DB")

    except Exception as e:
        print(f"Failed to scan DynamoDB for connection IDs: {e}")
        return

    message_json = json.dumps(message_data).encode('utf-8')
    success_count = 0

    for connection_id in connection_ids:
        try:
            api_client.post_to_connection(
                ConnectionId=connection_id,
                Data=message_json
            )
            success_count += 1
        except api_client.exceptions.GoneException:
            print(f"Connection {connection_id} seems GONE. But skipping delete for safety.")
            # table.delete_item(Key={'connectionId': connection_id})
        except Exception as e:
            if '410' in str(e):
                 print(f"Connection {connection_id} seems GONE (410). But skipping delete for safety.")
                 # table.delete_item(Key={'connectionId': connection_id})
            else:
                 print(f"Failed to post message to {connection_id}: {e}")

    print(f"Message sent to {success_count} connections")

# ===============================================
# 인시던트 DB 전송 및 업데이트 함수 
# ===============================================

def send_incident_to_db(incident_data: dict, action: str) -> str:
    """
    새로운 인시던트 생성 또는 기존 인시던트 상태 업데이트를 처리합니다.
    action: 'NEW' 또는 'UPDATE'
    """
    if not INCIDENT_TABLE_NAME:
        print("ERROR: INCIDENT_TABLE_NAME 환경 변수가 설정되지 않았습니다")
        return False

    dynamodb = get_dynamodb_resource()
    table = dynamodb.Table(INCIDENT_TABLE_NAME)
    now_iso = datetime.datetime.utcnow().isoformat()[:-3] + 'Z'

    try:
        if action == 'NEW':
            incident_id = generate_incident_id()
            event_occurrence_time = incident_data.get('time', now_iso)
            item = {
                'incident_id': incident_id,
                'event_type': incident_data.get('type', 'UnknownEvent'),
                'resource': incident_data.get('arn') or incident_data.get('sg') or 'N/A',
                'severity': incident_data.get('severity', 'LOW'),
                'status': 'NEW',
                'created_at': event_occurrence_time,
                'updated_at': now_iso,
                'details': json.dumps(incident_data, ensure_ascii=False)
            }
            table.put_item(Item=item)
            print(f"Incident NEW recorded: {incident_id}")
            return incident_id

        elif action == 'UPDATE':
            incident_id = incident_data.get('incident_id')
            if not incident_id or incident_id.startswith('sg-'):
                print("Cannot update incident: incident_id is missing")
                return ""

            table.update_item(
                Key={'incident_id': incident_id},
                UpdateExpression="set #s = :status, updated_at = :updated_at",
                ExpressionAttributeNames={'#s': 'status'},
                ExpressionAttributeValues={
                    ':status': incident_data.get('status', 'PROCESSING').upper(), # 💡 [수정]: 상태 대문자화
                    ':updated_at': now_iso
                }
            )
            print(f"Incident UPDATE recorded: {incident_id} -> {incident_data.get('status')}")
            return incident_id

        else:
            print(f"Unknown incident action: {action}")
            return ""

    except Exception as e:
        print(f"Failed to handle incident DB operation ({action}): {e}")
        return ""

# ===============================================
# 보안 그룹 상세 정보 조회 함수
# ===============================================

def get_security_group_details(group_id):
    """보안 그룹 ID로 상세 정보(설명, 태그)를 조회"""
    try:
        ec2_client = get_ec2_client()
        response = ec2_client.describe_security_groups(GroupIds=[group_id])
        if response['SecurityGroups']:
            return response['SecurityGroups'][0]
    except Exception as e:
        print(f"Error fetching SG details for {group_id}: {e}")
    return {}

# ===============================================
# 최근 열린 보안 그룹 기록 및 확인 함수 (상관관계용)
# ===============================================

def record_recent_open_sg(group_id, ttl_minutes=5):
    """보안그룹이 공개로 변경되었을 때 DynamoDB에 기록 (5분 TTL)"""
    try:
        dynamodb = get_dynamodb_resource()
        table = dynamodb.Table('RecentOpenSGs')
        expire_time = int((datetime.datetime.utcnow() + datetime.timedelta(minutes=ttl_minutes)).timestamp())

        table.put_item(Item={
            'groupId': group_id,
            'openedAt': datetime.datetime.utcnow().isoformat(),
            'expireAt': expire_time
        })
        print(f"Recorded open SG {group_id} with TTL {ttl_minutes}m")
    except Exception as e:
        print(f"Failed to record open SG: {e}")


def check_recent_open_sg(group_id):
    """해당 SG가 최근에 공개된 적 있는지 확인"""
    try:
        dynamodb = get_dynamodb_resource()
        table = dynamodb.Table('RecentOpenSGs')
        response = table.get_item(Key={'groupId': group_id})
        return 'Item' in response
    except Exception as e:
        print(f"Failed to check open SG record: {e}")
        return False

REMEDIATION_QUEUE_URL = os.environ.get('REMEDIATION_QUEUE_URL', 'https://sqs.us-east-1.amazonaws.com/021417007719/SecurityRemediationQueue')
SQS_CLIENT = boto3.client('sqs', region_name=REGION)

def send_remediation_request_to_sqs(group_id, rules_to_revoke, incident_id):
    """
    위험 규칙 데이터를 SQS 큐에 메시지로 전송하여 Remediation Processor를 트리거합니다.
    """
    if not REMEDIATION_QUEUE_URL:
        print("ERROR: REMEDIATION_QUEUE_URL 환경 변수가 설정되지 않았습니다.")
        return False
        
    try:
        payload = {
            'groupId': group_id,
            'remediationRules': rules_to_revoke,
            'incidentId': incident_id 
        }

        response = SQS_CLIENT.send_message(
            QueueUrl=REMEDIATION_QUEUE_URL,
            MessageBody=json.dumps(payload),
            MessageGroupId='RemediationRequest' 
        )
        
        if response.get('MessageId'):
            print(f"Successfully sent remediation request to SQS: {response['MessageId']}")
            return True
        else:
            print("Failed to send remediation request to SQS.")
            return False

    except Exception as e:
        print(f"Error sending SQS message: {e}")
        return False    

# ===============================================
# 메인 분석 함수 
# ===============================================

def is_high_risk_change(event_detail):
    """CloudTrail 이벤트 상세 내용을 분석하여 고위험 시나리오를 감지, 개별 알림 객체의 리스트를 반환"""

    group_id = event_detail.get('requestParameters', {}).get('groupId')
    ip_permissions_raw = event_detail.get('requestParameters', {}).get('ipPermissions', {})

    if isinstance(ip_permissions_raw, dict) and 'items' in ip_permissions_raw:
        ip_permissions = ip_permissions_raw.get('items', [])
    elif isinstance(ip_permissions_raw, list):
        ip_permissions = ip_permissions_raw
    else:
        ip_permissions = []

    if not group_id:
        return [], "GroupID not found in event"

    remediation_rules_to_revoke = []

    sg_details = get_security_group_details(group_id)
    description = sg_details.get('Description', '').lower()
    tags = sg_details.get('Tags', [])
    user_identity = event_detail.get('userIdentity', {})

    account_id = event_detail.get('recipientAccountId')
    region_name = event_detail.get('awsRegion')

    iam_arn_friendly = get_iam_arn_from_identity(user_identity, account_id)
    
    event_source_raw = event_detail.get('eventSource', 'Unknown')
    event_source_friendly = normalize_source(event_source_raw)
    event_name = event_detail.get('eventName', 'Unknown')
    
    # 모든 알림이 공유할 기본 정보 
    base_alert_info = {
        'time': event_detail.get('eventTime'),
        'source': event_source_friendly,
        'type': event_detail.get('eventName'),
        'sg': group_id,
        'arn': iam_arn_friendly,
        'resource': group_id,
        'account': account_id,
        'region': region_name,
        'alertType': 'ALERT'
    }

    all_violations = []
    discrete_alerts = []

    # 위반 플래그
    prod_policy_violated = False 
    high_risk_port_open = False
    is_suspicious_keyword = False
    is_new_sg_open = event_name == 'CreateSecurityGroup'

    for perm in ip_permissions:
        from_port = perm.get('fromPort')
        to_port = perm.get('toPort')
        protocol = perm.get('ipProtocol', 'any')

        ip_ranges_raw = perm.get('ipRanges', {})
        ip_ranges_list = ip_ranges_raw.get('items', []) if isinstance(ip_ranges_raw, dict) else ip_ranges_raw

        # 포트 범위 설정
        if from_port is None and to_port is None:
            current_ports = set()
        elif from_port is None or to_port is None:
            continue
        else:
            current_ports = set(range(from_port, to_port + 1))

        for ip_range_item in ip_ranges_list:
            cidr_ip = ip_range_item.get('cidrIp', '')

            # 0.0.0.0/0 (전체 공개) 감지
            if cidr_ip == '0.0.0.0/0': 
                
                # 시나리오 : 태그 정책 위반 (예: prod 환경 공개 금지)
                for tag in tags:
                    if tag.get('Key', '').lower() == 'environment' and tag.get('Value', '').lower() == 'prod':
                        prod_policy_violated = True
                        all_violations.append(f"CRITICAL: 정책 위반 - PROD 환경 공개")
                
                is_ssh_22_open = 22 in current_ports

                # 시나리오 : SSH(22) 포트가 0.0.0.0/0으로 열림
                if is_ssh_22_open:
                    high_risk_port_open = True
                    if event_name == 'AuthorizeSecurityGroupIngress':
                         # 기존 규칙 수정으로 22포트 공개됨
                         violation_msg = f"CRITICAL_22_OPEN: 기존 SG 수정으로 SSH(22) 전체 공개"
                         
                    elif event_name == 'CreateSecurityGroup':
                         # 신규 SG 생성 시 기본 SSH 오픈
                         violation_msg = f"CRITICAL_22_OPEN: 신규 SG 생성 시 SSH(22) 전체 공개"
                    else:
                         violation_msg = f"CRITICAL_22_OPEN: SSH(22) 전체 공개 ({event_name})"
                         
                    all_violations.append(violation_msg)        
                
                # 시나리오 : 고위험 포트(3389, 3306, 5432 등) 공개
                is_high_risk_combination = False
                for port in HIGH_RISK_PORTS:
                    if port != 22 and port in current_ports:
                        high_risk_port_open = True
                        all_violations.append(f"HIGH_RISK_PORT: 고위험 포트({port}) 전체 공개")
                        is_high_risk_combination = True

                # 시나리오 : SG 설명에 ‘test’·‘temp’·‘open’ 포함 + 공개 IP
                if any(keyword in description for keyword in SUSPICIOUS_KEYWORDS):
                    is_suspicious_keyword = True
                    all_violations.append(
                        f"WARN_SUSPICIOUS_DESC: 의심 키워드 포함 + 전체 공개 IP"
                    )

                # CRITICAL (PROD 위반) 또는 High Risk Port가 열린 경우, Revoke 리스트에 추가
                if prod_policy_violated or high_risk_port_open:
                    revocation_rule = {
                        'IpProtocol': protocol,
                        'FromPort': from_port,
                        'ToPort': to_port,
                        'CidrIp': cidr_ip
                    }
                    if revocation_rule not in remediation_rules_to_revoke:
                         remediation_rules_to_revoke.append(revocation_rule)

            # 시나리오 : 22포트 제한 정상 패턴 비교용 (INFO 레벨)
            elif cidr_ip != '0.0.0.0/0' and '/' in cidr_ip:
                if 22 in current_ports:
                    normal_alert = base_alert_info.copy()
                    normal_alert['severity'] = 'INFO'
                    normal_alert['type'] = "22포트 제한 정상 패턴 비교용"
                    normal_alert['rulesViolated'] = [f"INFO: SSH(22) {cidr_ip}로 제한적 오픈"]
                    discrete_alerts.append(normal_alert)


    # --- 위반 플래그 기반 개별 알림 객체 생성 ---
    
    # 알림 : 태그 정책 위반
    if prod_policy_violated:
        prod_alert = base_alert_info.copy()
        prod_alert['severity'] = 'CRITICAL'
        prod_alert['type'] = "태그 정책 위반 (PROD 공개 금지)"
        prod_alert['rulesViolated'] = [r for r in all_violations if '정책 위반' in r]
        discrete_alerts.append(prod_alert)

    # 알림 : 포트 공개/위험/설명
    if high_risk_port_open:

        is_ssh_critical = any('CRITICAL_22_OPEN' in r for r in all_violations)
        is_suspicious_warn = any('WARN_SUSPICIOUS_DESC' in r for r in all_violations)
        
        port_alert = base_alert_info.copy()
        port_alert['rulesViolated'] = [r for r in all_violations if 'CRITICAL_22_OPEN' in r or 'HIGH_RISK_PORT' in r or 'WARN_SUSPICIOUS_DESC' in r]
        
        # severity와 type 결정
        if is_ssh_critical:
            port_alert['severity'] = 'CRITICAL'

            if is_new_sg_open:
                # 신규 SG 생성 시 기본 SSH 오픈
                port_alert['type'] = "신규 SG 생성 시 기본 SSH 오픈"
            else:
                # 기존 규칙 수정으로 22포트 공개됨
                port_alert['type'] = "기존 규칙 수정으로 22 포트 공개"
                
            if is_suspicious_warn:
                 # 22번 포트 복합 감지 시 타입 수정
                 port_alert['type'] = "복합 감지: " + port_alert['type'] + " + SG 설명 의심 키워드 포함"

        else: # 22번 포트가 아니면서 고위험 포트가 열린 경우
            port_alert['severity'] = 'HIGH'
            high_risk_port_violations = [r.split(' ')[2] for r in all_violations if 'HIGH_RISK_PORT' in r]
            
            if high_risk_port_violations:
                port_list = ", ".join([p.split('(')[1].split(')')[0] for p in high_risk_port_violations])
                port_alert['type'] = f"고위험 포트 {port_list} 공개"
            else:
                port_alert['type'] = "고위험 포트 공개 (22번 제외)"

            if is_suspicious_warn:
                port_alert['type'] = "복합 감지: " + port_alert['type'] + " + SG 설명 의심 키워드 포함"
            
        # PROD SG 알림(CRITICAL)이 이미 생성된 경우 중복을 피하기 위해, severity가 CRITICAL이 아닌 경우만 추가
        if not prod_policy_violated or port_alert['severity'] != 'CRITICAL':
            discrete_alerts.append(port_alert)
            

    # 중복 제거 (같은 Type의 알림이 여러 규칙에서 생성되는 것을 방지)
    seen_types = set()
    unique_alerts = []
    for alert in discrete_alerts:
        alert_type = alert.get('type')
        if alert_type not in seen_types:
            unique_alerts.append(alert)
            seen_types.add(alert_type)

    is_remediation_triggered = False
    incident_id = None

    if remediation_rules_to_revoke:
        group_id = event_detail.get('requestParameters', {}).get('groupId')
        if unique_alerts:
            first_alert = unique_alerts[0]
            incident_id = send_incident_to_db(first_alert, 'NEW')

        print(f"Auto-Remediation: {len(remediation_rules_to_revoke)} rules detected. Sending request to SQS.")

        is_remediation_triggered = send_remediation_request_to_sqs(group_id, remediation_rules_to_revoke, incident_id)
        
        if is_remediation_triggered and incident_id:
             for alert in unique_alerts:
                 if 'CRITICAL' in alert.get('severity', '') or 'HIGH' in alert.get('severity', ''):
                     alert['message'] = "위험 규칙이 자동 조치(제거) 대기 중입니다."
                     alert['incident_id'] = incident_id

    if unique_alerts:
        print(f"ALERT: {len(unique_alerts)} discrete alerts created")
        return unique_alerts, "하나 이상의 위험 변경이 감지되었습니다"

    return [], "위험 변경이 감지되지 않았습니다"

# ===============================================
# 메인 핸들러 함수
# ===============================================

def lambda_handler(event, context):
    """메인 핸들러 함수: 이벤트 수신 후 위험 분석 및 웹소켓 전송을 담당"""

    print(f"Received event: {json.dumps(event)}")

    if event.get('source') == 'aws.events' and event.get('detail-type') == 'Scheduled Event':
        print("⚙️ Scheduled check skipped")
        return {
            'statusCode': 200,
            'body': json.dumps({'message': 'Scheduled check skipped'})
        }

    event_detail = event.get('detail', {})
    event_name = event_detail.get('eventName', '')

    alert_datas = []
    message = []

    if event_name == 'RevokeSecurityGroupIngress': 
        group_id = event_detail.get('requestParameters', {}).get('groupId', 'N/A')

        cleared_alert = {
            'time': event_detail.get('eventTime'),
            'source': normalize_source(event_detail.get('eventSource')),
            'type': '규칙 해제 감지',
            'severity': 'INFO',
            'sg': group_id,
            'alertType': 'CLEARED',
            'message': f"SG {group_id}에서 규칙이 해제되었습니다."
        }
        post_to_all_active_connections(cleared_alert)
        return {'statusCode': 200, 'body': json.dumps({'message': 'Revoke event handled'})}

    if event_name in ['ExternalAccessDetected', 'AcceptConnection', 'RemoteLoginAttempt']:
        group_id = (event_detail.get('groupId') or event_detail.get('securityGroupId') or event_detail.get('resourceId'))
        src_ip = event_detail.get('sourceIp') or event_detail.get('remoteIp')

        if group_id and check_recent_open_sg(group_id):
            alert_data = {
                'time': event_detail.get('eventTime'),
                'source': 'CloudTrail',
                'type': '22포트 오픈 직후 외부 접속 로그 감지',
                'severity': 'CRITICAL',
                'sg': group_id,
                'ip': src_ip,
                'alertType': 'ALERT',
                'message': f"SG {group_id} 공개 직후 외부 IP {src_ip}의 접근 감지 (상관관계 확인)"
            }
            post_to_all_active_connections(alert_data)
            print("External access detected after SG open")

            # send_incident_to_db(alert_data, 'NEW')
        else:
            print("INFO: SG가 최근에 오픈되지 않았거나 GroupID 누락")
        
        # 이 이벤트는 독립적으로 처리하고 종료
        return {'statusCode': 200, 'body': json.dumps({'message': 'External access processed'})}


    # 권한 부여 및 수정 이벤트 처리
    if event_name in ['AuthorizeSecurityGroupIngress', 'ModifySecurityGroupRules']:
        alert_datas, message = is_high_risk_change(event_detail)
        
        # SSH(22)가 0.0.0.0/0으로 열린 경우 기록
        if alert_datas:
             for alert in alert_datas:
                 if 'SSH' in alert['type'] and ('2.' in alert['type'] or '3.' in alert['type']):
                     group_id = alert['sg']
                     record_recent_open_sg(group_id)
                     break
        
        if alert_datas:
            print(f"Alert triggered: {message}")
        else:
            print("위험 변경이 감지되지 않았습니다")
    else:
        print(f"Ignored event: {event_name}")
        return {'statusCode': 200, 'body': json.dumps({'message': 'Ignored event'})}

    # 22포트 오픈 직후 외부 접속 로그 감지
        if event_name in ['ExternalAccessDetected', 'AcceptConnection', 'RemoteLoginAttempt']:
            group_id = (event_detail.get('groupId') or event_detail.get('securityGroupId') or event_detail.get('resourceId'))
            src_ip = event_detail.get('sourceIp') or event_detail.get('remoteIp')

            if group_id and check_recent_open_sg(group_id):
                alert_data = {
                    'time': event_detail.get('eventTime'),
                    'source': 'CloudTrail',
                    'type': '22포트 오픈 직후 외부 접속 로그 감지',
                    'severity': 'CRITICAL',
                    'sg': group_id,
                    'ip': src_ip,
                    'alertType': 'ALERT',
                    'message': f"SG {group_id} 공개 직후 외부 IP {src_ip}의 접근 감지"
                }
                post_to_all_active_connections(alert_data)
                print("External access detected after SG open")
            else:
                print("INFO: SG가 최근에 오픈되지 않았거나 GroupID 누락")
            return {'statusCode': 200, 'body': json.dumps({'message': 'External access processed'})}

    if alert_datas:
        for alert in alert_datas:
            group_id = alert['sg']
            if check_recent_open_sg(group_id):
                no_revoke_alert = {
                    'time': datetime.datetime.utcnow().isoformat(),
                    'source': 'CloudTrail',
                    'type': '보안그룹 규칙이 열렸으나 닫히지 않음',
                    'severity': 'WARNING',
                    'sg': group_id,
                    'alertType': 'ALERT',
                    'message': f"SG {group_id} 규칙이 열렸지만 Revoke 로그 없음, 지속 위험 상태"
                }
                alert_datas.append(no_revoke_alert)

        for alert_data in alert_datas:
            alert_type = 'ALERT'

            # 닫힘(Revoke) 로그 발생 시 상태 Clear 처리
            if event_name == 'RevokeSecurityGroupIngress':
                alert_type = 'CLEARED'
                alert_data['severity'] = 'INFO'

                preliminary_type = alert_data.get('type', '')
                
                # 한국어 Type 문자열 정리 및 해제/닫힘 반영
                if '태그 정책 위반' in preliminary_type:
                    final_type_string = preliminary_type.replace('태그 정책 위반', '정책 위반 해제')
                elif '신규 SG 생성 시' in preliminary_type:
                    final_type_string = preliminary_type.replace('신규 SG 생성 시 SSH(22) 전체 공개', '신규 SG 생성 시 SSH 공개 규칙 해제')
                elif '기존 규칙 수정으로' in preliminary_type:
                    final_type_string = preliminary_type.replace('기존 규칙 수정으로 22 포트 공개', '기존 규칙 수정으로 22 포트 공개 해제')
                elif '고위험 포트' in preliminary_type:
                    final_type_string = preliminary_type.replace(' 공개', ' 해제')
                elif '22포트 제한적' in preliminary_type:
                    final_type_string = preliminary_type
                else:
                    final_type_string = f"규칙 성공적 해제"

                # 복합 감지 문자열도 정리
                final_type_string = final_type_string.replace('복합 감지: ', '')
                final_type_string = final_type_string.replace(' + SG 설명 의심 키워드 포함', '')
                
                alert_data['type'] = final_type_string
                print(final_type_string)

            else:
                # 일반적인 위험 행위 (Authorize, Create, Modify)
                print(f"ALERT DETECTED: {alert_data.get('type')} (SEVERITY: {alert_data.get('severity')})")

            # 최종 알림 유형을 데이터에 추가 (대시보드 처리용)
            alert_data['alertType'] = alert_type

            post_to_all_active_connections(alert_data)

    else:
        print(f"INFO: {message}")

    return {
        'statusCode': 200,
        'body': json.dumps({'message': 'Processing complete'})
    }
