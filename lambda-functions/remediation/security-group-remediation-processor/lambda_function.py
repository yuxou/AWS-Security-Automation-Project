import json
import os
import boto3
import time
import datetime
from botocore.exceptions import ClientError
import uuid

# 환경 변수 로드
REMEDIATION_WS_ENDPOINT = os.environ.get('REMEDIATION_WS_ENDPOINT')
REGION_WS = os.environ.get('REGION_WS', 'us-east-1')
REGION = os.environ.get('AWS_REGION', 'us-east-1')
REMEDIATION_CONNECTIONS_TABLE = os.environ.get('REMEDIATION_CONNECTIONS_TABLE', 'RemediationWebSocketConnections')
INCIDENT_TABLE_NAME = os.environ.get('INCIDENT_TABLE_NAME', 'Incident') 
DYNAMODB_CLIENT = boto3.resource('dynamodb', region_name=REGION)

# ===============================================
# 유틸리티 및 클라이언트 함수
# ===============================================

def get_ec2_client(region=REGION):
    """EC2 클라이언트를 반환"""
    return boto3.client('ec2', region_name=region)

def get_api_gateway_client(endpoint, region=REGION_WS):
    """지정된 웹소켓 엔드포인트에 대한 API Gateway Management 클라이언트를 반환"""
    endpoint_url = f"https://{endpoint.rstrip('/')}" if endpoint and not endpoint.startswith('http') else endpoint

    return boto3.client(
        'apigatewaymanagementapi',
        endpoint_url=endpoint_url,
        region_name=region
    )
# ===============================================
# 인시던트 DB 상태 업데이트 함수
# ===============================================

def update_incident_status_in_db(incident_id: str, new_status: str) -> bool:
    """
    Incident DB에서 특정 인시던트의 상태를 업데이트합니다.
    """
    if not INCIDENT_TABLE_NAME:
        print("ERROR: INCIDENT_TABLE_NAME 환경 변수가 설정되지 않았습니다")
        return False
    
    if not incident_id:
        print("ERROR: incident_id가 누락되어 상태를 업데이트할 수 없습니다")
        return False

    table = DYNAMODB_CLIENT.Table(INCIDENT_TABLE_NAME)
    now_iso = datetime.datetime.utcnow().isoformat()[:-3] + 'Z'
    
    try:
        table.update_item(
            Key={'incident_id': incident_id},
            UpdateExpression="set #s = :status, updated_at = :updated_at",
            ExpressionAttributeNames={'#s': 'status'},
            ExpressionAttributeValues={
                ':status': new_status,
                ':updated_at': now_iso
            }
        )
        print(f"Incident DB UPDATE recorded: {incident_id} -> {new_status}")
        return True

    except ClientError as e:
        error_code = e.response['Error']['Code']
        print(f"DynamoDB UpdateItem ClientError ({error_code}): {e}")
        return False
    except Exception as e:
        print(f"Unexpected ERROR updating Incident DB: {e}")
        return False

# ===============================================
# 조치 및 웹소켓 전송 함수
# ===============================================

def generate_remediation_json(group_id, status, rules_to_revoke, incident_id=None):
    action_type = "보안 그룹 규칙 제거"
    port_list = sorted(set(rule.get('FromPort') for rule in rules_to_revoke if rule.get('FromPort')))
    
    if len(port_list) == 1:
        port_str = f"{port_list[0]}"
    elif len(port_list) > 1:
        port_str = ", ".join(map(str, port_list))
    else:
        port_str = "알 수 없음"
    
    playbook_name = f"고위험 포트 {port_str} 차단"
    time_str = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + 'Z'

    return {
      "time": time_str,
      "action": action_type, 
      "target": group_id,
      "playbook": playbook_name,
      "status": status,
      "incident_id": incident_id,         
      "incident_status": "MITIGATED" if status == "SUCCEEDED" else "PROCESSING" 
    }

def post_remediation_status(json_data):
    """지정된 웹소켓 엔드포인트에 대응 상태 JSON을 전송"""
    if not REMEDIATION_WS_ENDPOINT:
        print("ERROR: REMEDIATION_WS_ENDPOINT 환경 변수가 설정되지 않았습니다.")
        return False

    table = DYNAMODB_CLIENT.Table(REMEDIATION_CONNECTIONS_TABLE)
    
    try:
        api_client = get_api_gateway_client(REMEDIATION_WS_ENDPOINT)
        message_json = json.dumps(json_data).encode('utf-8')
        
        # 1. 활성 연결 ID 목록 스캔
        response = table.scan(ProjectionExpression='connectionId')
        connection_ids = [item['connectionId'] for item in response.get('Items', [])]
        print(f"DEBUG: Found {len(connection_ids)} active connections for Remediation channel.")
        
        success_count = 0
        for connection_id in connection_ids:
            try:
                # 2. 각 연결 ID에 메시지 전송
                api_client.post_to_connection(
                    ConnectionId=connection_id,
                    Data=message_json
                )
                success_count += 1
            except api_client.exceptions.GoneException:
                # 끊어진 연결 ID 삭제
                table.delete_item(Key={'connectionId': connection_id})
            except Exception as e:
                # 410 Gone 오류 처리 (post_to_connection에서 발생 가능)
                if '410' in str(e):
                    table.delete_item(Key={'connectionId': connection_id})
                else:
                    print(f"Failed to post message to {connection_id}: {e}")
                
        print(f"DEBUG: Remediation Status Sent to WS: {json_data['status']} ({success_count} connections)")
        return True 

    except Exception as e:
        print(f"ERROR: Failed to scan DB or post status to websocket: {e}")
        return False

def revoke_security_group_ingress_rule(sg_id, rules_to_revoke, ec2_client):
    """
    보안 그룹 ID와 인바운드 규칙 목록을 받아 해당 규칙을 제거합니다.
    """
    if not rules_to_revoke:
        print(f"Revoke 요청에 규칙이 없습니다. 아무것도 제거하지 않습니다.")
        return False

    try:
        for rule in rules_to_revoke:
            if 'CidrIp' in rule and rule['CidrIp']:
                ec2_client.revoke_security_group_ingress(
                    GroupId=sg_id,
                    IpProtocol=rule.get('IpProtocol'),
                    FromPort=rule.get('FromPort'),
                    ToPort=rule.get('ToPort'),
                    CidrIp=rule['CidrIp']
                )
                print(f" -> 규칙 제거 성공: {rule.get('IpProtocol')}/{rule.get('FromPort')}-{rule.get('ToPort')} from {rule['CidrIp']}")
        
        return True # 제거 성공

    except ClientError as e:
        error_code = e.response['Error']['Code']
        print(f"CRITICAL ERROR during revoke for {sg_id}: {error_code} - {e}")
        return False
    except Exception as e:
        print(f"UNEXPECTED ERROR during revoke for {sg_id}: {e}")
        return False

# ===============================================
# 메인 핸들러 함수 (Remediation Processor)
# ===============================================

def lambda_handler(event, context):
    """
    SQS 이벤트 레코드를 받아 조치 요청 데이터를 추출하고 자동 대응을 실행
    """
    print(f"Received remediation request: {json.dumps(event)}")

    if 'Records' not in event or not event['Records']:
        print("SQS Records가 이벤트에 포함되어 있지 않습니다. 조치 중단.")
        return {'statusCode': 400, 'body': 'No SQS records'}
    
    # SQS 레코드에서 메시지 본문(Payload) 추출
    message_body_string = event['Records'][0]['body']
    
    try:
        remediation_request = json.loads(message_body_string)
    except json.JSONDecodeError as e:
        print(f"❌ ERROR: 메시지 본문 JSON 파싱 실패: {e}")
        return {'statusCode': 400, 'body': 'Invalid JSON format in message body'}

    sg_id = remediation_request.get('groupId')
    rules_to_revoke = remediation_request.get('remediationRules', [])
    incident_id = remediation_request.get('incidentId')
    
    if not sg_id or not rules_to_revoke:
        print("필수 데이터 (groupId 또는 remediationRules) 누락. 조치 중단.")
        return {'statusCode': 400, 'body': 'Missing data'}

    ec2_client = get_ec2_client()
    
    # 1. 대응 상태 알림 (TRIGGERED) 전송
    remediation_event_data_triggered = generate_remediation_json(sg_id, "TRIGGERED", rules_to_revoke, incident_id)
    post_remediation_status(remediation_event_data_triggered)

    if incident_id:
        # 인시던트 ID가 있는 경우, 상태를 PROCESSING으로 변경
        update_incident_status_in_db(incident_id, "PROCESSING")

    # 2. 규칙 제거 실행
    is_revoked = revoke_security_group_ingress_rule(sg_id, rules_to_revoke, ec2_client)
    
    # 3. 대응 상태 알림 (SUCCEEDED/FAILED) 전송
    final_status = "SUCCEEDED" if is_revoked else "FAILED"
    incident_final_status = "MITIGATED" if is_revoked else "PROCESSING"
    
    remediation_event_data_final = generate_remediation_json(sg_id, final_status, rules_to_revoke, incident_id)
    post_remediation_status(remediation_event_data_final)

    if incident_id:
        update_incident_status_in_db(incident_id, incident_final_status)

    print(f"Remediation complete. Status: {final_status}")
    
    return {
        'statusCode': 200,
        'body': json.dumps({'status': final_status, 'message': 'Remediation process executed'})
    }
