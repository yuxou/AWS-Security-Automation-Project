import os
import json
import time
import uuid
import re

import boto3
from botocore.exceptions import ClientError, BotoCoreError

# ========= 환경변수 =========
ARCHIVE_BUCKET           = os.environ.get("ARCHIVE_BUCKET")                    # S3 버킷 이름
CONNECTIONS_TABLE_ACTIONS= os.environ.get("CONNECTIONS_TABLE_ACTIONS")         # RemediationWebSocketConnections
DVWA_INSTANCE_ID         = os.environ.get("DVWA_INSTANCE_ID")                  # 격리할 DVWA 인스턴스 ID
QUARANTINE_SG_ID         = os.environ.get("QUARANTINE_SG_ID")                  # 격리용 SG
REGION                   = os.environ.get("REGION", os.environ.get("AWS_REGION", "us-east-1"))
WS_ENDPOINT_ACTIONS      = os.environ.get("WS_ENDPOINT_ACTIONS")               # https://.../prod/
STATE_TABLE              = os.environ.get("STATE_TABLE")                       # 아직은 사용 안함(추후 상태 관리용)

# ========= AWS clients =========
ec2 = boto3.client("ec2", region_name=REGION)
s3  = boto3.client("s3",  region_name=REGION)
ddb = boto3.resource("dynamodb", region_name=REGION)

# ========= 공용 유틸 =========

def _log(obj):
    """CloudWatch 로그에 JSON 한 번 찍기"""
    print(json.dumps(obj, ensure_ascii=False))


def _epoch_ms() -> int:
    return int(time.time() * 1000)


def extract_region(event: dict) -> str:
    return (
        event.get("region")
        or (event.get("detail") or {}).get("region")
        or REGION
    )


def extract_account(event: dict) -> str:
    acct = event.get("account")
    if acct:
        return acct
    detail = event.get("detail") or {}
    ui = detail.get("userIdentity") or {}
    return ui.get("accountId") or ""


def build_alarm_arn_and_short(event: dict) -> tuple[str, str]:
    """
    CloudWatch Alarm 이벤트에서 alarmArn / alarmName 을 이용해
    전체 ARN 과 '...:alarm' 까지만 자른 short ARN 둘 다 리턴
    """
    detail = event.get("detail") or {}
    alarm_name = detail.get("alarmName", "unknown")
    alarm_arn  = detail.get("alarmArn")

    if not alarm_arn:
        region  = extract_region(event)
        account = extract_account(event)
        alarm_arn = f"arn:aws:cloudwatch:{region}:{account}:alarm:{alarm_name}"

    # arn:aws:cloudwatch:us-east-1:123456789012:alarm:dvwa-scanner...
    #  → arn:aws:cloudwatch:us-east-1:123456789012:alarm
    short_arn = alarm_arn
    m = re.match(r"^(arn:aws:cloudwatch:[^:]+:\d+:alarm)", alarm_arn)
    if m:
        short_arn = m.group(1)

    return alarm_arn, short_arn


# ========= S3 아카이브 (④ 로그/이벤트 스냅샷) =========

def archive_event_to_s3(event: dict) -> dict:
    if not ARCHIVE_BUCKET:
        _log({"warn": "ARCHIVE_BUCKET not set, skip archive"})
        return {"status": "skip", "reason": "no_bucket"}

    key = f"scanner/{int(time.time())}-{uuid.uuid4().hex}.json"
    body = json.dumps(event, ensure_ascii=False, indent=2)

    try:
        s3.put_object(
            Bucket=ARCHIVE_BUCKET,
            Key=key,
            Body=body.encode("utf-8"),
        )
        _log({"archive": "ok", "bucket": ARCHIVE_BUCKET, "key": key})
        return {"status": "ok", "bucket": ARCHIVE_BUCKET, "key": key}
    except (ClientError, BotoCoreError) as e:
        _log({"archive": "error", "error": str(e)})
        return {"status": "error", "error": str(e)}


# ========= 인스턴스 격리 (②) =========

def quarantine_instance(instance_id: str, quarantine_sg_id: str) -> dict:
    if not instance_id or not quarantine_sg_id:
        msg = "instance_id or quarantine_sg_id missing"
        _log({"quarantine": "skip", "reason": msg})
        return {"status": "skip", "reason": msg}

    try:
        resp = ec2.describe_instances(InstanceIds=[instance_id])
        reservations = resp.get("Reservations", [])
        if not reservations or not reservations[0]["Instances"]:
            msg = "instance_not_found"
            _log({"quarantine": "error", "reason": msg})
            return {"status": "error", "reason": msg}

        inst = reservations[0]["Instances"][0]
        ni   = inst["NetworkInterfaces"][0]
        eni_id = ni["NetworkInterfaceId"]

        # SG 를 격리 SG 하나로 교체
        ec2.modify_network_interface_attribute(
            NetworkInterfaceId=eni_id,
            Groups=[quarantine_sg_id]
        )

        result = {
            "status": "ok",
            "instance_id": instance_id,
            "eni_id": eni_id,
            "applied_sg": quarantine_sg_id,
        }
        _log({"quarantine": result})
        return result

    except (ClientError, BotoCoreError) as e:
        _log({"quarantine": "error", "error": str(e)})
        return {"status": "error", "error": str(e)}


# ========= HTTP 차단 (① - 지금은 격리 SG로 대체) =========

def block_world_http(instance_id: str) -> dict:
    """
    지금 구조에서는 '격리 SG 하나만 적용' 자체가 이미
    외부에서의 HTTP 접근을 막는 효과를 내므로
    여기서는 별도 작업 없이 상태만 남겨줌.
    """
    result = {"status": "blocked_by_quarantine_sg", "instance_id": instance_id}
    _log({"block_world_http": result})
    return result


# ========= Actions WebSocket 브로드캐스트 =========

def post_to_ws_actions(payload: dict):
    if not WS_ENDPOINT_ACTIONS:
        _log({"ws_actions": "skip", "reason": "WS_ENDPOINT_ACTIONS not set"})
        return

    if not CONNECTIONS_TABLE_ACTIONS:
        _log({"ws_actions": "skip", "reason": "CONNECTIONS_TABLE_ACTIONS not set"})
        return

    endpoint_url = WS_ENDPOINT_ACTIONS.rstrip("/")
    region = REGION
    try:
        # https://{apiId}.execute-api.{region}.amazonaws.com/{stage}
        region = endpoint_url.split(".execute-api.", 1)[-1].split(".amazonaws.com", 1)[0] or region
    except Exception:
        pass

    api = boto3.client("apigatewaymanagementapi", endpoint_url=endpoint_url, region_name=region)
    table = ddb.Table(CONNECTIONS_TABLE_ACTIONS)
    data_bytes = json.dumps(payload).encode("utf-8")

    ok = gone = err = 0
    last_key = None

    while True:
        scan_kwargs = {"ProjectionExpression": "connectionId"}
        if last_key:
            scan_kwargs["ExclusiveStartKey"] = last_key

        try:
            resp = table.scan(**scan_kwargs)
        except Exception as e:
            _log({"ws_actions": "scan_error", "error": str(e)})
            break

        for item in resp.get("Items", []) or []:
            cid = item.get("connectionId")
            if not cid:
                continue
            try:
                api.post_to_connection(ConnectionId=cid, Data=data_bytes)
                ok += 1
            except api.exceptions.GoneException:
                gone += 1
                try:
                    table.delete_item(Key={"connectionId": cid})
                except Exception:
                    pass
            except ClientError as e:
                err += 1
                _log({"ws_actions": "send_error", "code": e.response.get("Error", {}).get("Code")})

        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break

    _log({"ws_actions": "done", "ok": ok, "gone": gone, "err": err})


# ========= 메인 핸들러 =========

def lambda_handler(event, context):
    """
    CloudWatch Alarm (스캐너 감지) → 자동대응 3단계:
      1) 이벤트 원문 S3 아카이브
      2) DVWA 인스턴스 격리 SG 로 교체
      3) (간주) HTTP 차단
      + Actions WebSocket 으로 결과 전송
    """
    _log({"received_event": event})

    # 0. 이벤트 타입 확인
    if event.get("source") != "aws.cloudwatch":
        _log({"status": "skip", "reason": "not_cloudwatch"})
        return {"status": "skip"}

    if event.get("detail-type") != "CloudWatch Alarm State Change":
        _log({"status": "skip", "reason": "not_alarm_state_change"})
        return {"status": "skip"}

    detail = event.get("detail") or {}
    new_state = (detail.get("state") or {}).get("value", "UNKNOWN")

    # ALARM 상태에서만 자동대응 수행
    if new_state != "ALARM":
        _log({"status": "skip", "reason": f"state_is_{new_state}"})
        return {"status": "skip", "state": new_state}

    # 1. S3 아카이브
    archive_info = archive_event_to_s3(event)

    # 2. 인스턴스 격리
    quarantine_info = quarantine_instance(DVWA_INSTANCE_ID, QUARANTINE_SG_ID)

    # 3. HTTP 차단 (지금은 격리 SG 로 처리)
    block_info = block_world_http(DVWA_INSTANCE_ID)

    # 4. Actions WebSocket 알림 payload 구성
    alarm_arn, short_arn = build_alarm_arn_and_short(event)
    region  = extract_region(event)
    account = extract_account(event)

    ws_payload = {
        "time": _epoch_ms(),
        "source": "AutoRemediation",
        "type": "ScannerAutoResponse",
        "resource": DVWA_INSTANCE_ID or "",
        "sg": QUARANTINE_SG_ID or "",
        "arn": short_arn,
        "account": account,
        "region": region,
        "severity": "HIGH",
        "details": {
            "archive": archive_info,
            "quarantine": quarantine_info,
            "http_block": block_info,
            "alarmArn": alarm_arn,
        },
    }

    post_to_ws_actions(ws_payload)

    result = {
        "status": "remediation_done",
        "state": new_state,
        "archive": archive_info,
        "quarantine": quarantine_info,
        "http_block": block_info,
    }
    _log(result)
    return result
