import os
import json
import time
import urllib.request
import re
import boto3
from botocore.exceptions import ClientError

# ==============================
# 환경변수
# ==============================
# 이 Lambda는 "이벤트"용 WebSocket/테이블을 사용
WS_ENDPOINT_EVENTS = os.environ.get("WS_ENDPOINT_EVENTS")  # https://{apiId}.execute-api.{region}.amazonaws.com/{stage}/
CONNECTIONS_TABLE_EVENTS = os.environ.get("CONNECTIONS_TABLE_EVENTS", "WebSocketConnections")

# 내부에서 편하게 쓰려고 공통 이름으로 매핑
WS_ENDPOINT = WS_ENDPOINT_EVENTS
CONNECTIONS_TABLE = CONNECTIONS_TABLE_EVENTS

STATE_TABLE = os.environ.get("STATE_TABLE", "security-alerts-state")  # ※ 현재 코드에선 사용 안 함
ACCOUNT_ID_OVERRIDE = os.environ.get("ACCOUNT_ID_OVERRIDE")
HTTP_TIMEOUT = 8  # 지금은 고정 값으로 사용

ddb_client = boto3.client("dynamodb")
sts_client = boto3.client("sts")

def ddb_resource():
    """
    WebSocketConnections 테이블이 위치한 리전을 WS_ENDPOINT에서 추론(없으면 기본 us-east-1).
    """
    region = os.environ.get("AWS_REGION") or "us-east-1"
    try:
        if WS_ENDPOINT:
            region = WS_ENDPOINT.rstrip("/").split(".execute-api.", 1)[-1].split(".amazonaws.com", 1)[0] or region
    except Exception:
        pass
    return boto3.resource("dynamodb", region_name=region)

# ==============================
# 공용 유틸
# ==============================
def _ret(obj: dict):
    print(json.dumps(obj, ensure_ascii=False))
    return obj

# ==============================
# 계정ID 안전 추출
# ==============================
_ARN_ACCT_RE = re.compile(r"arn:aws:(?:iam|sts)::(\d{12}):")

def extract_account_id(event: dict, payload: dict) -> str:
    if ACCOUNT_ID_OVERRIDE:
        return ACCOUNT_ID_OVERRIDE

    acct = event.get("account")
    if acct:
        return acct

    acct = (event.get("detail") or {}).get("userIdentity", {}).get("accountId")
    if acct:
        return acct

    arn = payload.get("principal") or ""
    m = _ARN_ACCT_RE.search(arn)
    if m:
        return m.group(1)

    try:
        return sts_client.get_caller_identity().get("Account")
    except Exception:
        return ""

def extract_region(event: dict) -> str:
    return (
        event.get("region")
        or (event.get("detail") or {}).get("awsRegion")
        or os.environ.get("AWS_REGION")
        or "us-east-1"
    )

# ==============================
# 대시보드 스키마 변환
# ==============================
def build_dashboard_payload(event, *, source, etype, severity="HIGH",
                            resource="", sg="", arn=""):
    now_ms = int(time.time() * 1000)

    account = (
        event.get("account")
        or (event.get("detail") or {}).get("accountId")
        or (event.get("detail") or {}).get("userIdentity", {}).get("accountId")
        or ""
    )
    region = extract_region(event)

    return {
        "time": now_ms,
        "source": source,
        "type": etype,
        "resource": resource,
        "sg": sg,
        "arn": arn,
        "account": account,
        "region": region,
        "severity": severity,
    }

# ==============================
# WebSocket 브로드캐스트 (EVENTS 채널용)
# ==============================
def post_to_ws_dashboard(formatted_event: dict):
    endpoint = WS_ENDPOINT
    if not endpoint:
        print("❌ WS_ENDPOINT_EVENTS not set; skip")
        return

    endpoint_url = endpoint.rstrip("/")

    # 기본 리전은 Lambda 리전, 가능하면 WS_ENDPOINT에서 추출
    region = os.environ.get("AWS_REGION") or "us-east-1"
    try:
        region = endpoint_url.split(".execute-api.", 1)[-1].split(".amazonaws.com", 1)[0] or region
    except Exception:
        pass

    # API Gateway Management API 클라이언트
    api = boto3.client("apigatewaymanagementapi", endpoint_url=endpoint_url, region_name=region)
    data_bytes = json.dumps(formatted_event).encode("utf-8")

    if not CONNECTIONS_TABLE:
        print("❌ CONNECTIONS_TABLE_EVENTS not set; skip")
        return

    table = ddb_resource().Table(CONNECTIONS_TABLE)
    ok = gone = err = 0
    last_key = None

    while True:
        scan_kwargs = {"ProjectionExpression": "connectionId"}
        if last_key:
            scan_kwargs["ExclusiveStartKey"] = last_key

        try:
            resp = table.scan(**scan_kwargs)
        except Exception as e:
            print(f"❌ Failed to scan connections: {e}")
            break

        for it in resp.get("Items", []) or []:
            cid = it.get("connectionId")
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
                code = e.response.get("Error", {}).get("Code")
                print("send error:", code)
                if code == "AccessDeniedException":
                    try:
                        table.delete_item(Key={"connectionId": cid})
                        print("🧹 deleted stale connection:", cid)
                    except Exception as de:
                        print("delete failed:", de)

        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break

    print(f"WS broadcast done (EVENTS): ok={ok}, gone={gone}, err={err}")

# ==============================
# CloudWatch Alarm 이벤트 처리
# ==============================
def handle_cloudwatch_alarm(event):
    if event.get("source") != "aws.cloudwatch":
        return _ret({"status": "skip"})
    if event.get("detail-type") != "CloudWatch Alarm State Change":
        return _ret({"status": "skip_non_alarm"})

    d = event.get("detail", {}) or {}
    alarm_name = d.get("alarmName", "unknown")
    new_state  = (d.get("state") or {}).get("value", "UNKNOWN")

    # ARN 보정 및 'alarm:'까지만 표시
    region  = extract_region(event) or "us-east-1"
    account = extract_account_id(event, {}) or ""
    alarm_arn = f"arn:aws:cloudwatch:{region}:{account}:alarm"

    # 대시보드 severity 규칙
    sev = "HIGH" if new_state == "ALARM" else "LOW"

    # metric 이름 추출 시도
    metric_name = ""
    try:
        metrics = (d.get("configuration") or {}).get("metrics") or []
        m0 = metrics[0].get("metricStat", {}).get("metric", {}) if metrics else {}
        metric_name = m0.get("metricName", "")
    except Exception:
        pass

    payload = build_dashboard_payload(
        event,
        source="AWS CloudWatch",
        etype="외부 취약점 스캐너 탐지 감지",
        severity=sev,
        resource=metric_name or alarm_name,
        sg="",
        arn=alarm_arn,   # alarm까지만
    )

    post_to_ws_dashboard(payload)
    return _ret({"status": "alarm_forwarded", "alarm": alarm_name, "state": new_state})

# ==============================
# (참고) CloudTrail IAM AccessKey 예시 처리기
# ==============================
def handle_access_key_created(event):
    if event.get("source") != "aws.iam":
        return _ret({"status": "skip"})
    detail = event.get("detail", {}) or {}
    if detail.get("eventName") != "CreateAccessKey":
        return _ret({"status": "skip_non_target_event"})

    ui = detail.get("userIdentity", {}) or {}
    user_arn = ui.get("arn") or ui.get("principalId") or ""

    payload = build_dashboard_payload(
        event,
        source="AWS IAM",
        etype="AccessKeyCreated",
        severity="HIGH",
        resource=user_arn,
        sg="",
        arn="",
    )

    post_to_ws_dashboard(payload)
    return _ret({"status": "alert_sent"})

# ==============================
# Lambda 핸들러
# ==============================
def lambda_handler(event, context):
    try:
        src = event.get("source")
        dt  = event.get("detail-type")
        if src == "aws.cloudwatch" and dt == "CloudWatch Alarm State Change":
            return handle_cloudwatch_alarm(event)
        if src == "aws.iam" and dt == "AWS API Call via CloudTrail":
            return handle_access_key_created(event)
        return _ret({"status": "noop"})
    except Exception as e:
        print("handler error:", e)
        raise
