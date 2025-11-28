import os
import json
import time
import re
import boto3
import random   # ✅ Incident ID 생성용
from botocore.exceptions import ClientError

# ===== ENV =====
WS_ENDPOINT = os.environ.get("WS_ENDPOINT")  # https://.../prod/  (※ https 형식)
CONNECTIONS_TABLE = os.environ.get("CONNECTIONS_TABLE", "WebSocketConnections")
STATE_TABLE = os.environ.get("STATE_TABLE", "security-alerts-state-v2")
ACCOUNT_ID_OVERRIDE = os.environ.get("ACCOUNT_ID_OVERRIDE")

WINDOW_SECONDS = int(os.environ.get("WINDOW_SECONDS", "300") or "300")  # 5분
SEVERITY_ON_ALERT = os.environ.get("SEVERITY_ON_ALERT", "HIGH").upper()  # LOW|MEDIUM|HIGH|CRITICAL

USUAL_REGIONS = set([r.strip() for r in os.environ.get("USUAL_REGIONS", "").split(",") if r.strip()])
LEARNING_MODE = os.environ.get("LEARNING_MODE", "true").lower() in ("1", "true", "yes")

# 🔹 Incident 히스토리용 테이블
INCIDENT_TABLE = os.environ.get("INCIDENT_TABLE", "Incident")

# ===== AWS clients =====
sts_client = boto3.client("sts")


def ddb_resource():
    # WS endpoint의 리전과 맞춰 사용
    region = os.environ.get("AWS_REGION") or "us-east-1"
    try:
        region = WS_ENDPOINT.rstrip("/").split(".execute-api.", 1)[-1].split(".amazonaws.com", 1)[0] or region
    except Exception:
        pass
    return boto3.resource("dynamodb", region_name=region)


def api_ws():
    endpoint_url = WS_ENDPOINT.rstrip("/")
    region = os.environ.get("AWS_REGION") or "us-east-1"
    try:
        region = endpoint_url.split(".execute-api.", 1)[-1].split(".amazonaws.com", 1)[0] or region
    except Exception:
        pass
    return boto3.client("apigatewaymanagementapi", endpoint_url=endpoint_url, region_name=region)


# ===== Helpers =====
def _ret(obj):
    print(json.dumps(obj, ensure_ascii=False))
    return obj


def now_iso():
    """UTC ISO8601 문자열 (Z 포함)"""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


_ARN_ACCT_RE = re.compile(r"arn:aws:(?:iam|sts)::(\d{12}):")


def extract_account_id(event: dict, principal_arn: str = "") -> str:
    if ACCOUNT_ID_OVERRIDE:
        return ACCOUNT_ID_OVERRIDE
    acct = event.get("account") or ((event.get("detail") or {}).get("userIdentity") or {}).get("accountId")
    if acct:
        return acct
    m = _ARN_ACCT_RE.search(principal_arn or "")
    if m:
        return m.group(1)
    try:
        return sts_client.get_caller_identity().get("Account")
    except Exception:
        return ""


def extract_region(event: dict) -> str:
    return event.get("region") or (event.get("detail") or {}).get("awsRegion") or ""


# ===== NEW: source 통일 함수 =====
def normalize_source(source: str) -> str:
    if not source:
        return "Unknown"
    s = source.lower().strip()
    # 로그인/STS 계열
    if "signin" in s or "sts" in s:
        return "AWS Sign-In/STS"
    # CloudTrail
    if "cloudtrail" in s:
        return "CloudTrail"
    # CloudWatch
    if "cloudwatch" in s:
        return "CloudWatch"
    # S3
    if "s3" in s:
        return "S3"
    # EC2
    if "ec2" in s:
        return "EC2"

    # 기타 서비스: "aws.xxx" or "xxx.amazonaws.com" 형태를 사람이 읽기 쉽게 변환
    # 예: "lambda.amazonaws.com" → "Lambda"
    if s.endswith(".amazonaws.com"):
        svc = s.split(".")[0]  # lambda.amazonaws.com → lambda
        return svc.capitalize()

    # 기본적으로 원본 값 반환 (최소 변경)
    return source


def broadcast_to_ws(payload: dict):
    # WebSocket 연결 전체에 브로드캐스트
    if not WS_ENDPOINT or not CONNECTIONS_TABLE:
        print("WS disabled (missing env)")
        return

    api = api_ws()
    table = ddb_resource().Table(CONNECTIONS_TABLE)
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
            print("scan connections fail:", e)
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
                    except Exception:
                        pass

        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break

    print(f"WS broadcast: ok={ok}, gone={gone}, err={err}")


# ===== Incident 히스토리 유틸 =====
def incident_table():
    if not INCIDENT_TABLE:
        return None
    return ddb_resource().Table(INCIDENT_TABLE)


def generate_incident_id(prefix: str = "inc") -> str:
    """
    예: inc-20251118-143000-123
    """
    ts = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    rand = random.randint(0, 999)
    return f"{prefix}-{ts}-{rand:03d}"


def put_incident_record(event_type: str,
                        resource: str,
                        severity: str,
                        status: str = "NEW",
                        created_at: str | None = None):
    """
    Incident 테이블에 1건 저장.
    최종 히스토리 JSON 구조:
    {
      "incident_id": "...",
      "event_type": "...",
      "resource": "...",
      "severity": "LOW|MED|HIGH|CRITICAL",
      "status": "NEW|PROCESSING|MITIGATED|CLOSED",
      "created_at": "...",
      "updated_at": "..."
    }
    """

    print(f"[Incident] called: table={INCIDENT_TABLE}, event_type={event_type}, resource={resource}, severity={severity}, status={status}, created_at={created_at}")

    tbl = incident_table()
    if not tbl:
        print("❌ INCIDENT_TABLE not configured; skip incident logging")
        return None

    created = created_at or now_iso()
    iid = generate_incident_id()

    sev = (severity or "LOW").upper()
    st = (status or "NEW").upper()

    item = {
        "incident_id": iid,
        "event_type": event_type,
        "resource": resource or "",
        "severity": sev,
        "status": st,
        "created_at": created,
        "updated_at": created,
    }
    try:
        tbl.put_item(Item=item)
        print("✅ Incident stored:", json.dumps(item, ensure_ascii=False))
        return item
    except Exception as e:
        print("incident put fail:", e)
        return None


# ===== Baseline helpers =====
def _principal(event: dict) -> str:
    ui = (event.get("detail") or {}).get("userIdentity") or {}
    return ui.get("arn") or ui.get("principalId") or "unknown"


def _baseline_key(principal: str) -> str:
    return f"baseline_regions::{principal}"


def read_baseline_regions(principal: str) -> set:
    table = ddb_resource().Table(STATE_TABLE)
    try:
        r = table.get_item(Key={"id": _baseline_key(principal)})
        raw = (r.get("Item") or {}).get("regions")  # JSON string
        if not raw:
            return set()
        return set(json.loads(raw))
    except Exception:
        return set()


def write_baseline_regions(principal: str, regions: set):
    table = ddb_resource().Table(STATE_TABLE)
    try:
        table.put_item(
            Item={
                "id": _baseline_key(principal),
                "regions": json.dumps(sorted(list(regions))),
                "updatedAt": int(time.time()),
                "expiresAt": int(time.time()) + 60 * 60 * 24 * 90  # 90일 유지
            }
        )
    except Exception as e:
        print("write baseline fail:", e)


# ===== Unusual Region Detector =====
IMPORTANT_SERVICES = {
    "ec2.amazonaws.com", "s3.amazonaws.com", "iam.amazonaws.com",
    "lambda.amazonaws.com", "rds.amazonaws.com", "eks.amazonaws.com"
}
IMPORTANT_EVENTS = {
    "RunInstances", "StartInstances", "StopInstances", "TerminateInstances",
    "CreateBucket", "PutBucketAcl", "PutBucketPolicy", "DeleteBucket",
    "CreateAccessKey", "DeleteAccessKey",
    "AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy",
    "CreateFunction20150331", "UpdateFunctionConfiguration20150331", "DeleteFunction20150331",
    "CreateDBInstance", "ModifyDBInstance", "DeleteDBInstance"
}


def handle_unusual_region(event):
    detail = event.get("detail") or {}
    event_source = detail.get("eventSource")
    event_name = detail.get("eventName")
    if event_source not in IMPORTANT_SERVICES:
        return _ret({"status": "skip_service"})
    if event_name not in IMPORTANT_EVENTS:
        return _ret({"status": "skip_event"})

    principal = _principal(event)
    region = extract_region(event)
    account = extract_account_id(event, principal)

    if not region:
        return _ret({"status": "skip_no_region"})

    # === 추가: 사용자 ARN을 sg / arn 필드로 보강 ===
    user_arn = principal or f"arn:aws:iam::{account}:user/unknown"  # 실행 주체 ARN
    sg_hint = user_arn.split(":")[-1] if ":" in user_arn else user_arn  # 대시보드 표준 필드 맞춤

    # NEW: 사람이 읽기 좋은 source 명으로 정규화
    src_human = normalize_source(event_source or event.get("source", ""))

    # baseline 읽기 + 시드 합치기
    baseline = read_baseline_regions(principal)
    seeded = set(baseline) | USUAL_REGIONS

    # 이벤트 시각 (Incident created_at 에 사용할 값)
    when_iso = detail.get("eventTime") or event.get("time") or now_iso()

    if LEARNING_MODE:
        # 학습 모드: 새 리전 발견 시 baseline에 추가 + LOW 알림
        if region not in seeded:
            baseline.add(region)
            write_baseline_regions(principal, baseline)
            payload = {
                "time": int(time.time() * 1000),
                "source": src_human,
                "type": "LearnBaselineRegion",
                "resource": event_name,
                "sg": sg_hint,
                "arn": user_arn,
                "account": account,
                "region": region,
                "severity": "LOW"
            }

            # 🔹 Incident 히스토리 기록 (LOW 알림도 히스토리에 남김)
            incident = put_incident_record(
                event_type=payload["type"],
                resource=user_arn,
                severity=payload["severity"],
                status="NEW",
                created_at=when_iso
            )
            if incident:
                payload["incident_id"] = incident["incident_id"]

            broadcast_to_ws(payload)
            return _ret({"status": "learned", "principal": principal, "region": region})
        return _ret({"status": "learning_seeded", "principal": principal, "region": region})

    # 운영 모드: baseline/시드에 없는 리전이면 경보
    if region not in seeded:
        payload = {
            "time": int(time.time() * 1000),
            "source": src_human,
            "type": "평소 사용하지 않는 리전에서 주요 리소스 접근",
            "resource": event_name,
            "sg": sg_hint,
            "arn": user_arn,
            "account": account,
            "region": region,
            "severity": SEVERITY_ON_ALERT
        }

        # 🔹 디버깅 로그
        print(f"[UnusualRegion] going to record incident for principal={principal}, region={region}")

        # 🔹 Incident 히스토리 기록
        incident = put_incident_record(
            event_type=payload["type"],
            resource=user_arn,
            severity=payload["severity"],
            status="NEW",
            created_at=when_iso
        )
        if incident:
            payload["incident_id"] = incident["incident_id"]
            print(f"[UnusualRegion] incident_id attached: {incident['incident_id']}")
        else:
            print("[UnusualRegion] incident is None (put failed or skipped)")

        broadcast_to_ws(payload)
        return _ret({"status": "alert_sent", "principal": principal, "region": region})

    return _ret({"status": "inside_baseline", "principal": principal, "region": region})


# ===== Lambda entry =====
def lambda_handler(event, context):
    try:
        if event.get("detail-type") == "AWS API Call via CloudTrail":
            return handle_unusual_region(event)
        return _ret({"status": "noop"})
    except Exception as e:
        print("handler error:", e)
        raise
