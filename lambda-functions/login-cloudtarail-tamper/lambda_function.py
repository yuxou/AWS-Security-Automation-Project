import os
import json
import time
import urllib.request
import re
import boto3
import random
from datetime import datetime
from botocore.exceptions import ClientError

# ==============================
# 환경변수
# ==============================
WS_ENDPOINT           = os.environ.get("WS_ENDPOINT")  # https://{apiId}.execute-api.{region}.amazonaws.com/{stage}
STATE_TABLE           = os.environ.get("STATE_TABLE", "security-alerts-state")
CONNECTIONS_TABLE     = os.environ.get("CONNECTIONS_TABLE", "WebSocketConnections")
ACCOUNT_ID_OVERRIDE   = os.environ.get("ACCOUNT_ID_OVERRIDE")  # 있으면 이 값이 항상 표시됨
HTTP_TIMEOUT          = int(os.environ.get("HTTP_TIMEOUT", "8") or "8")
TAMPER_WINDOW_SECONDS = int(os.environ.get("TAMPER_WINDOW_SECONDS", "60") or "60")  # 로그인 직후 N초 이내 tamper

# 🔹 NEW: 리전 최근 사용 여부 판단용 (기본 7일)
REGION_WINDOW_SECONDS = int(os.environ.get("REGION_WINDOW_SECONDS", "604800") or "604800")  # 7*24*3600

# Incident 히스토리용 테이블
INCIDENT_TABLE        = os.environ.get("INCIDENT_TABLE", "Incident")

# 상태테이블 키 이름/구조를 환경변수로 제어
STATE_PK_NAME = os.environ.get("STATE_PK_NAME", "pk")  # 예: connectionId
STATE_SK_NAME = os.environ.get("STATE_SK_NAME")        # 예: sk (없으면 비움)
STATE_SK_VALUE = os.environ.get("STATE_SK_VALUE")      # 예: STATE (없으면 비움)

ddb_client = boto3.client("dynamodb")
sts_client = boto3.client("sts")


# ==============================
# 공용 유틸
# ==============================
def _to_int_safe(v):
    try:
        return int(v)
    except Exception:
        return None

def ddb_resource():
    region = os.environ.get("AWS_REGION") or "us-east-1"
    try:
        region = WS_ENDPOINT.rstrip("/").split(".execute-api.", 1)[-1].split(".amazonaws.com", 1)[0] or region
    except Exception:
        pass
    return boto3.resource("dynamodb", region_name=region)

# 상태테이블 키 오브젝트 생성
def _state_key_obj(pk_value: str):
    key = {STATE_PK_NAME: pk_value}
    if STATE_SK_NAME and STATE_SK_VALUE:
        key[STATE_SK_NAME] = STATE_SK_VALUE
    return key

def _ret(obj: dict):
    print(json.dumps(obj, ensure_ascii=False))
    return obj

def now_ms():
    return int(time.time() * 1000)

def now_iso():
    """UTC ISO8601 문자열 (Z 포함)"""
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def geoip(ip: str):
    try:
        with urllib.request.urlopen(f"https://ipinfo.io/{ip}/json", timeout=HTTP_TIMEOUT) as r:
            j = json.load(r)
        loc = j.get("loc")
        if not loc:
            return {
                "ip": ip,
                "lat": None,
                "lon": None,
                "city": j.get("city"),
                "country": j.get("country")
            }
        lat, lon = [float(x) for x in loc.split(",")]
        return {"ip": ip, "lat": lat, "lon": lon, "city": j.get("city"), "country": j.get("country")}
    except Exception as e:
        print("geoip fail:", e)
        return {"ip": ip, "lat": None, "lon": None}


# ==============================
# 계정ID/리전/SG/ARN 추출 + 보강
# ==============================
_ARN_ACCT_RE = re.compile(r"arn:aws:(?:iam|sts)::(\d{12}):")
_SG_RE = re.compile(r"\bsg-[0-9a-f]{8,}\b", re.IGNORECASE)

def extract_account_id(event: dict, payload: dict) -> str:
    if ACCOUNT_ID_OVERRIDE:
        return ACCOUNT_ID_OVERRIDE

    acct = event.get("account")
    if acct:
        return acct

    acct = (event.get("detail") or {}).get("userIdentity", {}).get("accountId")
    if acct:
        return acct

    arn = payload.get("principal") or payload.get("arn") or ""
    m = _ARN_ACCT_RE.search(arn)
    if m:
        return m.group(1)

    try:
        return sts_client.get_caller_identity().get("Account")
    except Exception:
        return ""

def extract_region(event: dict) -> str:
    return event.get("region") or (event.get("detail") or {}).get("awsRegion") or ""

# --- SG 추출 강화 ----------------------------------------------------
def extract_sg(event: dict, payload: dict) -> str:
    # 0) payload 직접 값(Composite 알림이면 여기서 받아오는 게 정석)
    for k in ("sg", "security_group", "securityGroupId", "securityGroup"):
        v = payload.get(k)
        if isinstance(v, str) and v.startswith("sg-"):
            return v

    detail = event.get("detail") or {}
    rp = (detail.get("requestParameters") or {})
    relem = (detail.get("responseElements") or {})

    def _pick_first_sg(obj):
        try:
            if isinstance(obj, dict):
                for val in obj.values():
                    r = _pick_first_sg(val)
                    if r:
                        return r
            elif isinstance(obj, list):
                for val in obj:
                    r = _pick_first_sg(val)
                    if r:
                        return r
            elif isinstance(obj, str) and obj.startswith("sg-"):
                return obj
        except Exception:
            pass
        return ""

    for v in (rp.get("groupId"), relem.get("groupId"), rp.get("securityGroupId")):
        if isinstance(v, str) and v.startswith("sg-"):
            return v

    candidates = [
        (rp.get("groupIdSet") or {}),
        (rp.get("groupSet") or {}),
        (rp.get("groups") or {}),
        (rp.get("securityGroupIds") or []),
        (rp.get("ipPermissions") or {}),
        (relem.get("groupIdSet") or {}),
        (relem.get("groupSet") or {}),
        (relem.get("groups") or {}),
        (relem.get("securityGroupIds") or []),
    ]
    for obj in candidates:
        gid = _pick_first_sg(obj)
        if gid:
            return gid

    try:
        import json as _json, re as _re
        m = _re.search(r"\bsg-[0-9a-f]{8,}\b", _json.dumps(event), _re.IGNORECASE)
        if m:
            return m.group(0)
    except Exception:
        pass
    return ""

# --- SG 조회 보강(Enrichment) ---------------------------------------
def _ec2(region_hint: str):
    region = region_hint or os.environ.get("AWS_REGION") or "us-east-1"
    return boto3.client("ec2", region_name=region)

def enrich_sg_with_lookup(event: dict, sg_now: str, region_hint: str) -> str:
    if sg_now:
        return sg_now

    detail = event.get("detail") or {}
    rp = (detail.get("requestParameters") or {})

    instance_id = rp.get("instanceId")
    eni_id = rp.get("networkInterfaceId")

    if not instance_id:
        arr = rp.get("instanceIds") or []
        if isinstance(arr, list) and arr:
            instance_id = arr[0]
    if not eni_id:
        eni = rp.get("eniId") or rp.get("networkInterface")
        if isinstance(eni, str) and eni.startswith("eni-"):
            eni_id = eni

    ec2 = _ec2(region_hint)

    try:
        if instance_id:
            r = ec2.describe_instances(InstanceIds=[instance_id])
            for res in r.get("Reservations", []):
                for inst in res.get("Instances", []):
                    sgs = inst.get("SecurityGroups") or []
                    if sgs:
                        return sgs[0].get("GroupId", "") or sg_now

        if eni_id:
            r = ec2.describe_network_interfaces(NetworkInterfaceIds=[eni_id])
            nis = r.get("NetworkInterfaces", [])
            if nis:
                groups = nis[0].get("Groups") or []
                if groups:
                    return groups[0].get("GroupId", "") or sg_now
    except Exception as e:
        print("enrich_sg lookup fail:", e)

    return sg_now


# === ARN 짧게 표기 유틸 (현재는 미사용) ===
def format_arn_for_ui(arn: str) -> str:
    if not arn or not isinstance(arn, str):
        return ""
    arn = arn.strip()
    m = re.match(r"^arn:aws:[^:]*:[^:]*:\d{12}:(.+)$", arn)
    if m:
        return ":" + m.group(1)
    m2 = re.match(r"^arn:aws:(?:iam|sts)::\d{12}:(.+)$", arn)
    if m2:
        return ":" + m2.group(1)
    if ":" in arn:
        return ":" + arn.split(":")[-1]
    return arn


# === source 정규화 ===
def normalize_source(source: str) -> str:
    """
    CloudTrail의 raw source 값(aws.signin, ec2.amazonaws.com 등)을
    대시보드에서 쓰기 좋은 이름으로 통일.
    """
    if not source:
        return "Unknown"

    s = source.lower().strip()

    # 로그인/STS
    if "signin" in s or "sts" in s:
        return "AWS Sign-In/STS"

    # CloudTrail
    if "cloudtrail" in s:
        return "CloudTrail"

    # CloudWatch
    if "cloudwatch" in s:
        return "CloudWatch"

    # S3
    if s == "aws.s3" or s.startswith("s3"):
        return "S3"

    # EC2
    if s == "aws.ec2" or "ec2" in s:
        return "EC2"

    # *.amazonaws.com → 서비스명 Capitalize
    if s.endswith(".amazonaws.com"):
        svc = s.split(".")[0]
        return svc.capitalize()

    # 기본 그대로
    return source


# ==============================
# Incident 히스토리 유틸
# ==============================
def incident_table():
    if not INCIDENT_TABLE:
        return None
    return ddb_resource().Table(INCIDENT_TABLE)

def generate_incident_id(prefix: str = "inc") -> str:
    """
    예: inc-20251117-143000-123
    """
    ts = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    rand = random.randint(0, 999)
    return f"{prefix}-{ts}-{rand:03d}"

def put_incident_record(
    event_type: str,
    resource: str,
    severity: str,
    status: str = "NEW",
    created_at=None,
    details: dict | None = None,   # 🔹 details 추가
):
    """
    Incident 테이블에 히스토리 1건 저장.
    대시보드에서 최종적으로 사용할 JSON 형태와 동일하게 저장한다.
    """
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
        "severity": sev,      # LOW | MED | HIGH | CRITICAL
        "status": st,         # NEW | PROCESSING | MITIGATED | CLOSED
        "created_at": created,
        "updated_at": created,
    }

    # 🔹 details 필드가 있으면 같이 저장
    if details:
        item["details"] = details

    try:
        tbl.put_item(Item=item)
        print("✅ Incident stored:", json.dumps(item, ensure_ascii=False))
        return item
    except Exception as e:
        print("incident put fail:", e)
        return None


# ==============================
# 대시보드 스키마 변환
# ==============================
def to_dashboard_event(event, payload) -> dict:
    """
    대시보드 호환용 'flat' JSON 전송.
    실시간 알림용이며, incident_id가 있으면 포함한다.
    """
    now = now_ms()
    account_id = extract_account_id(event, payload)
    region = extract_region(event)
    resource = payload.get("resource") or payload.get("principal") or ""

    raw_source = payload.get("source") \
        or (event.get("detail") or {}).get("eventSource") \
        or event.get("source") \
        or "AWS"
    source = normalize_source(raw_source)

    etype = payload.get("event_type") or "SecurityEvent"
    sev = (payload.get("severity") or "HIGH").upper()

    # sg / arn 계산
    sg = extract_sg(event, payload)
    sg = enrich_sg_with_lookup(event, sg, region)
    arn_raw = payload.get("arn") or payload.get("principal") or ""
    arn_for_ui = arn_raw  # 풀 ARN 그대로 전송
    incident = payload.get("incident") or {}

    meta = dict(payload)
    meta["account_id"] = account_id
    if arn_raw:
        meta["arn_original"] = arn_raw
    meta["arn"] = arn_for_ui
    meta["arn_short"] = arn_for_ui  # 호환용

    flat = {
        "kind": "event",
        "time": now,
        "source": source,
        "type": etype,
        "resource": resource,
        "sg": sg,
        "arn": arn_for_ui,
        "account": account_id,
        "region": region,
        "severity": sev,
        "meta": meta,
    }

    # Incident가 있으면 incident_id 포함
    if incident:
        flat["incident_id"] = incident.get("incident_id")

    style = (os.environ.get("DASHBOARD_PAYLOAD_STYLE") or "flat").lower()
    if style == "wrapped":
        return {"kind": "event", "event": flat}
    return flat


# ==============================
# WebSocket 브로드캐스트
# ==============================
def post_to_ws_dashboard(formatted_event: dict):
    endpoint = WS_ENDPOINT
    if not endpoint:
        print("❌ WS_ENDPOINT not set; skip")
        return

    endpoint_url = endpoint.rstrip("/")
    region = os.environ.get("AWS_REGION") or "us-east-1"
    try:
        region = endpoint_url.split(".execute-api.", 1)[-1].split(".amazonaws.com", 1)[0] or region
    except Exception:
        pass

    api = boto3.client("apigatewaymanagementapi", endpoint_url=endpoint_url, region_name=region)
    data_bytes = json.dumps(formatted_event).encode("utf-8")

    if not CONNECTIONS_TABLE:
        print("❌ CONNECTIONS_TABLE not set; skip")
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

    print(f"WS broadcast done: ok={ok}, gone={gone}, err={err}")


# ==============================
# 상태테이블(최근 로그인 기록) 유틸
# ==============================
def state_table():
    return ddb_resource().Table(STATE_TABLE)

# 🔹 NEW: principal+region 별 최근 활동 기록 유틸
def _region_activity_key(principal: str, region: str) -> str:
    return f"region#{principal}#{region}"

def get_region_last_seen(principal: str, region: str):
    tbl = state_table()
    key = _state_key_obj(_region_activity_key(principal, region))
    try:
        item = tbl.get_item(Key=key).get("Item")
    except Exception as e:
        print("region get fail:", key, e)
        return None
    if not item:
        return None
    return _to_int_safe(item.get("last_seen_ms"))

def put_region_last_seen(principal: str, region: str, when_ms: int):
    tbl = state_table()
    key = _state_key_obj(_region_activity_key(principal, region))
    ttl = int(time.time()) + 30 * 24 * 3600  # 30일 후 만료
    item = dict(key)
    item.update({
        "last_seen_ms": when_ms,
        "region": region,
        "principal": principal,
        "ttl": ttl,
    })
    try:
        tbl.put_item(Item=item)
    except Exception as e:
        print("region put fail:", key, e)

def is_region_unused_recently(principal: str, region: str, window_seconds: int) -> bool:
    """
    최근 window_seconds 이내에 사용 기록이 없으면 True (→ 알림 대상),
    이내에 사용 기록이 있으면 False (→ 스킵)
    """
    now_ms_ = now_ms()
    last_seen = get_region_last_seen(principal, region)
    if last_seen is None:
        # 한 번도 본 적 없으면 "최근에 사용 안 한 리전"으로 간주
        return True
    return (now_ms_ - last_seen) > (window_seconds * 1000)


def _put_login_state(keys: list[str], when_ms: int, src_ip: str, user_agent: str, ttl_sec: int = 3600):
    tbl = state_table()
    expires = int(time.time()) + ttl_sec
    for k in keys:
        item = {
            STATE_PK_NAME: k,
            "last_login_ms": when_ms,
            "source_ip": src_ip or "",
            "user_agent": user_agent or "",
            "ttl": expires
        }
        if STATE_SK_NAME and STATE_SK_VALUE:
            item[STATE_SK_NAME] = STATE_SK_VALUE
        try:
            tbl.put_item(Item=item)
        except Exception as e:
            print("state put fail:", k, e)

def _get_login_state(keys: list[str]):
    tbl = state_table()
    results = {}
    for k in keys:
        try:
            r = tbl.get_item(Key=_state_key_obj(k)).get("Item")
        except Exception as e:
            print("state get fail:", k, e)
            r = None
        results[k] = r
    return results


# ==============================
# 이벤트 처리기
# ==============================
def handle_login_success(event):
    detail = event.get("detail") or {}
    ui = detail.get("userIdentity") or {}
    arn = ui.get("arn") or ""
    principal_id = ui.get("principalId") or ""
    src_ip = detail.get("sourceIPAddress")
    user_agent = detail.get("userAgent")

    try:
        when_ms = int(time.time() * 1000)
    except Exception:
        when_ms = now_ms()

    keys = []
    if arn:
        keys.append(f"login#{arn}")
    if principal_id:
        keys.append(f"login#{principal_id}")

    if not keys:
        return _ret({"status": "skip_no_principal"})

    # 로그인 상태 저장
    _put_login_state(keys, when_ms, src_ip, user_agent, ttl_sec=3600)

    # 로그인 자체는 대시보드 알림 X (중복 방지)
    return _ret({"status": "login_state_saved", "keys": keys})

def handle_cloudtrail_tamper(event):
    detail = event.get("detail") or {}
    ui = detail.get("userIdentity") or {}
    arn = ui.get("arn") or ""
    principal_id = ui.get("principalId") or ""
    src_ip = detail.get("sourceIPAddress")
    user_agent = detail.get("userAgent")
    event_name = detail.get("eventName")
    when_iso_val = event.get("time") or detail.get("eventTime") or now_iso()
    now_ms_ = now_ms()

    keys = []
    if arn:
        keys.append(f"login#{arn}")
    if principal_id:
        keys.append(f"login#{principal_id}")

    recent = _get_login_state(keys) if keys else {}
    recent_login_within_window = False
    recent_login_ms = None

    for _, it in (recent or {}).items():
        item = it or {}
        lm = _to_int_safe(item.get("last_login_ms"))
        if lm is not None and (now_ms_ - lm) <= (TAMPER_WINDOW_SECONDS * 1000):
            recent_login_within_window = True
            recent_login_ms = lm
            break

    payload = {
        "alert_type": "cloudtrail_tamper_attempt",
        "severity": "HIGH",
        "source": "AWS CloudTrail",
        "event_type": "로그인 후 CloudTrail 중지/삭제/설정 변경 시도",
        "principal": arn or principal_id or "",
        "event_name": event_name,
        "recent_login_within_window": recent_login_within_window,
        "window_seconds": TAMPER_WINDOW_SECONDS,
        "recent_login_ms": recent_login_ms,
        "source_ip": src_ip,
        "user_agent": user_agent,
        "time": when_iso_val,
        "raw_event": detail,
        "arn": arn,
    }

    # 🔹 Incident details 구성
    incident_resource = arn or principal_id or ""
    region = extract_region(event)
    account_id = extract_account_id(event, {"arn": incident_resource})

    details_for_incident = {
        "time": when_iso_val,
        "source": "CloudTrail",
        "type": "로그인 후 CloudTrail 중지/삭제/설정 변경 시도",
        "sg": "",
        "arn": incident_resource,
        "resource": incident_resource,
        "account": account_id,
        "region": region,
        "alertType": "ALERT",
        "rulesViolated": [
            "CLOUDTRAIL_TAMPER_AFTER_LOGIN: 로그인 직후 CloudTrail 설정 변경/중지 시도"
        ],
        "severity": "HIGH",
    }

    # 🔹 1단계: Incident 히스토리 기록
    incident = put_incident_record(
        event_type=payload["event_type"],
        resource=incident_resource,
        severity=payload["severity"],
        status="NEW",
        created_at=when_iso_val,
        details=details_for_incident,
    )
    if incident:
        payload["incident"] = incident

    # 🔹 3단계: WebSocket으로 대시보드 알림
    dashboard_event = to_dashboard_event(event, payload)
    post_to_ws_dashboard(dashboard_event)
    return _ret({"status": "tamper_alert_sent", "recent_login_within_window": recent_login_within_window})

def handle_access_key_created(event):
    if event.get("source") != "aws.iam":
        return _ret({"status": "skip"})
    detail = event.get("detail", {}) or {}
    if detail.get("eventName") != "CreateAccessKey":
        return _ret({"status": "skip_non_target_event"})

    access_key_id = (
        (detail.get("responseElements", {}) or {}).get("accessKey", {}) or {}
    ).get("accessKeyId", "unknown")

    ui = detail.get("userIdentity", {}) or {}
    user_arn = ui.get("arn") or ui.get("principalId") or "unknown"
    user_type = ui.get("type")
    principal = ui.get("principalId")

    src_ip = detail.get("sourceIPAddress")
    user_agent = detail.get("userAgent")
    when_iso_val = event.get("time") or detail.get("eventTime") or now_iso()
    region = extract_region(event)

    # 🔹 NEW: 최근 7일 이내에 이 리전에서 활동한 적이 있으면 알림 스킵
    now_ms_ = now_ms()
    if region:
        unused_recently = is_region_unused_recently(user_arn, region, REGION_WINDOW_SECONDS)
        # 이번 이벤트 시각은 마지막 사용 시각으로 항상 기록
        put_region_last_seen(user_arn, region, now_ms_)

        if not unused_recently:
            return _ret({
                "status": "skip_recent_region",
                "principal": user_arn,
                "region": region
            })

    payload = {
        "alert_type": "access_key_created",
        "severity": "HIGH",
        "source": "AWS IAM",
        "event_type": "AccessKeyCreated",
        "principal": user_arn,
        "access_key_id": access_key_id,
        "actor_type": user_type,
        "principal_id": principal,
        "source_ip": src_ip,
        "user_agent": user_agent,
        "time": when_iso_val,
        "raw_event": detail,
        "arn": user_arn,
    }

    # 🔹 Incident details 구성
    account_id = extract_account_id(event, {"arn": user_arn})
    details_for_incident = {
        "time": when_iso_val,
        "source": "IAM",
        "type": "비정상 리전에서 AccessKey 생성",
        "sg": "",
        "arn": user_arn,
        "resource": user_arn,
        "account": account_id,
        "region": region,
        "alertType": "ALERT",
        "rulesViolated": [
            f"UNUSUAL_REGION_ACCESS_KEY: 최근 미사용 리전({region})에 새 액세스 키 생성"
        ],
        "severity": "HIGH",
    }

    # 🔹 1단계: Incident 히스토리 기록
    incident = put_incident_record(
        event_type=payload["event_type"],
        resource=user_arn,
        severity=payload["severity"],
        status="NEW",
        created_at=when_iso_val,
        details=details_for_incident,
    )
    if incident:
        payload["incident"] = incident

    # 🔹 3단계: WebSocket으로 대시보드 알림
    dashboard_event = to_dashboard_event(event, payload)
    post_to_ws_dashboard(dashboard_event)
    return _ret({"status": "alert_sent", "access_key_id": access_key_id})


# ==============================
# Lambda 핸들러
# ==============================
def lambda_handler(event, context):
    try:
        # CloudWatch Logs 직결 경우 스킵
        if "awslogs" in event:
            return _ret({"status": "skipped_cwlogs"})

        src = event.get("source")
        dtype = event.get("detail-type")

        # 1) Console 로그인 성공
        if src == "aws.signin" and dtype == "AWS Console Sign In via CloudTrail":
            detail = event.get("detail", {}) or {}
            if (detail.get("responseElements") or {}).get("ConsoleLogin") == "Success":
                return handle_login_success(event)

        # 2) STS AssumeRole → 성공 시 로그인으로 간주
        if src == "aws.sts" and dtype == "AWS API Call via CloudTrail":
            if (event.get("detail") or {}).get("eventName") == "AssumeRole":
                return handle_login_success(event)

        # 3) CloudTrail tamper 시도
        if src == "aws.cloudtrail" and dtype == "AWS API Call via CloudTrail":
            if (event.get("detail") or {}).get("eventSource") == "cloudtrail.amazonaws.com":
                if (event.get("detail") or {}).get("eventName") in (
                    "StopLogging",
                    "DeleteTrail",
                    "UpdateTrail",
                    "PutEventSelectors",
                    "UpdateTrailStatus",
                    "CreateTrail",
                ):
                    return handle_cloudtrail_tamper(event)

        # 4) Access Key 생성
        if src == "aws.iam" and dtype == "AWS API Call via CloudTrail":
            return handle_access_key_created(event)

        return _ret({"status": "noop"})
    except Exception as e:
        print("handler error:", e)
        raise
