import os
import json
import time
import urllib.request
import re
import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timezone

# ==============================
# 환경변수
# ==============================
WS_ENDPOINT = os.environ.get("WS_ENDPOINT")  # 하위호환
WS_ENDPOINT_EVENTS = os.environ.get("WS_ENDPOINT_EVENTS") or WS_ENDPOINT
WS_ENDPOINT_ACTIONS = os.environ.get("WS_ENDPOINT_ACTIONS") or WS_ENDPOINT_EVENTS or WS_ENDPOINT

STATE_TABLE = os.environ.get("STATE_TABLE", "security-alerts-state")

# 테이블 분리(없으면 하위호환)
CONNECTIONS_TABLE = os.environ.get("CONNECTIONS_TABLE", "WebSocketConnections")
CONNECTIONS_TABLE_EVENTS = os.environ.get("CONNECTIONS_TABLE_EVENTS") or CONNECTIONS_TABLE
CONNECTIONS_TABLE_ACTIONS = os.environ.get("CONNECTIONS_TABLE_ACTIONS") or CONNECTIONS_TABLE_EVENTS

WINDOW_MINUTES = int(os.environ.get("WINDOW_MINUTES", "10"))
SPEED_THRESHOLD_KMH = float(os.environ.get("SPEED_THRESHOLD_KMH", "900"))
ACCOUNT_ID_OVERRIDE = os.environ.get("ACCOUNT_ID_OVERRIDE")
DASHBOARD_SCHEMA = os.environ.get("DASHBOARD_SCHEMA", "").lower()

# 자동대응(옵션)
ACTION_MODE = (os.environ.get("ACTION_MODE") or "alert_only").lower()  # alert_only | semi_auto | full_auto
ALLOWED_COUNTRIES = [x.strip().upper() for x in (os.environ.get("ALLOWED_COUNTRIES") or "").split(",") if x.strip()]
ALLOWED_ASN = [x.strip().upper() for x in (os.environ.get("ALLOWED_ASN") or "").split(",") if x.strip()]

HTTP_TIMEOUT = 8

# 🔹 Incident 테이블 (새로 추가)
INCIDENT_TABLE = os.environ.get("INCIDENT_TABLE", "Incident")

ddb_client = boto3.client("dynamodb")  # 상태테이블(람다 리전)
sts_client = boto3.client("sts")

# ==============================
# DDB 리소스(엔드포인트 리전 맞춤)
# ==============================
def ddb_resource(endpoint_url_base=None):
    region = os.environ.get("AWS_REGION") or "us-east-1"
    try:
        base = (endpoint_url_base or WS_ENDPOINT_EVENTS or WS_ENDPOINT or "").rstrip("/")
        if ".execute-api." in base:
            region = base.split(".execute-api.", 1)[-1].split(".amazonaws.com", 1)[0] or region
    except Exception:
        pass
    return boto3.resource("dynamodb", region_name=region)

# ==============================
# 공용 유틸
# ==============================
def _ret(obj: dict):
    print(json.dumps(obj, ensure_ascii=False))
    return obj

def _now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def geoip(ip: str):
    try:
        with urllib.request.urlopen(f"https://ipinfo.io/{ip}/json", timeout=HTTP_TIMEOUT) as r:
            j = json.load(r)
        loc = j.get("loc")
        org = j.get("org") or ""  # 예: "AS4766 Korea Telecom"
        asn = org.split()[0].upper() if org else ""
        if not loc:
            return {"ip": ip, "lat": None, "lon": None, "city": j.get("city"), "country": j.get("country"), "asn": asn}
        lat, lon = [float(x) for x in loc.split(",")]
        return {"ip": ip, "lat": lat, "lon": lon, "city": j.get("city"), "country": j.get("country"), "asn": asn}
    except Exception as e:
        print("geoip fail:", e)
        return {"ip": ip, "lat": None, "lon": None, "asn": ""}

def haversine_km(lat1, lon1, lat2, lon2):
    if None in (lat1, lon1, lat2, lon2):
        return None
    from math import radians, sin, cos, atan2, sqrt
    R = 6371.0
    phi1, phi2 = radians(lat1), radians(lat2)
    dphi, dlambda = radians(lat2 - lat1), radians(lon2 - lon1)
    a = sin(dphi/2)**2 + cos(phi1)*cos(phi2)*sin(dlambda/2)**2
    return R * 2 * atan2(sqrt(1-a), sqrt(a))

def normalize_source(source: str) -> str:
    if not source:
        return "Unknown"
    s = source.lower()
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
    return source

def extract_auth_context(event: dict):
    """
    다양한 로그인/세션 시작 이벤트에서
    (principal_arn, user_type, ip, when_iso, auth_kind) 를 뽑아냄.
    지원하지 않는 이벤트면 None 리턴.
    """
    detail = event.get("detail") or {}
    src = event.get("source")
    dt = event.get("detail-type")

    # 1) 콘솔 로그인 (기존 케이스)
    if src == "aws.signin" and dt == "AWS Console Sign In via CloudTrail":
        ui = detail.get("userIdentity") or {}
        principal = ui.get("arn") or ui.get("principalId") or "unknown"
        u_type = ui.get("type")
        ip = detail.get("sourceIPAddress")
        when_iso = event.get("time") or detail.get("eventTime")
        auth_kind = "console"
        return principal, u_type, ip, when_iso, auth_kind

    # 2) STS / GetSessionToken / GetFederationToken / GetCallerIdentity 등
    if dt == "AWS API Call via CloudTrail":
        ev_src = (detail.get("eventSource") or "").lower()
        name = detail.get("eventName")
        if ev_src == "sts.amazonaws.com" and name in [
            "AssumeRole",
            "AssumeRoleWithSAML",
            "AssumeRoleWithWebIdentity",
            "GetSessionToken",
            "GetFederationToken",
            "GetCallerIdentity",
        ]:
            ui = detail.get("userIdentity") or {}
            u_type = ui.get("type")

            # 세션 기반이면 sessionIssuer.arn → 아니면 userIdentity.arn → principalId
            sess_ctx = (ui.get("sessionContext") or {}).get("sessionIssuer") or {}
            principal = (
                sess_ctx.get("arn")
                or ui.get("arn")
                or ui.get("principalId")
                or "unknown"
            )

            ip = detail.get("sourceIPAddress")
            when_iso = detail.get("eventTime") or event.get("time")
            auth_kind = "sts"
            return principal, u_type, ip, when_iso, auth_kind

    # 그 외 이벤트는 이 Lambda에서 처리 안 함
    return None


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

# ==============================
# 🔹 Incident 히스토리 유틸 (추가)
# ==============================
def incident_table():
    if not INCIDENT_TABLE:
        return None
    return ddb_resource().Table(INCIDENT_TABLE)

def generate_incident_id(prefix: str = "inc") -> str:
    """
    예: inc-20251120-143000-123
    """
    ts = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    rand = int(time.time() * 1000) % 1000  # 간단 랜덤 느낌
    return f"{prefix}-{ts}-{rand:03d}"

def put_incident_record(event_type: str,
                        resource: str,
                        severity: str,
                        status: str = "NEW",
                        note: str = "",
                        details=None,
                        created_at: str = None):
    """
    Incident 테이블에 1건 저장.

    {
      "incident_id": "...",
      "event_type": "...",
      "resource": "...",
      "severity": "LOW|MEDIUM|HIGH|CRITICAL",
      "status": "NEW|PROCESSING|MITIGATED|CLOSED",
      "note": "운영팀 확인 중",
      "created_at": "...",
      "updated_at": "...",
      "details": { ... }
    }
    """
    tbl = incident_table()
    if not tbl:
        print("❌ INCIDENT_TABLE not configured; skip incident logging")
        return None

    created = created_at or _now_iso()
    iid = generate_incident_id()

    sev = (severity or "LOW").upper()
    st = (status or "NEW").upper()

    item = {
        "incident_id": iid,
        "event_type": event_type,
        "resource": resource or "",
        "severity": sev,
        "status": st,
        "note": note or "",
        "created_at": created,
        "updated_at": created,
        "details": details or {},
    }

    try:
        tbl.put_item(Item=item)
        print("✅ Incident stored:", json.dumps(item, ensure_ascii=False))
        return item
    except Exception as e:
        print("incident put fail:", e)
        return None

# ==============================
# 대시보드 스키마 변환 (이벤트용)
# ==============================
_ARN_REGION_RE = re.compile(r"arn:aws:[^:]+:([a-z0-9-]+):\d{12}:")

def _pick(*vals):
    for v in vals:
        if v is not None and v != "":
            return v
    return None

def _region_from_arn(arn: str, fallback: str) -> str:
    if not arn:
        return fallback or ""
    m = _ARN_REGION_RE.search(arn)
    return m.group(1) if m else (fallback or "")

def to_dashboard_event(event, payload) -> dict:
    now_ms = int(time.time() * 1000)

    account_id = extract_account_id(event, payload)
    raw_source = payload.get("source") or event.get("source") or "Unknown"
    source = normalize_source(raw_source)
    etype  = payload.get("event_type") or payload.get("type") or "불가능한 위치(IP/Geo) 동시 로그인"
    sev    = (payload.get("severity") or "LOW").upper()

    sg_id  = _pick(payload.get("sg_id"), payload.get("securityGroupId"), payload.get("security_group_id"))
    sg_arn = _pick(payload.get("sg_arn"), payload.get("securityGroupArn"), payload.get("security_group_arn"))

    principal_arn = payload.get("principal", "") or ""
    resource = _pick(payload.get("resource"), sg_arn, principal_arn) or "-"

    region = event.get("region") or _region_from_arn(sg_arn or principal_arn, "") or payload.get("region", "")

    arn_display = resource or "-"
    sg_value = sg_id or ""  # 값 없으면 빈칸

    meta = dict(payload)
    meta["account_id"] = account_id
    meta["original_arn"] = resource
    if sg_id:
        meta["sg_id"] = sg_id
    if sg_arn:
        meta["sg_arn"] = sg_arn

    v1 = {
        "kind": "event",
        "event": {
            "time": now_ms,
            "source": source,
            "type": etype,
            "resource": resource,
            "account": account_id,
            "region": region,
            "severity": sev,
            "sg": sg_value,
            "arn": arn_display,
            "meta": meta
        }
    }

    v2 = {
        "type": "events.append",
        "data": {
            "ts": now_ms,
            "src": source,
            "evtType": etype,
            "res": resource,
            "acct": account_id,
            "region": region,
            "sev": sev,
            "sg": sg_value,
            "arn": arn_display,
            "meta": meta
        }
    }

    flat = {
        "time": now_ms,
        "source": source,
        "type": etype,
        "resource": resource,
        "sg": sg_value,
        "arn": arn_display,
        "account": account_id,
        "region": region,
        "severity": sev
    }

    return {"v1": v1, "v2": v2, "flat": flat}

# ==============================
# WebSocket 라우팅 (이벤트/액션 분리)
# ==============================
def _post_to_ws(endpoint_url_base: str, connections_table_name: str, formatted_bundle: dict):
    if not endpoint_url_base:
        print("❌ WS endpoint not set; skip")
        return

    endpoint_url = endpoint_url_base.rstrip("/").replace("wss://", "https://")
    region = os.environ.get("AWS_REGION") or "us-east-1"
    try:
        region = endpoint_url.split(".execute-api.", 1)[-1].split(".amazonaws.com", 1)[0] or region
    except Exception:
        pass

    api = boto3.client("apigatewaymanagementapi", endpoint_url=endpoint_url, region_name=region)

    # ✅ 여기서부터가 핵심 수정 부분
    #    v1 / v2 는 전부 버리고, 대시보드가 그대로 사용하는 flat 이벤트만 보낸다.
    if formatted_bundle.get("flat"):
        payload = formatted_bundle["flat"]
    elif formatted_bundle.get("v1") and isinstance(formatted_bundle["v1"], dict):
        # 혹시 flat 이 없다면 v1.event 를 flat 처럼 사용 (fallback)
        v1 = formatted_bundle["v1"]
        payload = v1.get("event", v1)
    elif formatted_bundle.get("v2") and isinstance(formatted_bundle["v2"], dict):
        # 마지막 안전장치: v2.data 를 flat 처럼 사용
        v2 = formatted_bundle["v2"]
        payload = v2.get("data", v2)
    else:
        print("⚠️ formatted_bundle에 전송할 payload가 없음:", formatted_bundle.keys())
        return

    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")

    table = ddb_resource(endpoint_url_base).Table(connections_table_name)

    ok = gone = err = 0
    last_key = None

    while True:
        scan_kwargs = {"ProjectionExpression": "connectionId"}
        if last_key:
            scan_kwargs["ExclusiveStartKey"] = last_key
        try:
            resp = table.scan(**scan_kwargs)
        except Exception as e:
            print(f"❌ Failed to scan connections({connections_table_name}): {e}")
            break

        for it in (resp.get("Items") or []):
            cid = it.get("connectionId")
            if not cid:
                continue
            try:
                api.post_to_connection(ConnectionId=cid, Data=data)
                ok += 1
            except api.exceptions.GoneException:
                gone += 1
                try:
                    table.delete_item(Key={"connectionId": cid})
                except Exception:
                    pass
            except ClientError as e:
                err += 1
                print("send error:", e)

        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break

    print(f"WS broadcast({endpoint_url} | {connections_table_name}): ok={ok}, gone={gone}, err={err}")

# 액션 대시보드가 요구하는 "평면 JSON"을 RAW로 전송
def _post_to_ws_raw(endpoint_url_base: str, connections_table_name: str, obj: dict):
    if not endpoint_url_base:
        print("❌ WS endpoint not set; skip")
        return

    endpoint_url = endpoint_url_base.rstrip("/").replace("wss://", "https://")
    region = os.environ.get("AWS_REGION") or "us-east-1"
    try:
        region = endpoint_url.split(".execute-api.", 1)[-1].split(".amazonaws.com", 1)[0] or region
    except Exception:
        pass

    api = boto3.client("apigatewaymanagementapi", endpoint_url=endpoint_url, region_name=region)
    table = ddb_resource(endpoint_url_base).Table(connections_table_name)

    ok = gone = err = 0
    last_key = None
    data = json.dumps(obj, ensure_ascii=False).encode("utf-8")

    while True:
        scan_kwargs = {"ProjectionExpression": "connectionId"}
        if last_key:
            scan_kwargs["ExclusiveStartKey"] = last_key
        try:
            resp = table.scan(**scan_kwargs)
        except Exception as e:
            print(f"❌ Failed to scan connections({connections_table_name}): {e}")
            break

        for it in (resp.get("Items") or []):
            cid = it.get("connectionId")
            if not cid:
                continue
            try:
                api.post_to_connection(ConnectionId=cid, Data=data)
                ok += 1
            except api.exceptions.GoneException:
                gone += 1
                try:
                    table.delete_item(Key={"connectionId": cid})
                except Exception:
                    pass
            except ClientError as e:
                err += 1
                print("send error:", e)

        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break

    print(f"WS broadcast RAW ({endpoint_url} | {connections_table_name}): ok={ok}, gone={gone}, err={err}")

def send_event(bundle: dict):
    _post_to_ws(WS_ENDPOINT_EVENTS, CONNECTIONS_TABLE_EVENTS, bundle)

def send_action_payload(payload: dict):
    # 필수 필드 보정
    p = dict(payload)
    p.setdefault("time", _now_iso())
    for k in ("action", "target", "playbook", "status"):
        p.setdefault(k, "")
    _post_to_ws_raw(WS_ENDPOINT_ACTIONS, CONNECTIONS_TABLE_ACTIONS, p)

# 하위호환
def post_to_ws_dashboard(formatted_bundle: dict):
    send_event(formatted_bundle)

# ==============================
# 상태 저장/로드
# ==============================
def state_key_for_user(user_arn: str):
    return f"impossible_travel:last_login#{user_arn}"

def read_last_login(user_arn: str):
    r = ddb_client.get_item(
        TableName=STATE_TABLE,
        Key={"connectionId": {"S": state_key_for_user(user_arn)}}
    )
    return r.get("Item")

def write_last_login(user_arn: str, ip: str, lat: float, lon: float, ts_ms: int):
    item = {
        "connectionId": {"S": state_key_for_user(user_arn)},
        "ip": {"S": ip or ""},
        "lat": {"N": str(lat) if lat is not None else "0"},
        "lon": {"N": str(lon) if lon is not None else "0"},
        "ts_ms": {"N": str(ts_ms)},
        "ttl": {"N": str(int(time.time()) + 60*60*24*30)}  # 30일 TTL
    }
    ddb_client.put_item(TableName=STATE_TABLE, Item=item)

# ==============================
# 자동대응 의사결정 & 실행
# ==============================
def should_auto_block(g: dict) -> bool:
    country = (g.get("country") or "").upper()
    asn = (g.get("asn") or "").upper()
    if not ALLOWED_COUNTRIES and not ALLOWED_ASN:
        return True
    if ALLOWED_COUNTRIES and country in ALLOWED_COUNTRIES:
        return False
    if ALLOWED_ASN and asn and asn in ALLOWED_ASN:
        return False
    return True

def auto_block_user(user_arn: str) -> dict:
    iam = boto3.client("iam")
    user_name = user_arn.split("/")[-1] if "/" in user_arn else user_arn
    result = {"user": user_name, "loginBlocked": False, "keysDisabled": 0, "error": None}
    try:
        # 1) 콘솔 로그인 비밀번호 초기화 요구
        try:
            iam.update_login_profile(UserName=user_name, PasswordResetRequired=True)
            result["loginBlocked"] = True
        except iam.exceptions.NoSuchEntityException:
            # LoginProfile 이 없었던 유저면 여기서 그냥 패스
            pass

        # 2) 액세스 키 비활성화 (있으면)
        try:
            keys = iam.list_access_keys(UserName=user_name).get("AccessKeyMetadata", [])
            for k in keys:
                iam.update_access_key(
                    UserName=user_name,
                    AccessKeyId=k["AccessKeyId"],
                    Status="Inactive"
                )
            result["keysDisabled"] = len(keys)
        except Exception as e:
            result["error"] = f"keys: {e}"

    except Exception as e:
        result["error"] = str(e)
    return result

# ==============================
# 코어: ConsoleLogin → Impossible travel
# ==============================
def handle_auth_impossible_travel(event):
    ctx = extract_auth_context(event)
    if not ctx:
        return _ret({"status": "skip_unsupported_event"})

    detail = event.get("detail") or {}

    user_arn, u_type, ip, when_iso, auth_kind = ctx
    if not ip or not user_arn or not when_iso:
        return _ret({"status": "skip_insufficient"})

    # === 현재 로그인 위치 GeoIP ===
    g = geoip(ip)
    lat2, lon2 = g.get("lat"), g.get("lon")

    # === 시간 파싱 ===
    try:
        from datetime import datetime as _dt
        t2 = int(_dt.fromisoformat(when_iso.replace("Z", "+00:00")).timestamp() * 1000)
    except Exception:
        t2 = int(time.time() * 1000)

    # === 이전 로그인 상태 읽기 & 갱신 ===
    last = read_last_login(user_arn)
    write_last_login(user_arn, ip, lat2, lon2, t2)

    if not last:
        # 이 주체 첫 로그인 (어떤 채널이든)
        return _ret({"status": "first_login_recorded", "auth_kind": auth_kind})

    try:
        lat1 = float(last.get("lat", {}).get("N"))
        lon1 = float(last.get("lon", {}).get("N"))
        t1 = int(last.get("ts_ms", {}).get("N"))
    except Exception:
        return _ret({"status": "bad_last_item"})

    minutes = abs(t2 - t1) / 1000 / 60.0
    if minutes > WINDOW_MINUTES:
        return _ret({"status": "outside_window", "minutes": minutes})

    dist_km = haversine_km(lat1, lon1, lat2, lon2)
    if dist_km is None:
        return _ret({"status": "no_geo"})

    speed = dist_km / max(minutes / 60.0, 0.0001)

    if speed <= SPEED_THRESHOLD_KMH:
        # 두 번째 로그인인데, 속도는 정상 범위
        return _ret({"status": "ok", "speed": speed, "auth_kind": auth_kind})

    # === 여기서부터가 '불가능 이동' 판정 ===
    payload = {
        "alert_type": "impossible_travel",
        "severity": "HIGH",
        "principal": user_arn,
        "auth_kind": auth_kind,     # console / sts
        "user_type": u_type,        # IAMUser / AssumedRole / ...
        "current": {
            "ip": ip,
            "lat": lat2,
            "lon": lon2,
            "time": when_iso,
            "city": g.get("city"),
            "country": g.get("country"),
            "asn": g.get("asn"),
        },
        "previous": {
            "ip": last.get("ip", {}).get("S"),
            "lat": float(last.get("lat", {}).get("N")),
            "lon": float(last.get("lon", {}).get("N")),
            "ts_ms": int(last.get("ts_ms", {}).get("N")),
        },
        "distance_km": round(dist_km, 1),
        "speed_kmh": round(speed, 1),
        "raw_event": detail,
        "event_type": "불가능한 위치(IP/Geo) 동시 로그인",
    }

    # 🔹 Incident details JSON (요청 포맷)
    account_for_incident = extract_account_id(event, {"principal": user_arn})
    region_for_incident = event.get("region") or "us-east-1"
    source_for_incident = normalize_source(
        event.get("source") or (detail.get("eventSource") or "AWS Sign-In/STS")
    )
    incident_type = "불가능한 위치(IP/Geo) 동시 로그인"

    # ── meta용 디바이스 / UA / IP 정리 ─────────────────────────
    user_agent = detail.get("userAgent") or ""
    ua_lower = user_agent.lower()

    # OS 대략 추정
    if "windows" in ua_lower:
        os_part = "windows"
    elif "mac os x" in ua_lower:
        os_part = "macos"
    elif "linux" in ua_lower:
        os_part = "linux"
    else:
        os_part = "unknown"

    # 브라우저 대략 추정
    if "firefox" in ua_lower:
        browser_part = "firefox"
    elif "chrome" in ua_lower:
        browser_part = "chrome"
    elif "safari" in ua_lower and "chrome" not in ua_lower:
        browser_part = "safari"
    else:
        browser_part = "unknown"

    device_summary = f"{os_part}|{browser_part}"

    meta_for_incident = {
        "ip": ip,
        "device": {
            "summary": device_summary,
            "ua": user_agent,
        },
        "geo": {
            "country": g.get("country"),
            "city": g.get("city"),
            "asn": g.get("asn"),
        },
    }

    incident_details = {
        "time": when_iso,
        "source": source_for_incident,
        "type": incident_type,
        "sg": "",  # SG 개념이 없으니까 빈 문자열
        "arn": user_arn,
        "resource": user_arn,
        "account": account_for_incident or "",
        "region": region_for_incident,
        "alertType": "ALERT",
        "rulesViolated": [
            "IMPOSSIBLE_TRAVEL: 불가능한 위치(IP/Geo) 동시 로그인"
        ],
        "severity": (payload.get("severity") or "HIGH").upper(),
        "meta": meta_for_incident,
    }

    # 🔹 Incident 기록
    incident = put_incident_record(
        event_type=incident_type,
        resource=user_arn,
        severity=payload["severity"],
        status="NEW",
        note="",  # note는 사용하지 않으므로 빈 문자열
        details=incident_details,
        created_at=when_iso,
    )

    if incident:
        # 대시보드 payload에도 incident_id 포함
        payload["incident_id"] = incident["incident_id"]

    # 1) 탐지 알림 → 이벤트 채널
    bundle = to_dashboard_event(event, payload)
    send_event(bundle)

    # 2) 자동대응 (semi_auto / full_auto 설정 & 화이트리스트 조건 만족 시)
    if ACTION_MODE in ("semi_auto", "full_auto") and should_auto_block(g):
        auto_action = ""
        action_status = "TRIGGERED"  # 기본값
        meta = {"auth_kind": auth_kind, "user_type": u_type}
        action_result = None

        if u_type == "IAMUser":
            if ACTION_MODE == "full_auto":
                # 실제 IAM 계정 잠금 시도
                auto_action = "로그인 비밀번호 재설정"
                action_result = auto_block_user(user_arn)
                meta["result"] = action_result

                # 에러 없으면 성공, 있으면 실패로 표시
                if not action_result.get("error"):
                    action_status = "SUCCEEDED"
                else:
                    action_status = "FAILED"
            else:
                # semi_auto : 자동으로는 안 막고 승인 필요 상태만 남김
                auto_action = "PasswordResetRequired"
                action_status = "PENDING"
        else:
            # 루트/Role/STS 등은 실제 차단 대신 스킵
            auto_action = "Skipped(Non-IAMUser)"
            action_status = "SKIPPED"

        # 대시보드 상세 보기용으로 payload에도 기록
        payload["auto_action"] = auto_action
        if action_result is not None:
            payload["auto_result"] = action_result

        # 🔹 자동 대응 로그 WebSocket으로 전송
        #    - index.html 은 이 JSON을 그대로 받아서 "자동 대응 로그" 테이블 + KPI에 반영함
        send_action_payload({
            "time": when_iso,
            "action": auto_action,
            "target": user_arn,
            "playbook": "account-lock-or-approve",
            "status": action_status,  # 여기 값이 SUCCEEDED 면 초록 KPI + 인시던트 갱신
            "incident_id": payload.get("incident_id"),  # 있으면 해당 인시던트 상태를 MITIGATED 로 올려줌
            "meta": meta
        })

        action_bundle = to_dashboard_event(event, payload)
        # send_action(action_bundle)  # 기존에 따로 구현되어 있다면 사용

    return _ret({"status": "alert_sent", "speed": speed, "auth_kind": auth_kind})

# ==============================
# 테스트용 WS 핑 / 액션
# ==============================
def ws_test_ping():
    payload = {
        "source": "internal",
        "event_type": "WS_PING",
        "severity": "INFO",
        "principal": "",
        "message": "hello from lambda test ping"
    }
    bundle = to_dashboard_event({"source":"internal"}, payload)
    print("[DEBUG] ws_test_ping bytes:", len(json.dumps(bundle.get('v2')).encode("utf-8")))
    send_event(bundle)

def ws_test_action():
    send_action_payload({
        "time": _now_iso(),
        "action": "QuarantineInstance",
        "target": "i-0123456789abcdef0",
        "playbook": "isolate-ec2",
        "status": "TRIGGERED"
    })

# ==============================
# Lambda 핸들러
# ==============================
def lambda_handler(event, context):
    try:
        print("[DEBUG] event:", json.dumps(event)[:500])

        if isinstance(event, dict) and event.get("test_ws") == "1":
            print("[DEBUG] entering test_ws branch")
            ws_test_ping()
            return _ret({"status": "sent_test_ping"})

        if isinstance(event, dict) and event.get("test_action") == "1":
            print("[DEBUG] entering test_action branch")
            ws_test_action()
            return _ret({"status": "sent_test_action"})

        if "awslogs" in event:
            return _ret({"status": "skipped_cwlogs"})

        src = event.get("source")
        dt  = event.get("detail-type")

        # 1) 콘솔 로그인
        if src == "aws.signin" and dt == "AWS Console Sign In via CloudTrail":
            return handle_auth_impossible_travel(event)

        # 2) CloudTrail 기반 STS / GetCallerIdentity 로그인 신호
        if dt == "AWS API Call via CloudTrail":
            # extract_auth_context 안에서 지원 여부를 다시 판단함
            return handle_auth_impossible_travel(event)

        return _ret({"status": "noop"})

    except Exception as e:
        import traceback
        print("handler error:", e)
        traceback.print_exc()
        raise
