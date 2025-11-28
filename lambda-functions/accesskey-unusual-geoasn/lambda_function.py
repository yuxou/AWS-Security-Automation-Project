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
WS_ENDPOINT = os.environ.get("WS_ENDPOINT")  # https://{apiId}.execute-api.{region}.amazonaws.com/{stage}
STATE_TABLE = os.environ.get("STATE_TABLE", "security-alerts-state-v2")
CONNECTIONS_TABLE = os.environ.get("CONNECTIONS_TABLE", "WebSocketConnections")
ACCOUNT_ID_OVERRIDE = os.environ.get("ACCOUNT_ID_OVERRIDE")
HTTP_TIMEOUT = 8
FORCE_IP = os.environ.get("FORCE_IP")  # 테스트용: 강제로 이 IP를 GeoIP로 사용
STALE_DAYS = int(os.environ.get("STALE_DAYS", "7") or "7")  # 7일 미접속이면 다시 알림

# DynamoDB 키 이름(기본: id), 정렬키가 있으면 STATE_SK_ATTR로 지정
STATE_PK_ATTR = os.environ.get("STATE_PK_ATTR", "id")
STATE_SK_ATTR = os.environ.get("STATE_SK_ATTR")  # 없으면 None

# (옵션) 중복 알림 억제 창(초). 0이면 비활성화
SUPPRESS_SECONDS = int(os.environ.get("SUPPRESS_SECONDS", "0") or "0")

# 🔹 Incident 히스토리용 테이블
INCIDENT_TABLE = os.environ.get("INCIDENT_TABLE", "Incident")

ddb_client = boto3.client("dynamodb")
sts_client = boto3.client("sts")

def ddb_resource():
    region = os.environ.get("AWS_REGION") or "us-east-1"
    try:
        region = WS_ENDPOINT.rstrip("/").split(".execute-api.", 1)[-1].split(".amazonaws.com", 1)[0] or region
    except Exception:
        pass
    return boto3.resource("dynamodb", region_name=region)

# ============== ARN 판별/선택 헬퍼 ==============
def _is_user_arn(arn: str) -> bool:
    # iam 사용자 ARN만 True (assumed-role, role 등은 False)
    return bool(re.match(r"^arn:aws:iam::\d{12}:user/", arn or ""))

def _pick_actor_user_arn(user_identity: dict) -> str:
    # 1) userIdentity.arn 이 user/* 형태면 그대로
    raw = (user_identity or {}).get("arn") or ""
    if _is_user_arn(raw):
        return raw
    # 2) 세션(assumed-role)이면 issuer가 user/* 인지 확인
    issuer = ((user_identity or {}).get("sessionContext") or {}).get("sessionIssuer") or {}
    issuer_arn = issuer.get("arn") or ""
    if _is_user_arn(issuer_arn):
        return issuer_arn
    # 3) 못 찾으면 비표시(스킵)
    return ""

# ==============================
# 공용 유틸
# ==============================
def _ret(obj: dict):
    print(json.dumps(obj, ensure_ascii=False))
    return obj

def now_iso() -> str:
    """UTC ISO8601 문자열 (Z 포함)"""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def geoip(ip: str):
    target_ip = FORCE_IP or ip
    if not target_ip:
        return {"ip": None, "lat": None, "lon": None, "city": None, "country": None, "asn": None}
    try:
        with urllib.request.urlopen(f"https://ipinfo.io/{target_ip}/json", timeout=HTTP_TIMEOUT) as r:
            j = json.load(r)
        loc = j.get("loc")
        lat = lon = None
        if loc:
            lat, lon = [float(x) for x in loc.split(",")]
        org = j.get("org") or ""   # 예: "AS13335 Cloudflare"
        m = re.search(r"(AS\d+)", (org or "").upper())
        asn = m.group(1) if m else None
        return {"ip": target_ip, "lat": lat, "lon": lon, "city": j.get("city"), "country": j.get("country"), "asn": asn}
    except Exception as e:
        print("geoip fail:", e)
        return {"ip": target_ip, "lat": None, "lon": None, "city": None, "country": None, "asn": None}

# ==============================
# 계정/리전/SG/ARN 추출 유틸
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

def extract_sg(event: dict, payload: dict) -> str:
    for k in ("sg", "security_group", "securityGroupId", "securityGroup"):
        v = payload.get(k)
        if isinstance(v, str) and v.startswith("sg-"):
            return v

    detail = event.get("detail") or {}
    rp = (detail.get("requestParameters") or {})
    relem = (detail.get("responseElements") or {})

    for v in (rp.get("groupId"), relem.get("groupId"), rp.get("securityGroupId")):
        if isinstance(v, str) and v.startswith("sg-"):
            return v

    def _pick_first_sg(obj):
        try:
            if isinstance(obj, dict):
                for val in obj.values():
                    r = _pick_first_sg(val)
                    if r: return r
            elif isinstance(obj, list):
                for val in obj:
                    r = _pick_first_sg(val)
                    if r: return r
            elif isinstance(obj, str) and obj.startswith("sg-"):
                return obj
        except Exception:
            pass
        return ""

    candidates = [
        (rp.get("groupIdSet") or {}), (rp.get("groupSet") or {}),
        (rp.get("groups") or {}), (rp.get("securityGroupIds") or []),
        (rp.get("ipPermissions") or {}),
        (relem.get("groupIdSet") or {}), (relem.get("groupSet") or {}),
        (relem.get("groups") or {}), (relem.get("securityGroupIds") or []),
    ]
    for obj in candidates:
        gid = _pick_first_sg(obj)
        if gid:
            return gid

    try:
        m = _SG_RE.search(json.dumps(event))
        if m:
            return m.group(0)
    except Exception:
        pass
    return ""

# ==============================
# Incident 히스토리 유틸
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
    rand = __import__("random").randint(0, 999)
    return f"{prefix}-{ts}-{rand:03d}"

def put_incident_record(event_type: str,
                        resource: str,
                        severity: str,
                        status: str = "NEW",
                        created_at: str | None = None,
                        details: dict | None = None):
    """
    Incident 테이블에 1건 저장.
    {
      "incident_id": "...",
      "event_type": "...",
      "resource": "...",
      "severity": "LOW|MED|HIGH|CRITICAL",
      "status": "NEW|PROCESSING|MITIGATED|CLOSED",
      "created_at": "...",
      "updated_at": "...",
      "details": { ... 대시보드 포맷 ... }   # ← 필드명 details 로 저장
    }
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
        "severity": sev,
        "status": st,
        "created_at": created,
        "updated_at": created,
    }
    if details is not None:
        item["details"] = details

    try:
        tbl.put_item(Item=item)
        print("✅ Incident stored:", json.dumps(item, ensure_ascii=False))
        return item
    except Exception as e:
        print("incident put fail:", e)
        return None

# ==============================
# 대시보드 스키마 변환 (플랫 구조)
# ==============================
def to_dashboard_event(event, payload) -> dict:
    now_ms = int(time.time() * 1000)
    account_id = extract_account_id(event, payload)
    region = extract_region(event)

    source = payload.get("source") or "AWS CloudTrail"
    etype  = payload.get("event_type") or "Access Key가 이상한 ASN/국가에서 사용"
    sev    = (payload.get("severity") or "HIGH").upper()

    resource = payload.get("resource") or payload.get("principal") or ""
    arn = payload.get("principal") or payload.get("arn") or (event.get("detail", {}).get("userIdentity", {}).get("arn") or "")
    sg  = extract_sg(event, payload)

    meta = dict(payload)
    meta["account_id"] = account_id
    meta["arn"] = arn  # 메타에도 동일하게

    event_obj = {
        "time": now_ms,
        "source": source,
        "type": etype,
        "resource": resource,
        "sg": sg,
        "arn": arn,              # 풀 ARN 그대로 표출
        "account": account_id,
        "region": region,
        "severity": sev,
        "meta": meta
    }

    # Incident가 있으면 incident_id도 포함
    if "incident_id" in payload:
        event_obj["incident_id"] = payload["incident_id"]

    return event_obj

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
# 상태 테이블 키 헬퍼
# ==============================
def _make_key(access_key_id: str):
    key = f"ak#{access_key_id}"
    if STATE_SK_ATTR:
        return {STATE_PK_ATTR: key, STATE_SK_ATTR: "v1"}
    else:
        return {STATE_PK_ATTR: key}

def _make_simple_key(pk: str):
    if STATE_SK_ATTR:
        return {STATE_PK_ATTR: pk, STATE_SK_ATTR: "v1"}
    return {STATE_PK_ATTR: pk}

def get_state_table():
    return ddb_resource().Table(STATE_TABLE)

# ==============================
# 베이스라인 저장/판단 로직
# ==============================
def upsert_baseline_and_check(access_key_id: str, country: str, asn: str, aws_region: str):
    """
    알림 조건:
      - 처음 보는 country/asn/region
      - 과거에 본 적은 있지만, 마지막 본 지 STALE_DAYS일 이상 지난 country/asn/region (재등장)
    저장:
      - countries/asns/regions : Set
      - country_last_seen/asn_last_seen/region_last_seen : {value: epoch_sec}
    """
    t = get_state_table()
    ddb_key = _make_key(access_key_id)
    now = int(time.time())
    stale_sec = STALE_DAYS * 86400

    try:
        res = t.get_item(Key=ddb_key)
        item = res.get("Item")
    except Exception as e:
        print("get_item failed:", e)
        item = None

    # 기존 세트
    already_countries = set(item.get("countries", [])) if item else set()
    already_asns      = set(item.get("asns", [])) if item else set()
    already_regions   = set(item.get("regions", [])) if item else set()

    # 최근 본 시각 맵(없으면 빈 맵)
    country_last_seen = dict(item.get("country_last_seen", {})) if item else {}
    asn_last_seen     = dict(item.get("asn_last_seen", {})) if item else {}
    region_last_seen  = dict(item.get("region_last_seen", {})) if item else {}

    seen_before = (len(already_countries) + len(already_asns) + len(already_regions)) > 0

    def is_new_or_stale(val: str, seen_set: set, last_seen_map: dict) -> (bool, str):
        """return (changed, reason)"""
        if not val:
            return (False, "")
        if val not in seen_set:
            return (True, "new_value")
        # 기존에 봤던 값인데 오래 안 봤다면 stale
        last = int(last_seen_map.get(val, 0) or 0)
        if last and (now - last) >= stale_sec:
            return (True, "stale_revisit")
        return (False, "")

    # 각 축 평가
    c_changed, c_reason = is_new_or_stale(country, already_countries, country_last_seen)
    a_changed, a_reason = is_new_or_stale(asn,     already_asns,      asn_last_seen)
    r_changed, r_reason = is_new_or_stale(aws_region, already_regions, region_last_seen)

    changed = c_changed or a_changed or r_changed
    reason  = c_reason or a_reason or r_reason  # 하나라도 있으면 그걸 대표 reason으로

    # 세트/맵 갱신
    if country:
        already_countries.add(country)
        country_last_seen[country] = now
    if asn:
        already_asns.add(asn)
        asn_last_seen[asn] = now
    if aws_region:
        already_regions.add(aws_region)
        region_last_seen[aws_region] = now

    put_item = dict(ddb_key)
    put_item.update({
        "countries": list(already_countries),
        "asns":      list(already_asns),
        "regions":   list(already_regions),
        "country_last_seen": country_last_seen,
        "asn_last_seen":     asn_last_seen,
        "region_last_seen":  region_last_seen,
        "first_seen": item.get("first_seen", now) if item else now,
        "last_seen":  now,
    })

    try:
        t.put_item(Item=put_item)
    except Exception as e:
        print("put_item failed:", e)

    # 첫 기록은 학습만, 이후에 new/stale이면 알림
    should_alert = (item is not None) and changed and seen_before

    return should_alert, {
        "baseline_countries": list(already_countries),
        "baseline_asns":      list(already_asns),
        "baseline_regions":   list(already_regions),
        "reason":             reason,
        "stale_days":         STALE_DAYS
    }

# ==============================
# (옵션) 중복 알림 억제
# ==============================
def should_suppress(access_key_id: str, country: str, asn: str, aws_region: str) -> bool:
    if SUPPRESS_SECONDS <= 0:
        return False
    t = get_state_table()
    now = int(time.time())
    key = f"suppress#{access_key_id}#{country or '-'}#{asn or '-'}#{aws_region or '-'}"
    k = _make_simple_key(key)
    try:
        res = t.get_item(Key=k)
        item = res.get("Item")
    except Exception as e:
        print("suppress get_item failed:", e)
        item = None

    last_emit = int(item.get("last_emit", 0)) if item else 0
    if last_emit and (now - last_emit) < SUPPRESS_SECONDS:
        return True

    # 갱신
    try:
        t.put_item(Item={**k, "last_emit": now})
    except Exception as e:
        print("suppress put_item failed:", e)
    return False

# ==============================
# Access Key "비정상 위치/ASN/리전" 탐지 (유일한 탐지)
# ==============================
def handle_unusual_accesskey_use(event):
    detail = event.get("detail", {}) or {}
    ui = detail.get("userIdentity", {}) or {}

    # (A) iam 사용자 ARN만 허용. user가 없으면 스킵
    actor_user_arn = _pick_actor_user_arn(ui)
    if not actor_user_arn:
        return _ret({"status": "skip_non_user_principal"})

    # (B) Access Key 없는 이벤트는 제외
    access_key_id = ui.get("accessKeyId")
    if not access_key_id:
        return _ret({"status": "skip_no_access_key"})

    # (C) 위치/ASN/리전 추출
    src_ip = detail.get("sourceIPAddress")
    aws_region = detail.get("awsRegion")
    actor_type = ui.get("type")

    g = geoip(src_ip)
    country = g.get("country")
    asn = g.get("asn")

    # (D) 베이스라인 갱신 및 변동 판단
    should_alert, baseline = upsert_baseline_and_check(access_key_id, country, asn, aws_region)

    # (E) (옵션) 중복 억제 창
    if should_alert and should_suppress(access_key_id, country, asn, aws_region):
        return _ret({"status": "suppressed", "access_key_id": access_key_id})

    when_iso_val = event.get("time") or detail.get("eventTime") or now_iso()

    payload = {
        "alert_type": "access_key_unusual_location",
        "severity": "HIGH" if should_alert else "INFO",
        "source": "AWS CloudTrail",
        "event_type": "Access Key가 이상한 ASN/국가에서 사용",
        "principal": actor_user_arn,   # 대시보드에 보낼 "사용자" 풀 ARN
        "actor_type": actor_type,
        "access_key_id": access_key_id,
        "source_ip": g.get("ip"),
        "country": country,
        "asn": asn,
        "aws_region": aws_region,
        "time": when_iso_val,
        "baseline": baseline,
        "raw_event": detail
    }

    if should_alert:
        # 🔹 Incident details에 넣을 JSON
        account_id = extract_account_id(event, payload)
        sg = extract_sg(event, payload) or ""
        incident_details = {
            "time": when_iso_val,
            "source": "CloudTrail",
            "type": payload["event_type"],
            "sg": sg,
            "arn": actor_user_arn,
            "resource": actor_user_arn,
            "account": account_id,
            "region": aws_region,
            "alertType": "ALERT",
            "rulesViolated": [payload["event_type"]],
            "severity": payload["severity"],
        }

        # 1) Incident 히스토리 기록 (필드명: details)
        incident = put_incident_record(
            event_type=payload["event_type"],
            resource=actor_user_arn,
            severity=payload["severity"],
            status="NEW",
            created_at=when_iso_val,
            details=incident_details
        )
        if incident:
            payload["incident_id"] = incident["incident_id"]

        # 2) 대시보드 알림
        dashboard_event = to_dashboard_event(event, payload)
        post_to_ws_dashboard(dashboard_event)
        return _ret({"status": "alert_sent", "access_key_id": access_key_id, "reason": baseline.get("reason")})
    else:
        return _ret({"status": "learned_or_no_change", "access_key_id": access_key_id})

# ==============================
# Lambda 핸들러
# ==============================
def lambda_handler(event, context):
    try:
        # EventBridge에서 오는 CloudTrail 관리 이벤트만 처리
        if "awslogs" in event:
            return _ret({"status": "skipped_cwlogs"})

        if event.get("detail-type") == "AWS API Call via CloudTrail":
            return handle_unusual_accesskey_use(event)

        return _ret({"status": "noop"})
    except Exception as e:
        print("handler error:", e)
        raise
