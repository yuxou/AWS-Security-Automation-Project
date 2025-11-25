# file: broadcaster.py  (Python 3.12)
import os
import json
import time
from datetime import datetime
import ipaddress
import urllib.request
from urllib.error import URLError, HTTPError
from decimal import Decimal


import boto3
from botocore.exceptions import ClientError
import random

# ===== Env =====
TABLE_NAME = os.environ["TABLE_NAME"]
# 원본 WS 엔드포인트를 먼저 읽고, 스킴이 없으면 보정
_WS_ENDPOINT_RAW = os.environ["WS_ENDPOINT"]
if not _WS_ENDPOINT_RAW.startswith("http"):
    WS_ENDPOINT = f"https://{_WS_ENDPOINT_RAW}"
else:
    WS_ENDPOINT = _WS_ENDPOINT_RAW

INCIDENT_TABLE = os.environ.get("INCIDENT_TABLE", "Incident")

# ===== AWS clients =====
dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table(TABLE_NAME)
apigw = boto3.client("apigatewaymanagementapi", endpoint_url=WS_ENDPOINT)

# 👇 Incident 테이블 핸들
incident_table = dynamodb.Table(INCIDENT_TABLE)
# 👆 끝

# ===== Helpers =====
def _to_dynamodb_compatible(value):
    """
    DynamoDB에 넣기 전에 float -> Decimal 로 바꾸는 헬퍼.
    dict / list 안에 중첩된 값까지 모두 변환.
    """
    if isinstance(value, float):
        return Decimal(str(value))
    if isinstance(value, list):
        return [_to_dynamodb_compatible(v) for v in value]
    if isinstance(value, dict):
        return {k: _to_dynamodb_compatible(v) for k, v in value.items()}
    return value

def epoch_ms_from_iso(s: str | None) -> int:
    if not s:
        return int(time.time() * 1000)
    try:
        return int(datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp() * 1000)
    except Exception:
        try:
            v = int(float(s))
            return v if v > 10**12 else v * 1000
        except Exception:
            return int(time.time() * 1000)

def generate_incident_id(prefix: str = "inc") -> str:
    """예: inc-20251119-153045-123 (UTC 기준 + 3자리 난수)"""
    ts = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    rand = random.randint(0, 999)
    return f"{prefix}-{ts}-{rand:03d}"

def save_incident_if_needed(evt: dict) -> str | None:
    """
    evt(type 등)을 보고 Incident 저장. 저장 시 incident_id 리턴.
    """
    try:
        event_type = (evt.get("type") or "").strip()
        if not event_type:
            return None

        now_iso = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        incident_id = generate_incident_id()

        # 첫 번째 함수(_save_incident_for_iam_event) 방식과 동일하게 필드 구성
        incident_meta = evt.get("meta")  # ConsoleLogin 쪽에서 만든 meta 그대로 사용

        item = {
            "incident_id": incident_id,
            "event_type": event_type,
            "resource": evt.get("resource") or "",
            "severity": evt.get("severity") or "LOW",
            "status": "NEW",                          # 인시던트 상태
            "meta": incident_meta or {},              # incident_details 대신 meta 사용
            "source": evt.get("source") or "",
            "account": str(evt.get("account") or ""),
            "region": str(evt.get("region") or ""),
            "created_at": now_iso,
            "updated_at": now_iso,
        }

        # float → Decimal 변환(기존 로직 유지: geo.lat/lon 등)
        item = _to_dynamodb_compatible(item)

        incident_table.put_item(Item=item)
        return incident_id

    except Exception as e:
        print("save_incident_if_needed error:", e)
        return None


def build_severity(success: bool, user_type: str, mfa_used: str) -> str:
    if not success and (mfa_used or "").lower() in ("no", "false", "0", ""):
        return "HIGH"
    if not success:
        return "MEDIUM"
    return "LOW"

def resolve_arn(detail: dict, user_identity: dict, account: str) -> str:
    arn = (user_identity.get("arn") or "").strip()
    if arn:
        return arn

    utype = (user_identity.get("type") or "").strip()
    uname = (user_identity.get("userName") or "").strip()
    pid   = (user_identity.get("principalId") or "").strip()

    if utype == "IAMUser" and uname:
        return f"arn:aws:iam::{account}:user/{uname}"
    if utype == "Root":
        return f"arn:aws:iam::{account}:root"

    sess_issuer = ((user_identity.get("sessionContext") or {}).get("sessionIssuer") or {})
    issuer_arn = (sess_issuer.get("arn") or "").strip()
    if issuer_arn:
        return issuer_arn

    if pid:
        return f"arn:aws:iam::{account}:principal/{pid}"

    req = (detail.get("requestParameters") or {})
    req_uname = (req.get("userName") or req.get("username") or "").strip()
    if req_uname:
        return f"arn:aws:iam::{account}:user/{req_uname}"

    return f"arn:aws:iam::{account}:unknown"

def _is_public_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip.split("%")[0])
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved)
    except Exception:
        return False

def _normalize_ipv6_mapped(ip: str) -> str:
    return ip.split("::ffff:")[-1] if ip.startswith("::ffff:") else ip

def ip_geo_lookup(ip: str, lang: str = "ko", timeout: float = 2.5) -> dict:
    if not ip:
        return {}
    ip = _normalize_ipv6_mapped(ip)
    if not _is_public_ip(ip):
        return {}

    url = f"http://ip-api.com/json/{ip}?lang={lang}&fields=status,country,countryCode,regionName,city,lat,lon,query"
    req = urllib.request.Request(url, headers={"User-Agent": "lambda-geo-lookup/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
            data = json.loads(raw or "{}")
    except (URLError, HTTPError, TimeoutError, ValueError) as e:
        print(f"[geo] lookup error for {ip}: {e}")
        return {}

    if data.get("status") != "success":
        return {}

    return {
        "ip": data.get("query"),
        "country": data.get("country"),
        "countryCode": data.get("countryCode"),
        "region": data.get("regionName"),
        "city": data.get("city"),
        "lat": data.get("lat"),
        "lon": data.get("lon"),
    }

def extract_login_fields(detail: dict) -> dict:
    result = ((detail.get("responseElements") or {}).get("ConsoleLogin") or "").title()
    success = (result == "Success")

    user_identity = detail.get("userIdentity") or {}
    account = detail.get("recipientAccountId") or user_identity.get("accountId") or ""
    region = detail.get("awsRegion") or "us-east-1"

    resource = (
        user_identity.get("userName")
        or (user_identity.get("sessionContext") or {}).get("sessionIssuer", {}).get("userName")
        or user_identity.get("principalId")
        or ""
    )

    add = detail.get("additionalEventData") or {}
    mfa_used = add.get("MFAUsed", "")
    user_type = user_identity.get("type", "")

    arn = resolve_arn(detail, user_identity, account)

    source_label = "AWS-SignIn/STS"
    type_label = "콘솔 로그인: 성공" if success else "콘솔 로그인: 실패"

    payload = {
        "time": epoch_ms_from_iso(detail.get("eventTime")),
        "source": source_label,
        "type": type_label,
        "resource": str(resource),
        "sg": "",
        "arn": str(arn),
        "account": str(account),
        "region": str(region),
        "severity": build_severity(success, user_type, mfa_used),
    }

    ua = (detail.get("userAgent") or "").strip()
    ip = (detail.get("sourceIPAddress") or "").strip()

    meta = {}
    if ua:
        meta["device"] = {"ua": ua}
    if ip:
        meta["ip"] = _normalize_ipv6_mapped(ip)
        geo = ip_geo_lookup(ip, lang="ko", timeout=2.5)
        if geo:
            meta["geo"] = {
                "country": geo.get("country"),
                "countryCode": geo.get("countryCode"),
                "region": geo.get("region"),
                "city": geo.get("city"),
                "lat": geo.get("lat"),
                "lon": geo.get("lon"),
            }

    city          = (add.get("City") or add.get("city") or "").strip()
    country       = (add.get("Country") or add.get("country") or "").strip()
    country_code  = (add.get("CountryCode") or add.get("countryCode") or add.get("ISO2CountryCode") or "").strip()
    signin_region = (add.get("SigninRegion") or add.get("signInRegion") or add.get("Region") or "").strip()
    new_device    = (add.get("NewDeviceUsed") or add.get("newDeviceUsed") or add.get("NewDevice") or "").strip()

    if city or country or country_code or signin_region:
        meta.setdefault("geo", {})
        if city:          meta["geo"].setdefault("city", city)
        if country:       meta["geo"].setdefault("country", country)
        if country_code:  meta["geo"].setdefault("countryCode", country_code)
        if signin_region: meta["geo"].setdefault("signinRegion", signin_region)

    if new_device:
        meta["newDeviceUsed"] = new_device

    if user_type:
        meta["userType"] = user_type
    if user_type == "Root":
        meta["isRoot"] = True
    if mfa_used != "":
        meta["mfaUsed"] = mfa_used

    err = (detail.get("errorMessage") or "").strip()
    if err:
        meta["errorMessage"] = err

    if meta:
        payload["meta"] = meta

    return payload

def post_to_all(payload: dict):
    """
    현재 연결된 모든 WebSocket connectionId에 payload 브로드캐스트
    - Gone/LimitExceeded 에러 시 connection 정리
    """
    scan_kwargs = {}
    while True:
        resp = table.scan(**scan_kwargs)
        items = resp.get("Items", [])
        for it in items:
            conn_id = it.get("connectionId")
            if not conn_id:
                continue
            try:
                apigw.post_to_connection(
                    ConnectionId=conn_id,
                    Data=json.dumps(payload, ensure_ascii=False).encode("utf-8")
                )
            except ClientError as e:
                code = e.response["Error"]["Code"]
                print(f"post_to_connection error({code}) for {conn_id}")
                if code in ("GoneException", "LimitExceededException"):
                    # 연결이 끊긴 항목 정리(원하면 주석 해제)
                    # try:
                    #     table.delete_item(Key={"connectionId": conn_id})
                    # except Exception:
                    #     pass
                    pass  # ← 빈 블록 방지
                else:
                    # 다른 오류는 그대로 로그만 남긴다.
                    pass

        last = resp.get("LastEvaluatedKey")
        if not last:
            break
        scan_kwargs["ExclusiveStartKey"] = last

# ===== Lambda entry =====
def lambda_handler(event, context):
    """
    EventBridge가 전달하는 ConsoleLogin 이벤트(단건/배열/Records 래핑) 처리
    """
    candidates = []
    if isinstance(event, dict) and "detail" in event:
        candidates = [event]
    elif isinstance(event, dict) and "Records" in event:
        candidates = [r for r in event["Records"] if isinstance(r, dict) and "detail" in r]
    elif isinstance(event, list):
        candidates = [e for e in event if isinstance(e, dict) and "detail" in e]
    else:
        print("Unknown event shape:", json.dumps(event)[:2000])
        return {"statusCode": 200}

    processed = 0
    for ev in candidates:
        detail_type = ev.get("detail-type") or ev.get("detailType") or ""
        detail = ev.get("detail") or {}
        event_name = (detail.get("eventName") or "").strip()

        if event_name != "ConsoleLogin":
            print(f"Skip eventName={event_name} detail-type={detail_type}")
            continue

        payload = extract_login_fields(detail)
        print("=== ConsoleLogin Payload ===", json.dumps(payload, ensure_ascii=False))

        incident_id = save_incident_if_needed(payload)
        if incident_id:
            payload["incident_id"] = incident_id

        post_to_all(payload)
        processed += 1

    if processed == 0:
        print("No ConsoleLogin records processed.")

    return {"statusCode": 200}
