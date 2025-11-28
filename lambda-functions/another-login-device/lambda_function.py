# file: lambda_function.py (Python 3.12)
import os
import json
import time
import hashlib
import ipaddress
import boto3
from botocore.exceptions import ClientError
# 👇 Incident 저장용
import random
from datetime import datetime
# 👆 끝

# ====== ENV ======
CONN_TABLE  = os.environ["CONNECTIONS_TABLE"]     # e.g. WebSocketConnections
KNOWN_TABLE = os.environ["KNOWN_DEV_TABLE"]       # e.g. KnownDevices
WS_ENDPOINT = os.environ["WS_ENDPOINT"]           # e.g. https://abcd.execute-api.ap-northeast-2.amazonaws.com/prod
# 👇 Incident 테이블 이름 (환경변수 없으면 기본 'Incident')
INCIDENT_TABLE = os.environ.get("INCIDENT_TABLE", "Incident")
# 👆 끝

# 표시 문자열
SOURCE_NAME       = "AWS SignIn/STS"
UNUSUAL_TYPE_STR  = "새로운 디바이스 접근"

# 지문 모드: UA_ONLY | UA_IP_PREFIX24 | UA_IP
FINGERPRINT_MODE  = os.environ.get("FINGERPRINT_MODE", "UA_ONLY").upper()

# ====== CLIENTS ======
dynamodb    = boto3.resource("dynamodb")
conn_table  = dynamodb.Table(CONN_TABLE)
known_table = dynamodb.Table(KNOWN_TABLE)
apigw       = boto3.client("apigatewaymanagementapi", endpoint_url=WS_ENDPOINT)
# 👇 Incident 테이블 핸들
incident_table = dynamodb.Table(INCIDENT_TABLE)
# 👆 끝

# ====== HELPERS ======
def epoch_ms() -> int:
    return int(time.time() * 1000)

def _normalize_ua(ua: str) -> str:
    """세부 버전/디바이스 모델 제거 후 OS/브라우저 계열만 남김"""
    u = (ua or "").lower()
    if "windows" in u:
        osfam = "windows"
    elif "mac os x" in u or "macintosh" in u:
        osfam = "macos"
    elif "iphone" in u or "ipad" in u or "ios" in u:
        osfam = "ios"
    elif "android" in u:
        osfam = "android"
    elif "linux" in u:
        osfam = "linux"
    else:
        osfam = "other-os"

    if "edg/" in u or " edge/" in u:
        br = "edge"
    elif "chrome/" in u and "safari/" in u:
        br = "chrome"
    elif "safari/" in u and "chrome/" not in u:
        br = "safari"
    elif "firefox/" in u:
        br = "firefox"
    else:
        br = "other-browser"

    return f"{osfam}|{br}"

def _ip_prefix24(ip: str) -> str:
    """IPv4는 /24, IPv6는 /48 수준으로 네트워크만 유지"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.version == 4:
            parts = ip.split(".")
            if len(parts) == 4:
                return ".".join(parts[:3]) + ".0/24"
            return ""
        hextets = ip_obj.exploded.split(":")
        return ":".join(hextets[:3]) + "::/48"
    except Exception:
        return ""

def fingerprint(user_agent: str | None, ip: str | None) -> str:
    """지문 생성 (모드에 따라 UA, IP 조합)"""
    ua_norm = _normalize_ua(user_agent or "")
    mode = FINGERPRINT_MODE
    if mode == "UA_ONLY":
        base = ua_norm
    elif mode == "UA_IP_PREFIX24":
        base = f"{ua_norm}|{_ip_prefix24(ip or '')}"
    else:
        base = f"{ua_norm}|{ip or ''}"
    return hashlib.sha256(base.encode("utf-8")).hexdigest()

def load_known(principal: str) -> list[str]:
    try:
        r = known_table.get_item(Key={"principal": principal})
        return r.get("Item", {}).get("fingerprints", [])
    except ClientError as e:
        print("DDB get_item error:", e)
        return []

def add_known(principal: str, fp: str) -> None:
    try:
        known_table.update_item(
            Key={"principal": principal},
            UpdateExpression="ADD fingerprints :f",
            ExpressionAttributeValues={":f": set([fp])}
        )
    except ClientError as e:
        print("DDB update_item error:", e)

def list_connections() -> list[str]:
    try:
        r = conn_table.scan(ProjectionExpression="connectionId")
        return [i["connectionId"] for i in r.get("Items", [])]
    except ClientError as e:
        print("scan connections error:", e)
        return []

def broadcast(payload: dict) -> None:
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    for cid in list_connections():
        try:
            apigw.post_to_connection(ConnectionId=cid, Data=data)
        except ClientError as e:
            if e.response["Error"]["Code"] == "GoneException":
                try:
                    conn_table.delete_item(Key={"connectionId": cid})
                except Exception:
                    pass
            else:
                print("post_to_connection error:", e)

# ====== Incident 저장 유틸 ======
def generate_incident_id(prefix: str = "inc") -> str:
    """
    예: inc-YYYYMMDD-HHMMSS-XYZ (UTC 기준, 랜덤 3자리)
    """
    ts = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    rand = random.randint(0, 999)
    return f"{prefix}-{ts}-{rand:03d}"

def save_incident_if_needed(evt: dict) -> str | None:
    """
    대시보드 payload(evt)를 Incident 테이블에 저장.
    최소 evt['type']이 있어야 저장. 성공 시 incident_id 반환.
    """
    try:
        event_type = (evt.get("type") or "").strip()
        if not event_type:
            return None

        now_iso = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        incident_id = generate_incident_id()

        item = {
            "incident_id": incident_id,
            "event_type": event_type,
            "resource": evt.get("resource") or "",
            "severity": evt.get("severity", "LOW"),
            "status": "NEW",
            # ✅ meta를 그대로 저장 (device/ip 포함)
            "meta": evt.get("meta") or {},
            "created_at": now_iso,
            "updated_at": now_iso
        }

        if evt.get("account"):
            item["account"] = str(evt["account"])
        if evt.get("region"):
            item["region"] = str(evt["region"])
        if evt.get("source"):
            item["source"] = str(evt["source"])

        incident_table.put_item(Item=item)
        return incident_id
    except Exception as e:
        print("save_incident_if_needed error:", e)
        return None

# ====== ARN RESOLVER ======
def resolve_arn(detail: dict, user_identity: dict, account: str) -> str:
    """
    실패/성공 불문하고 arn을 최대한 채워 넣는다.
    """
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

# ====== PRINCIPAL 표시용 ======
def get_principal_display_and_arn(detail: dict) -> tuple[str, str]:
    """
    handler.py 와 동일한 스타일:
    resource = f"{typ.lower()}/{user or prn or 'unknown'}"
    """
    ui   = detail.get("userIdentity", {}) or {}
    typ  = ui.get("type") or ""
    user = ui.get("userName") or ""
    prn  = ui.get("principalId") or ""

    resource = f"{typ.lower()}/{user or prn or 'unknown'}"

    account = detail.get("recipientAccountId") or ui.get("accountId") or ""
    arn     = resolve_arn(detail, ui, str(account))

    return resource, arn

# ====== BUILDERS ======
def build_consolelogin_payload(detail: dict) -> tuple[dict, str, str, str]:
    """CloudTrail ConsoleLogin/세션 이벤트 전송용 최소 필드 구성"""
    account   = detail.get("recipientAccountId") or detail.get("userIdentity", {}).get("accountId") or ""
    region    = detail.get("awsRegion") or "unknown"
    ui        = detail.get("userIdentity", {}) or {}

    # principal 키(지문 저장용)는 예전과 동일한 기준 유지
    principal = ui.get("arn") or ui.get("principalId") or ui.get("userName") or "unknown"

    ua        = detail.get("userAgent", "") or ""
    ip        = detail.get("sourceIPAddress", "") or ""

    # UA를 정규화해서 디바이스 정보로 사용
    device_str = _normalize_ua(ua)

    # 👉 리소스 표시는 handler.py 와 동일한 포맷 사용
    resource, resolved_arn = get_principal_display_and_arn(detail)

    payload = {
        "time": epoch_ms(),
        "source": SOURCE_NAME,
        "type": UNUSUAL_TYPE_STR,
        "resource": resource,    # ← type/user or principalId 형식
        "sg": "",
        "arn": resolved_arn,
        "account": str(account),
        "region": region,
        "severity": "MEDIUM",
        # ✅ meta 객체로 디바이스/UA/IP 제공 (프런트에서 JSON.parse 불필요)
        "meta": {
            "device": {
                "summary": device_str,  # 예: "windows|chrome"
                "ua": ua                # 원본 UA
            },
            "ip": ip
        },
    }
    return payload, principal, ua, ip

def build_guardduty_payload(event: dict) -> dict:
    d = event.get("detail", {}) or {}
    acct   = d.get("accountId") or "unknown"
    region = d.get("region") or event.get("region") or "unknown"
    ftype  = d.get("type", "GuardDuty")
    sev    = float(d.get("severity", 0))
    inst   = d.get("resource", {}).get("instanceDetails", {}).get("instanceId", "unknown")

    # GuardDuty 는 별도의 device/ip 가 없으므로 service 전체를 meta 로 보냄
    meta = d.get("service") or {}

    return {
        "time": epoch_ms(),
        "source": "GuardDuty",
        "type": ftype,
        "resource": inst,
        "sg": "",
        "arn": d.get("resource", {}).get("resourceArn") or d.get("arn", ""),
        "account": str(acct),
        "region": region,
        "severity": "HIGH" if sev >= 7 else "MEDIUM",
        "meta": meta,
    }

# ====== HANDLER ======
def lambda_handler(event, context):
    src    = (event.get("source") or "").lower()
    dtype  = (event.get("detail-type") or "").lower()
    detail = event.get("detail", {}) or {}

    # GuardDuty 이벤트
    if src.startswith("aws.guardduty") or "guardduty" in dtype:
        gd_payload = build_guardduty_payload(event)
        incident_id = save_incident_if_needed(gd_payload)
        if incident_id:
            gd_payload["incident_id"] = incident_id
        broadcast(gd_payload)
        return {"ok": True, "kind": "guardduty"}

    # ConsoleLogin/STS 등 (새로운 디바이스 접근)
    payload, principal, ua, ip = build_consolelogin_payload(detail)
    fp = fingerprint(ua, ip)
    known = load_known(principal)

    if fp not in known:
        incident_id = save_incident_if_needed(payload)
        if incident_id:
            payload["incident_id"] = incident_id
        broadcast(payload)
        add_known(principal, fp)
        return {"ok": True, "kind": "new_device", "principal": principal, "mode": FINGERPRINT_MODE}

    return {"ok": True, "kind": "known_device", "mode": FINGERPRINT_MODE}
