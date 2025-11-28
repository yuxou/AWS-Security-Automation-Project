# file: handler.py (Python 3.12)
import os, json, time, ipaddress, hashlib, random
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Tuple
import boto3
from botocore.exceptions import ClientError

# ===== env =====
CONNECTIONS_TABLE = os.environ["CONNECTIONS_TABLE"]   # e.g. WebSocketConnections
WS_ENDPOINT       = os.environ["WS_ENDPOINT"]         # e.g. https://<apiId>.execute-api.us-east-1.amazonaws.com/prod
KNOWN_TABLE       = os.environ["KNOWN_TABLE"]         # e.g. KnownIps
WINDOW_DAYS       = int(os.getenv("WINDOW_DAYS", "30"))
ALLOW_CIDRS_RAW   = os.getenv("ALLOW_CIDRS", "").strip()
SCOPE             = os.getenv("SCOPE", "principal").lower()  # principal | account | global

# Incident 테이블 이름 (환경변수 없으면 기본 'Incident')
INCIDENT_TABLE    = os.environ.get("INCIDENT_TABLE", "Incident")

# ===== clients =====
dynamodb    = boto3.resource("dynamodb")
conn_table  = dynamodb.Table(CONNECTIONS_TABLE)
known_table = dynamodb.Table(KNOWN_TABLE)
apigw       = boto3.client("apigatewaymanagementapi", endpoint_url=WS_ENDPOINT)
incident_table = dynamodb.Table(INCIDENT_TABLE)

# ===== allowlist nets =====
_ALLOW_NETS: list[ipaddress._BaseNetwork] = []
if ALLOW_CIDRS_RAW:
    for c in ALLOW_CIDRS_RAW.split(","):
        c = c.strip()
        if c:
            _ALLOW_NETS.append(ipaddress.ip_network(c, strict=False))

# ===== resolve arn =====
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

# ===== helpers =====
def _in_allowlist(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return any(ip_obj in n for n in _ALLOW_NETS)
    except Exception:
        return False

def _epoch_ms(dt_iso: str | None) -> int:
    if not dt_iso:
        return int(time.time() * 1000)
    try:
        return int(datetime.fromisoformat(dt_iso.replace("Z","+00:00")).timestamp() * 1000)
    except Exception:
        return int(time.time() * 1000)

def _normalize_ua(ua: str) -> str:
    """OS/브라우저 계열만 추출 (핸들러/Incident 공통 사용)"""
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

# ===== stable principal & scope =====
def _stable_principal(detail: Dict[str, Any]) -> str:
    ui  = (detail.get("userIdentity") or {})
    typ = ui.get("type") or ""
    if typ == "AssumedRole":
        issuer = ((ui.get("sessionContext") or {}).get("sessionIssuer") or {})
        return issuer.get("arn") or ui.get("arn") or ui.get("principalId") or "assumedrole/unknown"
    if typ == "IAMUser":
        return ui.get("arn") or ui.get("userName") or ui.get("principalId") or "iamuser/unknown"
    if typ == "Root":
        acct = detail.get("recipientAccountId") or ui.get("accountId") or "unknown"
        return f"arn:aws:iam::{acct}:root"
    return ui.get("arn") or ui.get("principalId") or "principal/unknown"

def _scope_pk(account: str, detail: Dict[str, Any]) -> str:
    if SCOPE == "global":
        return "global#all"
    if SCOPE == "account":
        return f"acct#{account}"
    # default: principal
    return f"user#{account}#{_stable_principal(detail)}"

# ===== presentation helpers =====
def _get_principal_display_and_arn(detail: Dict[str, Any]) -> Tuple[str, str]:
    """
    resource = f"{typ.lower()}/{user or prn or 'unknown'}"
    (lambda_function.py 와 동일 스타일)
    """
    ui = detail.get("userIdentity", {}) or {}
    typ = ui.get("type") or ""
    user= ui.get("userName") or ""
    prn = ui.get("principalId") or ""
    resource = f"{typ.lower()}/{user or prn or 'unknown'}"
    account  = str(detail.get("recipientAccountId","") or ui.get("accountId",""))
    arn = resolve_arn(detail, ui, account)
    return resource, arn

def _build_severity(unusual: bool, detail: Dict[str, Any]) -> str:
    mfa     = (detail.get("additionalEventData",{}) or {}).get("MFAUsed","No")
    root    = (detail.get("userIdentity",{}) or {}).get("type") == "Root"
    success = (detail.get("responseElements",{}) or {}).get("ConsoleLogin","Unknown") == "Success"
    if not unusual:
        return "LOW"
    if root and success and mfa != "Yes":
        return "CRITICAL"
    if success and mfa != "Yes":
        return "HIGH"
    return "MEDIUM"

def _localize_type(event_name: str) -> str:
    mapping = {
        "ConsoleLogin": "새로운 IP로 로그인 접근",
        "AssumeRole":   "새로운 IP로 역할 전환 접근",
    }
    return mapping.get(event_name or "Unknown", "새로운 IP로 알 수 없음 접근")

def _standard_source(event_src: str) -> str:
    if event_src == "signin.amazonaws.com":
        return "AWS SignIn/STS"
    if event_src == "sts.amazonaws.com":
        return "AWS SignIn/STS"
    return event_src or "aws"

def _make_msg_id(detail: Dict[str, Any]) -> str:
    ui = detail.get("userIdentity", {}) or {}
    principal = ui.get("arn") or ui.get("principalId") or ui.get("userName") or "unknown"
    base = "|".join([
        str(detail.get("recipientAccountId") or ui.get("accountId") or ""),
        principal,
        detail.get("eventName",""),
        detail.get("awsRegion",""),
        detail.get("sourceIPAddress","") or "",
        detail.get("eventID",""),
    ])
    return hashlib.sha1(base.encode("utf-8")).hexdigest()

# ===== payload =====
def _build_payload(detail: Dict[str, Any], unusual: bool) -> Dict[str, Any]:
    event_time = detail.get("eventTime")
    event_src  = detail.get("eventSource","")
    event_name = detail.get("eventName","")
    account    = str(detail.get("recipientAccountId","") or (detail.get("userIdentity",{}) or {}).get("accountId",""))
    region     = detail.get("awsRegion","")
    src_ip     = detail.get("sourceIPAddress","") or ""   # meta.ip

    resource, arn = _get_principal_display_and_arn(detail)
    source        = _standard_source(event_src)
    typ           = _localize_type(event_name)
    severity      = _build_severity(unusual, detail)

    payload = {
        "time": _epoch_ms(event_time),
        "source": source,
        "type": typ,
        "resource": resource,
        "sg": "",
        "arn": arn,
        "account": account,
        "region": region,
        "severity": severity,
        "msgId": _make_msg_id(detail),
        "emittedAt": int(time.time() * 1000),
        # 기본 meta: ip만 포함 (대시보드용)
        "meta": {"ip": src_ip},
    }
    return payload

# ===== NEW: atomic check + safe path for lastSeen =====
def _sanitize_ip_key(ip: str) -> str:
    return ("ip#" + ip.replace(".", "_").replace(":", "_"))[:100]

def _mark_and_is_new_ip(account: str, detail: Dict[str, Any], ip: str) -> Tuple[bool, str]:
    if not ip:
        return False, "no-ip"
    if _in_allowlist(ip):
        return False, "allowlist"

    pk    = _scope_pk(account, detail)
    now   = int(time.time())
    ttl   = int((datetime.now(timezone.utc) + timedelta(days=WINDOW_DAYS)).timestamp())
    ipkey = _sanitize_ip_key(ip)

    def ensure_lastseen_map():
        try:
            known_table.update_item(
                Key={"pk": pk},
                UpdateExpression="SET #ls = if_not_exists(#ls, :empty)",
                ExpressionAttributeNames={"#ls": "lastSeen"},
                ExpressionAttributeValues={":empty": {}},
            )
        except ClientError:
            pass

    try:
        known_table.update_item(
            Key={"pk": pk},
            UpdateExpression="ADD #ips :ipset SET #u=:u, #e=:e",
            ConditionExpression="attribute_not_exists(#ips) OR NOT contains(#ips, :ipval)",
            ExpressionAttributeNames={
                "#ips": "ips", "#u": "updatedAt", "#e": "expiresAt",
            },
            ExpressionAttributeValues={
                ":ipset": {ip}, ":ipval": ip, ":u": now, ":e": ttl,
            },
        )
        ensure_lastseen_map()
        known_table.update_item(
            Key={"pk": pk},
            UpdateExpression="SET #ls.#k = :u",
            ExpressionAttributeNames={"#ls": "lastSeen", "#k": ipkey},
            ExpressionAttributeValues={":u": now},
        )
        print(f"NEW-IP pk={pk} ip={ip}")
        return True, "new"

    except ClientError as e:
        if e.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            ensure_lastseen_map()
            try:
                known_table.update_item(
                    Key={"pk": pk},
                    UpdateExpression="SET #u=:u, #e=:e, #ls.#k=:u",
                    ExpressionAttributeNames={
                        "#u": "updatedAt", "#e": "expiresAt",
                        "#ls": "lastSeen", "#k": ipkey,
                    },
                    ExpressionAttributeValues={":u": now, ":e": ttl},
                )
            except ClientError:
                pass
            print(f"SEEN-IP pk={pk} ip={ip}")
            return False, "seen"
        else:
            print(f"DDB-ERROR pk={pk} ip={ip} err={e}")
            return False, "ddb-error"

# ===== Incident 저장 관련 유틸 =====
def _generate_incident_id(prefix: str = "inc") -> str:
    """
    예: inc-YYYYMMDD-HHMMSS-XYZ (UTC 기준, 랜덤 3자리)
    """
    ts = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    rand = random.randint(0, 999)
    return f"{prefix}-{ts}-{rand:03d}"

def _save_incident_for_new_ip(detail: Dict[str, Any], payload: Dict[str, Any]) -> str | None:
    """
    새로운 IP 로그인 이벤트(payload)를 Incident 테이블에 저장.
    lambda_function.py처럼 incident_details 없이 meta에 디바이스/IP 저장.
    """
    try:
        event_type = (payload.get("type") or "").strip()
        if not event_type:
            return None

        # CloudTrail 원본에서 UA 가져와서 디바이스 정보 생성
        ua = detail.get("userAgent", "") or ""
        device_summary = _normalize_ua(ua) if ua else ""

        # payload.meta(ip 포함)를 기반으로 Incident용 meta를 구성
        base_meta = payload.get("meta") or {}
        meta: Dict[str, Any] = dict(base_meta)  # 원본 payload는 건드리지 않도록 복사

        if ua or device_summary:
            meta["device"] = {
                "summary": device_summary,  # 예: "windows|chrome"
                "ua": ua,                   # 원본 UA
            }

        now_iso = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        incident_id = _generate_incident_id()

        item: Dict[str, Any] = {
            "incident_id": incident_id,
            "event_type": event_type,
            "resource": payload.get("resource") or "",
            "severity": payload.get("severity") or "LOW",
            "status": "NEW",
            # lambda_function.py와 동일하게 meta에만 저장
            "meta": meta,
            "source": payload.get("source") or "",
            "account": payload.get("account") or "",
            "region": payload.get("region") or "",
            "created_at": now_iso,
            "updated_at": now_iso,
        }

        incident_table.put_item(Item=item)
        return incident_id
    except Exception as e:
        print(f"save_incident_for_new_ip error: {e}")
        return None

# ===== websocket broadcast =====
def _broadcast_to_ws(payload: Dict[str, Any]) -> None:
    scan_kwargs: Dict[str, Any] = {}
    while True:
        resp = conn_table.scan(**scan_kwargs)
        items = resp.get("Items", [])
        for it in items:
            cid = it.get("connectionId")
            if not cid:
                continue
            try:
                apigw.post_to_connection(
                    ConnectionId=cid,
                    Data=json.dumps(payload, ensure_ascii=False).encode("utf-8")
                )
            except apigw.exceptions.GoneException:
                try:
                    conn_table.delete_item(Key={"connectionId": cid})
                except ClientError:
                    pass
            except Exception:
                pass
        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        scan_kwargs["ExclusiveStartKey"] = lek

# ===== lambda entry =====
def handler(event, context):
    try:
        print(json.dumps(event, indent=2, ensure_ascii=False))
    except Exception as e:
        print(f"event dump failed: {e}")

    detail     = event.get("detail", {}) or {}
    event_src  = detail.get("eventSource","")
    event_name = detail.get("eventName","")
    src_ip     = detail.get("sourceIPAddress","") or ""

    # 관심 이벤트만 처리
    if (event_src, event_name) not in {
        ("signin.amazonaws.com", "ConsoleLogin"),
        ("sts.amazonaws.com",    "AssumeRole"),
    }:
        return {"ignored": True, "reason": "event-not-interest"}

    account = str(detail.get("recipientAccountId","") or (detail.get("userIdentity",{}) or {}).get("accountId",""))

    # 새로운 IP만 처리
    is_new, reason = _mark_and_is_new_ip(account, detail, src_ip)
    if not is_new:
        print(f"skip broadcast: {reason} ip={src_ip}")
        return {"ok": True, "new_ip": False, "reason": reason}

    payload = _build_payload(detail, unusual=True)

    # Incident 테이블에 저장 (incident_details 없이 meta에 디바이스+IP 저장)
    incident_id = _save_incident_for_new_ip(detail, payload)
    if incident_id:
        payload["incident_id"] = incident_id

    stamp = f"{int(time.time()*1000)}-{account}"
    print(f"WS-BROADCAST {stamp} 새로운 IP로 로그인 접근 -> start")
    _broadcast_to_ws(payload)
    print(f"WS-BROADCAST {stamp} done")
    return {"ok": True, "new_ip": True}
