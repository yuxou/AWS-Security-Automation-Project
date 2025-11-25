# file: lambda_function.py
import os
import json
import time
import urllib.request
import re
import boto3
import random  # ✅ Incident ID 생성용
from botocore.exceptions import ClientError
from datetime import datetime, timezone

# ==============================
# 환경변수
# ==============================
WS_ENDPOINT = os.environ.get("WS_ENDPOINT")  # https://{apiId}.execute-api.{region}.amazonaws.com/{stage}
STATE_TABLE = os.environ.get("STATE_TABLE", "security-alerts-state")
CONNECTIONS_TABLE = os.environ.get("CONNECTIONS_TABLE", "WebSocketConnections")
ACCOUNT_ID_OVERRIDE = os.environ.get("ACCOUNT_ID_OVERRIDE")  # 있으면 이 값이 항상 표시됨
HTTP_TIMEOUT = 8

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


def get_ec2_client(region_hint: str = None):
    region = region_hint or os.environ.get("AWS_REGION") or "us-east-1"
    return boto3.client("ec2", region_name=region)


# ==============================
# 공용 유틸
# ==============================
def _ret(obj: dict):
    print(json.dumps(obj, ensure_ascii=False))
    return obj


def iso_to_epoch_ms(iso_str: str) -> int:
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return int(dt.timestamp() * 1000)
    except Exception:
        return int(time.time() * 1000)


def now_iso() -> str:
    """UTC ISO8601 (Z 포함)"""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def geoip(ip: str):
    try:
        with urllib.request.urlopen(f"https://ipinfo.io/{ip}/json", timeout=HTTP_TIMEOUT) as r:
            j = json.load(r)
        loc = j.get("loc")
        if not loc:
            return {"ip": ip, "lat": None, "lon": None, "city": j.get("city"), "country": j.get("country")}
        lat, lon = [float(x) for x in loc.split(",")]
        return {"ip": ip, "lat": lat, "lon": lon, "city": j.get("city"), "country": j.get("country")}
    except Exception as e:
        print("geoip fail:", e)
        return {"ip": ip, "lat": None, "lon": None}


# ==============================
# 계정ID/리전/SG/ARN 추출
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
    for k in ("sg", "security_group", "securityGroupId"):
        v = payload.get(k)
        if isinstance(v, str) and v.startswith("sg-"):
            return v

    detail = event.get("detail") or {}
    rp = (detail.get("requestParameters") or {})
    relem = (detail.get("responseElements") or {})

    for v in (rp.get("groupId"), relem.get("groupId")):
        if isinstance(v, str) and v.startswith("sg-"):
            return v

    try:
        items = (rp.get("groupSet") or {}).get("items") or []
        for it in items:
            gid = it.get("groupId")
            if isinstance(gid, str) and gid.startswith("sg-"):
                return gid
    except Exception:
        pass

    try:
        perms = (rp.get("ipPermissions") or {}).get("items") or []
        for p in perms:
            groups = (p.get("groups") or {}).get("items") or []
            for g in groups:
                gid = g.get("groupId")
                if isinstance(gid, str) and gid.startswith("sg-"):
                    return gid
    except Exception:
        pass

    try:
        groups = (rp.get("groups") or {}).get("items") or []
        for g in groups:
            gid = g.get("groupId")
            if isinstance(gid, str) and gid.startswith("sg-"):
                return gid
    except Exception:
        pass

    try:
        m = _SG_RE.search(json.dumps(event))
        if m:
            return m.group(0)
    except Exception:
        pass
    return ""


def enrich_sg_with_lookup(event: dict, sg_now: str, region_hint: str) -> str:
    if sg_now:
        return sg_now

    detail = event.get("detail") or {}
    rp = (detail.get("requestParameters") or {})
    instance_id = rp.get("instanceId")
    eni_id = rp.get("networkInterfaceId")

    ec2 = get_ec2_client(region_hint)

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


# ==============================
# Incident 히스토리 유틸
# ==============================
def incident_table():
    if not INCIDENT_TABLE:
        return None
    return ddb_resource().Table(INCIDENT_TABLE)


def generate_incident_id(prefix: str = "INC") -> str:
    """
    예: INC-YYYYMMDD-HHMMSS-123
    """
    ts = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    rand = random.randint(0, 999)
    return f"{prefix}-{ts}-{rand:03d}"


def put_incident_record(
    event_type: str,
    resource: str,
    severity: str,
    status: str = "NEW",
    created_at: str | None = None,
    account: str | None = None,
    region: str | None = None,
    details: dict | None = None,
    meta: dict | None = None,
):
    """
    Incident 테이블에 1건 저장.
    + account, region, details(JSON string), meta 까지 같이 저장
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

    if account:
        item["account"] = account
    if region:
        item["region"] = region

    if details:
        # ✅ 기존 details는 그대로 JSON 문자열로 저장
        try:
            item["details"] = json.dumps(details, ensure_ascii=False)
        except TypeError:
            # 혹시 직렬화 안 되는 값이 섞여 있어도 안전하게 저장
            item["details"] = json.dumps({"raw": str(details)}, ensure_ascii=False)

    if meta:
        # ✅ meta 필드에 디바이스/IP/액세스키 상세 저장
        item["meta"] = meta

    try:
        tbl.put_item(Item=item)
        print("✅ Incident stored:", json.dumps(item, ensure_ascii=False))
        return item
    except Exception as e:
        print("incident put fail:", e)
        return None


# ==============================
# meta 생성 유틸 (디바이스/IP/액세스 키)
# ==============================
def _normalize_ua(ua: str) -> str:
    """
    UA를 간단한 OS/브라우저 조합으로 정규화 (예: windows|chrome)
    """
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


def _build_common_meta(detail: dict) -> dict:
    """
    공통 meta 구성:
    - device: summary + 원본 UA
    - ip: sourceIPAddress
    - api: eventName
    - accessKey: (액세스 키 관련 이벤트일 때)
        - owner_type: Root / IAMUser / AssumedRole ...
        - owner: 어떤 계정/사용자의 키인지 (userName 등)
        - access_key_id: 생성/변경/삭제 대상 키 ID
        - status: Active / Inactive (있는 경우)
        - event_name: CreateAccessKey / UpdateAccessKey / DeleteAccessKey
    """
    ua = detail.get("userAgent") or ""
    ip = detail.get("sourceIPAddress") or ""
    event_name = detail.get("eventName") or ""

    device_summary = _normalize_ua(ua) if ua else ""

    meta: dict = {}

    if ua or device_summary:
        meta["device"] = {
            "summary": device_summary,  # 예: "windows|chrome"
            "ua": ua,  # 원본 UA
        }
    if ip:
        meta["ip"] = ip

    if event_name:
        meta["api"] = event_name

    # 액세스 키 상세 정보
    params = detail.get("requestParameters", {}) or {}
    resp = detail.get("responseElements", {}) or {}
    ui = detail.get("userIdentity", {}) or {}

    if event_name in ("CreateAccessKey", "UpdateAccessKey", "DeleteAccessKey"):
        ak_meta: dict = {}

        owner_type = ui.get("type")
        owner_name = params.get("userName") or ui.get("userName")
        if owner_type == "Root":
            owner_name = "RootAccount"

        if owner_type:
            ak_meta["owner_type"] = owner_type
        if owner_name:
            ak_meta["owner"] = owner_name

        access_key_id = None
        status = None

        # CreateAccessKey 응답: responseElements.accessKey.accessKeyId / status
        ak_block = resp.get("accessKey")
        if isinstance(ak_block, dict):
            access_key_id = ak_block.get("accessKeyId") or access_key_id
            status = ak_block.get("status") or status

        # Update/Delete 경우: requestParameters.accessKeyId 에 있을 수 있음
        if not access_key_id:
            access_key_id = params.get("accessKeyId")

        if access_key_id:
            ak_meta["access_key_id"] = access_key_id
        if status:
            ak_meta["status"] = status

        ak_meta["event_name"] = event_name  # 어떤 액세스 키 조작인지

        if ak_meta:
            meta["accessKey"] = ak_meta

    return meta


# ==============================
# 대시보드 스키마(새 형식) 변환
# ==============================
def to_dashboard_event(event, payload) -> dict:
    when_ms = int(time.time() * 1000)
    when_iso = event.get("time") or (event.get("detail") or {}).get("eventTime")
    if when_iso:
        when_ms = iso_to_epoch_ms(when_iso)

    account_id = extract_account_id(event, payload)
    region = extract_region(event)

    source = payload.get("source") or "AWS"
    etype = payload.get("event_type") or (event.get("detail-type") or "Unknown")
    resource = payload.get("resource") or payload.get("principal") or ""

    sg = enrich_sg_with_lookup(event, extract_sg(event, payload), region)

    arn_full = payload.get("principal") or payload.get("arn") or ""
    sev = (payload.get("severity") or "HIGH").upper()

    event_obj = {
        "time": when_ms,
        "source": source,
        "type": etype,
        "resource": resource,
        "sg": sg,
        "arn": arn_full,
        "account": account_id,
        "region": region,
        "severity": sev,
    }

    incident_id = payload.get("incident_id")
    if incident_id:
        event_obj["incident_id"] = incident_id

    # ✅ meta도 대시보드 payload에 포함 → 인시던트 상세에서 추가 데이터(JSON)로 보임
    meta = payload.get("meta")
    if meta:
        event_obj["meta"] = meta

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

        for it in (resp.get("Items") or []):
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
# Access Key 생성 이벤트 처리
# ==============================
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

    # ✅ 공통 meta (디바이스, IP, 액세스 키 상세)
    meta = _build_common_meta(detail)

    payload = {
        "alert_type": "access_key_created",
        "severity": "HIGH",
        "source": "AWS IAM",
        "event_type": "액세스 키 생성",
        "principal": user_arn,
        "resource": user_arn,
        "actor_type": user_type,
        "principal_id": principal,
        "source_ip": src_ip,
        "user_agent": user_agent,
        "meta": meta,  # ✅ payload에 meta 포함
    }

    # 🔹 Incident details용 필드 준비 (기존 구조 유지)
    account_id = extract_account_id(event, payload)
    region = extract_region(event)

    details = {
        "time": when_iso_val,
        "source": "IAM",
        "type": payload["event_type"],
        "sg": "",  # AccessKey는 SG 없음
        "arn": user_arn,
        "resource": user_arn,
        "account": account_id,
        "region": region,
        "alertType": "ALERT",
        "rulesViolated": ["액세스 키 생성"],
        "severity": payload["severity"],
    }

    # 🔹 Incident 히스토리 기록 (account/region/details + meta 같이 저장)
    incident = put_incident_record(
        event_type=payload["event_type"],
        resource=user_arn,
        severity=payload["severity"],
        status="NEW",
        created_at=when_iso_val,
        account=account_id,
        region=region,
        details=details,
        meta=meta,  # ✅ Incident 테이블에도 meta 저장
    )
    if incident:
        payload["incident_id"] = incident["incident_id"]

    dashboard_event = to_dashboard_event(event, payload)
    post_to_ws_dashboard(dashboard_event)
    return _ret({"status": "alert_sent", "access_key_id": access_key_id})


# ==============================
# Lambda 핸들러
# ==============================
def lambda_handler(event, context):
    try:
        if "awslogs" in event:
            return _ret({"status": "skipped_cwlogs"})

        if event.get("source") == "aws.iam" and event.get("detail-type") == "AWS API Call via CloudTrail":
            return handle_access_key_created(event)

        return _ret({"status": "noop"})
    except Exception as e:
        print("handler error:", e)
        raise

