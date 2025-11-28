import os, json, time, urllib.request, re, boto3, random
from botocore.exceptions import ClientError
from decimal import Decimal
from datetime import datetime

# ---------- JSON 직렬화 보조 ----------
def _json_safe(x):
    if isinstance(x, Decimal):
        return int(x) if x % 1 == 0 else float(x)
    if isinstance(x, dict):
        return {k: _json_safe(v) for k, v in x.items()}
    if isinstance(x, (list, tuple, set)):
        return [_json_safe(v) for v in x]
    return x

# ---------- 환경변수 ----------
WS_ENDPOINT        = os.environ.get("WS_ENDPOINT")
STATE_TABLE        = os.environ.get("STATE_TABLE", "security-alerts-state-v2")
CONNECTIONS_TABLE  = os.environ.get("CONNECTIONS_TABLE", "WebSocketConnections")
ACCOUNT_ID_OVERRIDE= os.environ.get("ACCOUNT_ID_OVERRIDE")
STATE_PK           = os.environ.get("STATE_PK", "id")
HTTP_TIMEOUT       = 8

# 🔹 Incident 테이블
INCIDENT_TABLE     = os.environ.get("INCIDENT_TABLE", "Incident")

# 상관관계 윈도(초) – 현재 SG 마커 방식은 사용 안 하지만 남겨둠
CORRELATION_TTL_SECONDS = int(os.environ.get("CORRELATION_TTL_SECONDS", "600"))

# 이벤트 시간 사용 방식: "0"이면 현재시간 사용
USE_EVENT_TIME = os.environ.get("USE_EVENT_TIME", "1")

# 호환 포맷 전송 옵션 (대시보드 JSON 파싱 에러 방지 위해 TEXT 기본 끔)
COMPAT_V1   = os.environ.get("COMPAT_V1", "1") == "1"
COMPAT_TEXT = os.environ.get("COMPAT_TEXT", "0") == "1"

ddb_client = boto3.client("dynamodb")
sts_client = boto3.client("sts")
ec2_client = boto3.client("ec2")  # 🔹 SG 규칙 / ENI 확인용

def ddb_resource():
    region = os.environ.get("AWS_REGION") or "us-east-1"
    try:
        region = WS_ENDPOINT.rstrip("/").split(".execute-api.", 1)[-1].split(".amazonaws.com", 1)[0] or region
    except Exception:
        pass
    return boto3.resource("dynamodb", region_name=region)

# ---------- 공용 유틸 ----------
def _ret(obj: dict):
    print(json.dumps(obj, ensure_ascii=False))
    return obj

def now_epoch() -> int:
    return int(time.time())

def now_iso() -> str:
    """UTC ISO8601 문자열 (Z 포함)"""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def to_decimal(n):
    return Decimal(str(n)) if not isinstance(n, Decimal) else n

def safe_get(d, *keys, default=None):
    cur = d
    for k in keys:
        if cur is None:
            return default
        cur = cur.get(k)
    return cur if cur is not None else default

_ARN_ACCT_RE = re.compile(r"arn:aws:(?:iam|sts)::(\d{12}):")

def extract_account_id(event: dict, payload: dict) -> str:
    if ACCOUNT_ID_OVERRIDE:
        return ACCOUNT_ID_OVERRIDE
    acct = event.get("account")
    if acct: return acct
    acct = (event.get("detail") or {}).get("userIdentity", {}).get("accountId")
    if acct: return acct
    arn = payload.get("arn") or payload.get("principal") or ""
    m = _ARN_ACCT_RE.search(arn)
    if m: return m.group(1)
    try:
        return sts_client.get_caller_identity().get("Account")
    except Exception:
        return ""

def extract_region(event: dict) -> str:
    return event.get("region") or (event.get("detail") or {}).get("awsRegion") or ""

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

# ---------- Incident 유틸 ----------
def incident_table():
    if not INCIDENT_TABLE:
        return None
    return ddb_resource().Table(INCIDENT_TABLE)

def generate_incident_id(prefix: str = "inc") -> str:
    """
    예: inc-20251120-014801-123
    """
    ts = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    rand = random.randint(0, 999)
    return f"{prefix}-{ts}-{rand:03d}"

def put_incident_record(event_type: str,
                        resource: str,
                        severity: str,
                        status: str = "NEW",
                        created_at: str | None = None,
                        details: dict | None = None):
    """
    Incident 테이블에 1건 저장.
    details 필드에 대시보드와 유사한 JSON 구조 저장.
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
    if details:
        item["details"] = details

    try:
        tbl.put_item(Item=_json_safe(item))
        print("✅ Incident stored:", json.dumps(item, ensure_ascii=False))
        return item
    except Exception as e:
        print("incident put fail:", e)
        return None

# ---------- 대시보드 스키마 변환 ----------
def _event_time_ms(event: dict) -> int:
    if USE_EVENT_TIME == "0":
        return int(time.time() * 1000)
    t = event.get("time") or (event.get("detail") or {}).get("eventTime")
    if t:
        dt = datetime.fromisoformat(str(t).replace('Z', '+00:00'))
        return int(dt.timestamp() * 1000)
    return int(time.time() * 1000)

def to_dashboard_event(event, payload) -> dict:
    # 1) 컨텍스트 값들 먼저 계산
    account_id = extract_account_id(event, payload)
    region     = extract_region(event)
    resource   = payload.get("resource") or payload.get("principal", "")

    # CloudTrail eventSource 우선 사용(예: ec2.amazonaws.com)
    src_from_event = safe_get(event, "detail", "eventSource")
    source = src_from_event or payload.get("source") or event.get("source") or "Unknown"
    source = normalize_source(source)

    # 표시할 이벤트 타입/심각도
    etype = payload.get("event_type") or "인스턴스가 공개 SG에 연결된 상태로 배포됨"
    sev   = (payload.get("severity") or "CRITICAL").upper()

    # 2) 메타 구성 (여기서 account_id 등 주입)
    meta = dict(payload)
    meta["account_id"] = account_id
    meta["eventName"]  = (event.get("detail") or {}).get("eventName")
    meta["eventID"]    = (event.get("detail") or {}).get("eventID") or event.get("id")

    # ARN을 표준 키로 고정(프론트/플랫너 모두에서 동일 키 사용)
    meta["arn"] = meta.get("arn") or meta.get("principal") or meta.get("actor") or ""

    # 3) 최종 대시보드 이벤트
    return {
        "kind": "event",
        "event": {
            "time": _event_time_ms(event),
            "source": source,
            "type": etype,
            "resource": resource,
            "account": account_id,
            "region": region,
            "severity": sev,
            "meta": meta,
            "arn": meta["arn"]   # 일부 대시보드가 top-level 'arn'을 바로 쓰는 경우 대비
        },
    }

# ---------- WebSocket 브로드캐스트 ----------
def _flatten_v1(v2_event: dict) -> dict:
    e = v2_event.get("event", v2_event)
    t = e.get("time")
    if not isinstance(t, (int, float)):
        try:
            t = int(datetime.fromisoformat(str(t).replace('Z','+00:00')).timestamp()*1000)
        except Exception:
            t = int(time.time()*1000)
    meta = e.get("meta") or {}
    sg_list = meta.get("sg_ids") or ([meta.get("sg_id")] if meta.get("sg_id") else [])
    sg_value = ",".join([s for s in sg_list if s])
    arn_value = e.get("arn") or meta.get("arn") or meta.get("principal") or meta.get("actor") or ""
    return {
        "time": int(t),
        "source":  normalize_source(e.get("source") or "AWS EC2"),
        "type":    e.get("type") or e.get("event_type") or "Unknown",
        "resource":e.get("resource") or e.get("principal") or "-",
        "account": e.get("account") or (meta.get("account_id") or ""),
        "region":  e.get("region") or "",
        "severity":(e.get("severity") or "INFO").upper(),
        "sg": sg_value,     # SG 표시
        "arn": arn_value,   # 행위자 ARN 표시
        "meta": meta
    }

def _text_summary(v1: dict) -> str:
    ts = datetime.fromtimestamp(v1["time"]/1000).strftime("%Y-%m-%d %H:%M:%S")
    return f"[{v1.get('severity','INFO')}] {v1.get('type')} :: {v1.get('resource')} | {v1.get('region')} {v1.get('account')} @ {ts}"

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

    # 🔹 v1 평탄 JSON만 대시보드로 보냄 (v2는 더 이상 전송 X)
    v1_obj = _flatten_v1(
        formatted_event if formatted_event.get("kind") == "event"
        else {"kind": "event", "event": formatted_event.get("event", formatted_event)}
    )
    v1_bytes = json.dumps(_json_safe(v1_obj)).encode("utf-8") if COMPAT_V1 else None

    # 디버깅 로그
    print("DEBUG_V1_FOR_DASHBOARD:", json.dumps(v1_obj, ensure_ascii=False))

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
                # ✅ v1 JSON만 전송 → 대시보드에는 한 줄만 찍힘
                if v1_bytes:
                    api.post_to_connection(ConnectionId=cid, Data=v1_bytes)
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

# ---------- STATE: SG 오픈 마커 (현재는 사용 안 함, 남겨만 둠) ----------
def state_table():
    return ddb_resource().Table(STATE_TABLE)

def put_sg_open_marker(sg_id: str, actor_arn: str, src_ip: str, when_iso: str):
    t = state_table()
    now = now_epoch()
    ttl = now + CORRELATION_TTL_SECONDS
    item = {
        STATE_PK: f"sg-open#{sg_id}",
        "type": "sg_open",
        "sg_id": sg_id,
        "actor": actor_arn,
        "src_ip": src_ip or "",
        "when_iso": when_iso or "",
        "ttl": to_decimal(ttl),
        "created": to_decimal(now),
    }
    t.put_item(Item=item)
    print(f"[STATE] put marker for {sg_id} ttl={ttl}")

def get_open_markers_for_sg_ids(sg_ids):
    # 현재는 사용하지 않지만 함수는 남겨둠
    if not sg_ids:
        return {}
    t = state_table()
    now = now_epoch()
    out = {}
    for sg in sg_ids:
        key = {STATE_PK: f"sg-open#{sg}"}
        try:
            r = t.get_item(Key=key)
            it = r.get("Item")
            if not it:
                continue
            ttl = int(it.get("ttl", 0))
            if ttl >= now and it.get("sg_id") == sg:
                out[sg] = it
        except Exception as e:
            print(f"[STATE] get_item failed for {key}: {e}")
    print("[STATE] matched markers =", list(out.keys()))
    return out

# ---------- EC2 이벤트 파서 ----------
def extract_sg_ids_from_event(detail: dict):
    sg_ids = set()

    # RunInstances: requestParameters.networkInterfaceSet.items[].groupSet.items[].groupId
    for ni in (safe_get(detail, "requestParameters", "networkInterfaceSet", "items", default=[]) or []):
        for g in (safe_get(ni, "groupSet", "items", default=[]) or []):
            gid = g.get("groupId")
            if gid: sg_ids.add(gid)

    # RunInstances: requestParameters.securityGroupId (고전)
    gid = safe_get(detail, "requestParameters", "securityGroupId")
    if gid: sg_ids.add(gid)

    # responseElements: instancesSet[].networkInterfaceSet[].groupSet[].groupId
    for it in (safe_get(detail, "responseElements", "instancesSet", "items", default=[]) or []):
        for ni in (safe_get(it, "networkInterfaceSet", "items", default=[]) or []):
            for g in (safe_get(ni, "groupSet", "items", default=[]) or []):
                gid = g.get("groupId")
                if gid: sg_ids.add(gid)

    # ModifyInstanceAttribute: requestParameters.groupSet.items[].groupId
    for g in (safe_get(detail, "requestParameters", "groupSet", "items", default=[]) or []):
        gid = g.get("groupId")
        if gid: sg_ids.add(gid)

    return list(sg_ids)

# ---------- SG 규칙 확인: SSH 월드 오픈 여부 ----------
def is_world_open_ssh_sg(sg_id: str) -> bool:
    """
    SG에 22/tcp (또는 전체 포트) + 0.0.0.0/0 또는 ::/0 가 있으면 True
    """
    try:
        resp = ec2_client.describe_security_groups(GroupIds=[sg_id])
    except ClientError as e:
        print(f"describe_security_groups failed for {sg_id}: {e}")
        return False

    for sg in resp.get("SecurityGroups", []):
        for perm in sg.get("IpPermissions", []):
            ip_proto = perm.get("IpProtocol")
            from_port = perm.get("FromPort")
            to_port   = perm.get("ToPort")

            # 프로토콜 체크
            if ip_proto not in ("tcp", "-1"):
                continue

            # 포트 체크 (전체 포트 허용도 포함)
            if from_port is None or to_port is None:
                port_ok = True  # all ports
            else:
                try:
                    port_ok = int(from_port) <= 22 <= int(to_port)
                except Exception:
                    port_ok = False
            if not port_ok:
                continue

            # CIDR 체크
            cidrs = []
            for r in perm.get("IpRanges", []):
                c = r.get("CidrIp")
                if c: cidrs.append(c)
            for r in perm.get("Ipv6Ranges", []):
                c = r.get("CidrIpv6")
                if c: cidrs.append(c)

            for c in cidrs:
                if c in ("0.0.0.0/0", "::/0"):
                    print(f"[SG] {sg_id} is world-open SSH (port 22, cidr={c})")
                    return True

    return False

def filter_world_open_sg_ids(sg_ids):
    """입력 SG 목록 중 SSH 월드 오픈인 것만 골라낸다."""
    world = []
    for sg_id in sg_ids:
        if is_world_open_ssh_sg(sg_id):
            world.append(sg_id)
    return world

# ---------- SG 에 붙어있는 인스턴스 조회 (신규) ----------
def get_instances_attached_to_sg(sg_id: str):
    """
    SG 가 이미 어떤 인스턴스에 attach 되어 있는지 ENI 기준으로 조회
    """
    instance_ids = set()
    try:
        resp = ec2_client.describe_network_interfaces(
            Filters=[{"Name": "group-id", "Values": [sg_id]}]
        )
    except ClientError as e:
        print(f"describe_network_interfaces failed for {sg_id}: {e}")
        return []

    for ni in resp.get("NetworkInterfaces", []):
        att = ni.get("Attachment") or {}
        iid = att.get("InstanceId")
        if iid:
            instance_ids.add(iid)

    return list(instance_ids)

# ---------- 핸들러들 ----------

def handle_instance_with_open_sg(event):
    """
    RunInstances / ModifyInstanceAttribute 에서import os, json, time, urllib.request, re, boto3, random
from botocore.exceptions import ClientError
from decimal import Decimal
from datetime import datetime

# ---------- JSON 직렬화 보조 ----------
def _json_safe(x):
    if isinstance(x, Decimal):
        return int(x) if x % 1 == 0 else float(x)
    if isinstance(x, dict):
        return {k: _json_safe(v) for k, v in x.items()}
    if isinstance(x, (list, tuple, set)):
        return [_json_safe(v) for v in x]
    return x

# ---------- 환경변수 ----------
WS_ENDPOINT        = os.environ.get("WS_ENDPOINT")
STATE_TABLE        = os.environ.get("STATE_TABLE", "security-alerts-state-v2")
CONNECTIONS_TABLE  = os.environ.get("CONNECTIONS_TABLE", "WebSocketConnections")
ACCOUNT_ID_OVERRIDE= os.environ.get("ACCOUNT_ID_OVERRIDE")
STATE_PK           = os.environ.get("STATE_PK", "id")
HTTP_TIMEOUT       = 8

# 🔹 Incident 테이블
INCIDENT_TABLE     = os.environ.get("INCIDENT_TABLE", "Incident")

# 상관관계 윈도(초) – 현재 SG 마커 방식은 사용 안 하지만 남겨둠
CORRELATION_TTL_SECONDS = int(os.environ.get("CORRELATION_TTL_SECONDS", "600"))

# 이벤트 시간 사용 방식: "0"이면 현재시간 사용
USE_EVENT_TIME = os.environ.get("USE_EVENT_TIME", "1")

# 호환 포맷 전송 옵션 (대시보드 JSON 파싱 에러 방지 위해 TEXT 기본 끔)
COMPAT_V1   = os.environ.get("COMPAT_V1", "1") == "1"
COMPAT_TEXT = os.environ.get("COMPAT_TEXT", "0") == "1"

ddb_client = boto3.client("dynamodb")
sts_client = boto3.client("sts")
ec2_client = boto3.client("ec2")  # 🔹 SG 규칙 / ENI 확인용

def ddb_resource():
    region = os.environ.get("AWS_REGION") or "us-east-1"
    try:
        region = WS_ENDPOINT.rstrip("/").split(".execute-api.", 1)[-1].split(".amazonaws.com", 1)[0] or region
    except Exception:
        pass
    return boto3.resource("dynamodb", region_name=region)

# ---------- 공용 유틸 ----------
def _ret(obj: dict):
    print(json.dumps(obj, ensure_ascii=False))
    return obj

def now_epoch() -> int:
    return int(time.time())

def now_iso() -> str:
    """UTC ISO8601 문자열 (Z 포함)"""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def to_decimal(n):
    return Decimal(str(n)) if not isinstance(n, Decimal) else n

def safe_get(d, *keys, default=None):
    cur = d
    for k in keys:
        if cur is None:
            return default
        cur = cur.get(k)
    return cur if cur is not None else default

_ARN_ACCT_RE = re.compile(r"arn:aws:(?:iam|sts)::(\d{12}):")

def extract_account_id(event: dict, payload: dict) -> str:
    if ACCOUNT_ID_OVERRIDE:
        return ACCOUNT_ID_OVERRIDE
    acct = event.get("account")
    if acct: return acct
    acct = (event.get("detail") or {}).get("userIdentity", {}).get("accountId")
    if acct: return acct
    arn = payload.get("arn") or payload.get("principal") or ""
    m = _ARN_ACCT_RE.search(arn)
    if m: return m.group(1)
    try:
        return sts_client.get_caller_identity().get("Account")
    except Exception:
        return ""

def extract_region(event: dict) -> str:
    return event.get("region") or (event.get("detail") or {}).get("awsRegion") or ""

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

# ---------- Incident 유틸 ----------
def incident_table():
    if not INCIDENT_TABLE:
        return None
    return ddb_resource().Table(INCIDENT_TABLE)

def generate_incident_id(prefix: str = "inc") -> str:
    """
    예: inc-20251120-014801-123
    """
    ts = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    rand = random.randint(0, 999)
    return f"{prefix}-{ts}-{rand:03d}"

def put_incident_record(event_type: str,
                        resource: str,
                        severity: str,
                        status: str = "NEW",
                        created_at: str | None = None,
                        details: dict | None = None):
    """
    Incident 테이블에 1건 저장.
    details 필드에 대시보드와 유사한 JSON 구조 저장.
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
    if details:
        item["details"] = details

    try:
        tbl.put_item(Item=_json_safe(item))
        print("✅ Incident stored:", json.dumps(item, ensure_ascii=False))
        return item
    except Exception as e:
        print("incident put fail:", e)
        return None

# ---------- 대시보드 스키마 변환 ----------
def _event_time_ms(event: dict) -> int:
    if USE_EVENT_TIME == "0":
        return int(time.time() * 1000)
    t = event.get("time") or (event.get("detail") or {}).get("eventTime")
    if t:
        dt = datetime.fromisoformat(str(t).replace('Z', '+00:00'))
        return int(dt.timestamp() * 1000)
    return int(time.time() * 1000)

def to_dashboard_event(event, payload) -> dict:
    # 1) 컨텍스트 값들 먼저 계산
    account_id = extract_account_id(event, payload)
    region     = extract_region(event)
    resource   = payload.get("resource") or payload.get("principal", "")

    # CloudTrail eventSource 우선 사용(예: ec2.amazonaws.com)
    src_from_event = safe_get(event, "detail", "eventSource")
    source = src_from_event or payload.get("source") or event.get("source") or "Unknown"
    source = normalize_source(source)

    # 표시할 이벤트 타입/심각도
    etype = payload.get("event_type") or "인스턴스가 공개 SG에 연결된 상태로 배포됨"
    sev   = (payload.get("severity") or "CRITICAL").upper()

    # 2) 메타 구성 (여기서 account_id 등 주입)
    meta = dict(payload)
    meta["account_id"] = account_id
    meta["eventName"]  = (event.get("detail") or {}).get("eventName")
    meta["eventID"]    = (event.get("detail") or {}).get("eventID") or event.get("id")

    # ARN을 표준 키로 고정(프론트/플랫너 모두에서 동일 키 사용)
    meta["arn"] = meta.get("arn") or meta.get("principal") or meta.get("actor") or ""

    # 3) 최종 대시보드 이벤트
    return {
        "kind": "event",
        "event": {
            "time": _event_time_ms(event),
            "source": source,
            "type": etype,
            "resource": resource,
            "account": account_id,
            "region": region,
            "severity": sev,
            "meta": meta,
            "arn": meta["arn"]   # 일부 대시보드가 top-level 'arn'을 바로 쓰는 경우 대비
        },
    }

# ---------- WebSocket 브로드캐스트 ----------
def _flatten_v1(v2_event: dict) -> dict:
    e = v2_event.get("event", v2_event)
    t = e.get("time")
    if not isinstance(t, (int, float)):
        try:
            t = int(datetime.fromisoformat(str(t).replace('Z','+00:00')).timestamp()*1000)
        except Exception:
            t = int(time.time()*1000)
    meta = e.get("meta") or {}
    sg_list = meta.get("sg_ids") or ([meta.get("sg_id")] if meta.get("sg_id") else [])
    sg_value = ",".join([s for s in sg_list if s])
    arn_value = e.get("arn") or meta.get("arn") or meta.get("principal") or meta.get("actor") or ""
    return {
        "time": int(t),
        "source":  normalize_source(e.get("source") or "AWS EC2"),
        "type":    e.get("type") or e.get("event_type") or "Unknown",
        "resource":e.get("resource") or e.get("principal") or "-",
        "account": e.get("account") or (meta.get("account_id") or ""),
        "region":  e.get("region") or "",
        "severity":(e.get("severity") or "INFO").upper(),
        "sg": sg_value,     # SG 표시
        "arn": arn_value,   # 행위자 ARN 표시
        "meta": meta
    }

def _text_summary(v1: dict) -> str:
    ts = datetime.fromtimestamp(v1["time"]/1000).strftime("%Y-%m-%d %H:%M:%S")
    return f"[{v1.get('severity','INFO')}] {v1.get('type')} :: {v1.get('resource')} | {v1.get('region')} {v1.get('account')} @ {ts}"

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

    # 🔹 v1 평탄 JSON만 대시보드로 보냄 (v2는 더 이상 전송 X)
    v1_obj = _flatten_v1(
        formatted_event if formatted_event.get("kind") == "event"
        else {"kind": "event", "event": formatted_event.get("event", formatted_event)}
    )
    v1_bytes = json.dumps(_json_safe(v1_obj)).encode("utf-8") if COMPAT_V1 else None

    # 디버깅 로그
    print("DEBUG_V1_FOR_DASHBOARD:", json.dumps(v1_obj, ensure_ascii=False))

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
                # ✅ v1 JSON만 전송 → 대시보드에는 한 줄만 찍힘
                if v1_bytes:
                    api.post_to_connection(ConnectionId=cid, Data=v1_bytes)
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

# ---------- STATE: SG 오픈 마커 (현재는 사용 안 함, 남겨만 둠) ----------
def state_table():
    return ddb_resource().Table(STATE_TABLE)

def put_sg_open_marker(sg_id: str, actor_arn: str, src_ip: str, when_iso: str):
    t = state_table()
    now = now_epoch()
    ttl = now + CORRELATION_TTL_SECONDS
    item = {
        STATE_PK: f"sg-open#{sg_id}",
        "type": "sg_open",
        "sg_id": sg_id,
        "actor": actor_arn,
        "src_ip": src_ip or "",
        "when_iso": when_iso or "",
        "ttl": to_decimal(ttl),
        "created": to_decimal(now),
    }
    t.put_item(Item=item)
    print(f"[STATE] put marker for {sg_id} ttl={ttl}")

def get_open_markers_for_sg_ids(sg_ids):
    # 현재는 사용하지 않지만 함수는 남겨둠
    if not sg_ids:
        return {}
    t = state_table()
    now = now_epoch()
    out = {}
    for sg in sg_ids:
        key = {STATE_PK: f"sg-open#{sg}"}
        try:
            r = t.get_item(Key=key)
            it = r.get("Item")
            if not it:
                continue
            ttl = int(it.get("ttl", 0))
            if ttl >= now and it.get("sg_id") == sg:
                out[sg] = it
        except Exception as e:
            print(f"[STATE] get_item failed for {key}: {e}")
    print("[STATE] matched markers =", list(out.keys()))
    return out

# ---------- EC2 이벤트 파서 ----------
def extract_sg_ids_from_event(detail: dict):
    sg_ids = set()

    # RunInstances: requestParameters.networkInterfaceSet.items[].groupSet.items[].groupId
    for ni in (safe_get(detail, "requestParameters", "networkInterfaceSet", "items", default=[]) or []):
        for g in (safe_get(ni, "groupSet", "items", default=[]) or []):
            gid = g.get("groupId")
            if gid: sg_ids.add(gid)

    # RunInstances: requestParameters.securityGroupId (고전)
    gid = safe_get(detail, "requestParameters", "securityGroupId")
    if gid: sg_ids.add(gid)

    # responseElements: instancesSet[].networkInterfaceSet[].groupSet[].groupId
    for it in (safe_get(detail, "responseElements", "instancesSet", "items", default=[]) or []):
        for ni in (safe_get(it, "networkInterfaceSet", "items", default=[]) or []):
            for g in (safe_get(ni, "groupSet", "items", default=[]) or []):
                gid = g.get("groupId")
                if gid: sg_ids.add(gid)

    # ModifyInstanceAttribute: requestParameters.groupSet.items[].groupId
    for g in (safe_get(detail, "requestParameters", "groupSet", "items", default=[]) or []):
        gid = g.get("groupId")
        if gid: sg_ids.add(gid)

    return list(sg_ids)

# ---------- SG 규칙 확인: SSH 월드 오픈 여부 ----------
def is_world_open_ssh_sg(sg_id: str) -> bool:
    """
    SG에 22/tcp (또는 전체 포트) + 0.0.0.0/0 또는 ::/0 가 있으면 True
    """
    try:
        resp = ec2_client.describe_security_groups(GroupIds=[sg_id])
    except ClientError as e:
        print(f"describe_security_groups failed for {sg_id}: {e}")
        return False

    for sg in resp.get("SecurityGroups", []):
        for perm in sg.get("IpPermissions", []):
            ip_proto = perm.get("IpProtocol")
            from_port = perm.get("FromPort")
            to_port   = perm.get("ToPort")

            # 프로토콜 체크
            if ip_proto not in ("tcp", "-1"):
                continue

            # 포트 체크 (전체 포트 허용도 포함)
            if from_port is None or to_port is None:
                port_ok = True  # all ports
            else:
                try:
                    port_ok = int(from_port) <= 22 <= int(to_port)
                except Exception:
                    port_ok = False
            if not port_ok:
                continue

            # CIDR 체크
            cidrs = []
            for r in perm.get("IpRanges", []):
                c = r.get("CidrIp")
                if c: cidrs.append(c)
            for r in perm.get("Ipv6Ranges", []):
                c = r.get("CidrIpv6")
                if c: cidrs.append(c)

            for c in cidrs:
                if c in ("0.0.0.0/0", "::/0"):
                    print(f"[SG] {sg_id} is world-open SSH (port 22, cidr={c})")
                    return True

    return False

def filter_world_open_sg_ids(sg_ids):
    """입력 SG 목록 중 SSH 월드 오픈인 것만 골라낸다."""
    world = []
    for sg_id in sg_ids:
        if is_world_open_ssh_sg(sg_id):
            world.append(sg_id)
    return world

# ---------- SG 에 붙어있는 인스턴스 조회 (신규) ----------
def get_instances_attached_to_sg(sg_id: str):
    """
    SG 가 이미 어떤 인스턴스에 attach 되어 있는지 ENI 기준으로 조회
    """
    instance_ids = set()
    try:
        resp = ec2_client.describe_network_interfaces(
            Filters=[{"Name": "group-id", "Values": [sg_id]}]
        )
    except ClientError as e:
        print(f"describe_network_interfaces failed for {sg_id}: {e}")
        return []

    for ni in resp.get("NetworkInterfaces", []):
        att = ni.get("Attachment") or {}
        iid = att.get("InstanceId")
        if iid:
            instance_ids.add(iid)

    return list(instance_ids)

# ---------- 핸들러들 ----------

def handle_instance_with_open_sg(event):
    """
    RunInstances / ModifyInstanceAttribute 에서
    SSH open SG 가 붙은 인스턴스 배포/변경 감지
    """
    detail = event.get("detail", {}) or {}
    en = detail.get("eventName")
    if en not in ("RunInstances", "ModifyInstanceAttribute"):
        return _ret({"status": "skip_non_target_event"})

    sg_ids = extract_sg_ids_from_event(detail)
    if not sg_ids:
        return _ret({"status": "no_sg_in_event"})

    # 🔹 실제 SG 설정을 보고 SSH 월드 오픈인 SG만 필터링
    world_sg_ids = filter_world_open_sg_ids(sg_ids)
    if not world_sg_ids:
        return _ret({"status": "no_world_open_sg", "sgs": sg_ids})

    account  = extract_account_id(event, {})
    region   = extract_region(event)

    # 인스턴스 ID 추출
    instance_ids = []
    for it in (safe_get(detail, "responseElements", "instancesSet", "items", default=[]) or []):
        iid = it.get("instanceId")
        if iid:
            instance_ids.append(iid)
    if not instance_ids:
        iid = safe_get(detail, "requestParameters", "instanceId")
        if iid:
            instance_ids.append(iid)

    ui = detail.get("userIdentity", {}) or {}
    actor_arn = ui.get("arn") or ui.get("principalId") or "unknown"

    when_iso = event.get("time") or detail.get("eventTime") or now_iso()
    resource_val = ",".join(instance_ids) if instance_ids else ",".join(world_sg_ids)

    payload = {
        "alert_type": "ec2_deployed_open_ssh",
        "severity": "CRITICAL",
        "source": "AWS EC2",
        "event_type": "인스턴스가 공개 SG에 연결된 상태로 배포됨",
        "resource": resource_val,
        "account": account,
        "region": region,
        "sg_ids": world_sg_ids,
        "sg_id": world_sg_ids[0] if world_sg_ids else "",
        "principal": actor_arn,
        "arn": actor_arn,
        "api_event": en,
        "time": when_iso,
        "raw_event": detail
    }

    # 🔹 Incident details 구성
    incident_details = {
        "time": when_iso,
        "source": "EC2",
        "type": "인스턴스가 공개 SG에 연결된 상태로 배포됨",
        "sg": world_sg_ids[0] if world_sg_ids else "",
        "arn": actor_arn,
        "resource": resource_val,
        "account": account,
        "region": region,
        "alertType": "ALERT",
        "rulesViolated": ["인스턴스가 공개 SG에 연결된 상태로 배포됨"],
        "severity": "CRITICAL",
    }

    incident = put_incident_record(
        event_type="인스턴스가 공개 SG에 연결된 상태로 배포됨",
        resource=resource_val,
        severity="CRITICAL",
        status="NEW",
        created_at=when_iso,
        details=incident_details,
    )
    if incident:
        payload["incident_id"] = incident["incident_id"]

    dashboard_event = to_dashboard_event(event, payload)
    post_to_ws_dashboard(dashboard_event)
    return _ret({"status": "alert_sent", "instance_ids": instance_ids, "sgs": world_sg_ids})


# 🔥 신규: SG 룰 변경으로 인해 기존 인스턴스가 SSH open 상태가 되는 경우
def handle_sg_rule_change_affects_instances(event):
    """
    AuthorizeSecurityGroupIngress / ModifySecurityGroupRules 이벤트에서,
    해당 SG 가 SSH 월드 오픈 상태가 되었고,
    그 SG 에 이미 attach 되어 있던 인스턴스가 있다면 알림 발생.
    """
    detail = event.get("detail", {}) or {}
    en = detail.get("eventName")
    if en not in ("AuthorizeSecurityGroupIngress", "ModifySecurityGroupRules"):
        return _ret({"status": "skip_non_sg_rule_event"})

    sg_id = safe_get(detail, "requestParameters", "groupId") \
        or safe_get(detail, "responseElements", "groupId")
    if not sg_id:
        return _ret({"status": "no_sg_in_event"})

    # 변경 후 SG 가 SSH 월드 오픈인지 확인
    if not is_world_open_ssh_sg(sg_id):
        return _ret({"status": "sg_not_world_open_after_change", "sg": sg_id})

    # 이 SG 에 현재 붙어 있는 인스턴스 목록 조회
    instance_ids = get_instances_attached_to_sg(sg_id)
    if not instance_ids:
        return _ret({"status": "world_open_sg_but_no_instances", "sg": sg_id})

    account = extract_account_id(event, {})
    region  = extract_region(event)

    ui = detail.get("userIdentity", {}) or {}
    actor_arn = ui.get("arn") or ui.get("principalId") or "unknown"

    when_iso = event.get("time") or detail.get("eventTime") or now_iso()
    resource_val = ",".join(instance_ids)

    payload = {
        "alert_type": "ec2_existing_instances_now_open_ssh",
        "severity": "CRITICAL",
        "source": "AWS EC2",
        "event_type": "인스턴스가 공개 SG에 연결된 상태로 배포됨",  # 이벤트 이름은 동일하게 유지
        "resource": resource_val,
        "account": account,
        "region": region,
        "sg_ids": [sg_id],
        "sg_id": sg_id,
        "principal": actor_arn,
        "arn": actor_arn,
        "api_event": en,
        "time": when_iso,
        "raw_event": detail
    }

    incident_details = {
        "time": when_iso,
        "source": "EC2",
        "type": "인스턴스가 공개 SG에 연결된 상태로 배포됨",
        "sg": sg_id,
        "arn": actor_arn,
        "resource": resource_val,
        "account": account,
        "region": region,
        "alertType": "ALERT",
        "rulesViolated": ["인스턴스가 공개 SG에 연결된 상태로 배포됨"],
        "severity": "CRITICAL",
        "reason": "SG rule change made attached instances SSH-open"
    }

    incident = put_incident_record(
        event_type="인스턴스가 공개 SG에 연결된 상태로 배포됨",
        resource=resource_val,
        severity="CRITICAL",
        status="NEW",
        created_at=when_iso,
        details=incident_details,
    )
    if incident:
        payload["incident_id"] = incident["incident_id"]

    dashboard_event = to_dashboard_event(event, payload)
    post_to_ws_dashboard(dashboard_event)
    return _ret({"status": "alert_sent_by_sg_rule_change", "instance_ids": instance_ids, "sg": sg_id})


def handle_access_key_created(event):
    if event.get("source") != "aws.iam":
        return _ret({"status": "skip"})
    detail = event.get("detail", {}) or {}
    if detail.get("eventName") != "CreateAccessKey":
        return _ret({"status": "skip_non_target_event"})

    access_key_id = ((detail.get("responseElements", {}) or {}).get("accessKey", {}) or {}).get("accessKeyId", "unknown")
    ui = detail.get("userIdentity", {}) or {}
    user_arn = ui.get("arn") or ui.get("principalId") or "unknown"
    user_type = ui.get("type")
    principal = ui.get("principalId")
    src_ip = detail.get("sourceIPAddress")
    user_agent = detail.get("userAgent")
    when_iso = event.get("time") or detail.get("eventTime") or now_iso()

    payload = {
        "alert_type": "access_key_created",
        "severity": "HIGH",
        "source": "AWS IAM",
        "event_type": "새 Access Key 생성",
        "principal": user_arn,
        "access_key_id": access_key_id,
        "actor_type": user_type,
        "principal_id": principal,
        "arn": user_arn,
        "source_ip": src_ip,
        "user_agent": user_agent,
        "time": when_iso,
        "raw_event": detail,
    }

    account = extract_account_id(event, payload)
    region  = extract_region(event)

    # 🔹 Incident details – 요청한 형식 그대로
    incident_details = {
        "time": when_iso,
        "source": "IAM",
        "type": "새 Access Key 생성",
        "sg": "",
        "arn": user_arn,
        "resource": user_arn,
        "account": account,
        "region": region,
        "alertType": "ALERT",
        "rulesViolated": ["새 Access Key 생성"],
        "severity": "HIGH"
    }

    incident = put_incident_record(
        event_type="새 Access Key 생성",
        resource=user_arn,
        severity="HIGH",
        status="NEW",
        created_at=when_iso,
        details=incident_details,
    )
    if incident:
        payload["incident_id"] = incident["incident_id"]

    dashboard_event = to_dashboard_event(event, payload)
    post_to_ws_dashboard(dashboard_event)
    return _ret({"status": "alert_sent", "access_key_id": access_key_id})

# ---------- 메인 핸들러 ----------
def lambda_handler(event, context):
    try:
        if "awslogs" in event:
            return _ret({"status": "skipped_cwlogs"})

        src = event.get("source")
        dt  = event.get("detail-type")
        detail = event.get("detail", {}) or {}
        en  = detail.get("eventName")

        # 🔥 SG 규칙 변경으로 기존 인스턴스가 SSH open 이 되는 경우
        if src == "aws.ec2" and dt == "AWS API Call via CloudTrail" and en in ("AuthorizeSecurityGroupIngress", "ModifySecurityGroupRules"):
            return handle_sg_rule_change_affects_instances(event)

        # 인스턴스 생성/SG 교체 시 공개 SG 연결
        if src == "aws.ec2" and dt == "AWS API Call via CloudTrail" and en in ("RunInstances", "ModifyInstanceAttribute"):
            return handle_instance_with_open_sg(event)

        if src == "aws.iam" and dt == "AWS API Call via CloudTrail":
            return handle_access_key_created(event)

        return _ret({"status": "noop"})
    except Exception as e:
        print("handler error:", e)
        raise

    SSH open SG 가 붙은 인스턴스 배포/변경 감지
    """
    detail = event.get("detail", {}) or {}
    en = detail.get("eventName")
    if en not in ("RunInstances", "ModifyInstanceAttribute"):
        return _ret({"status": "skip_non_target_event"})

    sg_ids = extract_sg_ids_from_event(detail)
    if not sg_ids:
        return _ret({"status": "no_sg_in_event"})

    # 🔹 실제 SG 설정을 보고 SSH 월드 오픈인 SG만 필터링
    world_sg_ids = filter_world_open_sg_ids(sg_ids)
    if not world_sg_ids:
        return _ret({"status": "no_world_open_sg", "sgs": sg_ids})

    account  = extract_account_id(event, {})
    region   = extract_region(event)

    # 인스턴스 ID 추출
    instance_ids = []
    for it in (safe_get(detail, "responseElements", "instancesSet", "items", default=[]) or []):
        iid = it.get("instanceId")
        if iid:
            instance_ids.append(iid)
    if not instance_ids:
        iid = safe_get(detail, "requestParameters", "instanceId")
        if iid:
            instance_ids.append(iid)

    ui = detail.get("userIdentity", {}) or {}
    actor_arn = ui.get("arn") or ui.get("principalId") or "unknown"

    when_iso = event.get("time") or detail.get("eventTime") or now_iso()
    resource_val = ",".join(instance_ids) if instance_ids else ",".join(world_sg_ids)

    payload = {
        "alert_type": "ec2_deployed_open_ssh",
        "severity": "CRITICAL",
        "source": "AWS EC2",
        "event_type": "인스턴스가 공개 SG에 연결된 상태로 배포됨",
        "resource": resource_val,
        "account": account,
        "region": region,
        "sg_ids": world_sg_ids,
        "sg_id": world_sg_ids[0] if world_sg_ids else "",
        "principal": actor_arn,
        "arn": actor_arn,
        "api_event": en,
        "time": when_iso,
        "raw_event": detail
    }

    # 🔹 Incident details 구성
    incident_details = {
        "time": when_iso,
        "source": "EC2",
        "type": "인스턴스가 공개 SG에 연결된 상태로 배포됨",
        "sg": world_sg_ids[0] if world_sg_ids else "",
        "arn": actor_arn,
        "resource": resource_val,
        "account": account,
        "region": region,
        "alertType": "ALERT",
        "rulesViolated": ["인스턴스가 공개 SG에 연결된 상태로 배포됨"],
        "severity": "CRITICAL",
    }

    incident = put_incident_record(
        event_type="인스턴스가 공개 SG에 연결된 상태로 배포됨",
        resource=resource_val,
        severity="CRITICAL",
        status="NEW",
        created_at=when_iso,
        details=incident_details,
    )
    if incident:
        payload["incident_id"] = incident["incident_id"]

    dashboard_event = to_dashboard_event(event, payload)
    post_to_ws_dashboard(dashboard_event)
    return _ret({"status": "alert_sent", "instance_ids": instance_ids, "sgs": world_sg_ids})


# 🔥 신규: SG 룰 변경으로 인해 기존 인스턴스가 SSH open 상태가 되는 경우
def handle_sg_rule_change_affects_instances(event):
    """
    AuthorizeSecurityGroupIngress / ModifySecurityGroupRules 이벤트에서,
    해당 SG 가 SSH 월드 오픈 상태가 되었고,
    그 SG 에 이미 attach 되어 있던 인스턴스가 있다면 알림 발생.
    """
    detail = event.get("detail", {}) or {}
    en = detail.get("eventName")
    if en not in ("AuthorizeSecurityGroupIngress", "ModifySecurityGroupRules"):
        return _ret({"status": "skip_non_sg_rule_event"})

    sg_id = safe_get(detail, "requestParameters", "groupId") \
        or safe_get(detail, "responseElements", "groupId")
    if not sg_id:
        return _ret({"status": "no_sg_in_event"})

    # 변경 후 SG 가 SSH 월드 오픈인지 확인
    if not is_world_open_ssh_sg(sg_id):
        return _ret({"status": "sg_not_world_open_after_change", "sg": sg_id})

    # 이 SG 에 현재 붙어 있는 인스턴스 목록 조회
    instance_ids = get_instances_attached_to_sg(sg_id)
    if not instance_ids:
        return _ret({"status": "world_open_sg_but_no_instances", "sg": sg_id})

    account = extract_account_id(event, {})
    region  = extract_region(event)

    ui = detail.get("userIdentity", {}) or {}
    actor_arn = ui.get("arn") or ui.get("principalId") or "unknown"

    when_iso = event.get("time") or detail.get("eventTime") or now_iso()
    resource_val = ",".join(instance_ids)

    payload = {
        "alert_type": "ec2_existing_instances_now_open_ssh",
        "severity": "CRITICAL",
        "source": "AWS EC2",
        "event_type": "인스턴스가 공개 SG에 연결된 상태로 배포됨",  # 이벤트 이름은 동일하게 유지
        "resource": resource_val,
        "account": account,
        "region": region,
        "sg_ids": [sg_id],
        "sg_id": sg_id,
        "principal": actor_arn,
        "arn": actor_arn,
        "api_event": en,
        "time": when_iso,
        "raw_event": detail
    }

    incident_details = {
        "time": when_iso,
        "source": "EC2",
        "type": "인스턴스가 공개 SG에 연결된 상태로 배포됨",
        "sg": sg_id,
        "arn": actor_arn,
        "resource": resource_val,
        "account": account,
        "region": region,
        "alertType": "ALERT",
        "rulesViolated": ["인스턴스가 공개 SG에 연결된 상태로 배포됨"],
        "severity": "CRITICAL",
        "reason": "SG rule change made attached instances SSH-open"
    }

    incident = put_incident_record(
        event_type="인스턴스가 공개 SG에 연결된 상태로 배포됨",
        resource=resource_val,
        severity="CRITICAL",
        status="NEW",
        created_at=when_iso,
        details=incident_details,
    )
    if incident:
        payload["incident_id"] = incident["incident_id"]

    dashboard_event = to_dashboard_event(event, payload)
    post_to_ws_dashboard(dashboard_event)
    return _ret({"status": "alert_sent_by_sg_rule_change", "instance_ids": instance_ids, "sg": sg_id})


def handle_access_key_created(event):
    if event.get("source") != "aws.iam":
        return _ret({"status": "skip"})
    detail = event.get("detail", {}) or {}
    if detail.get("eventName") != "CreateAccessKey":
        return _ret({"status": "skip_non_target_event"})

    access_key_id = ((detail.get("responseElements", {}) or {}).get("accessKey", {}) or {}).get("accessKeyId", "unknown")
    ui = detail.get("userIdentity", {}) or {}
    user_arn = ui.get("arn") or ui.get("principalId") or "unknown"
    user_type = ui.get("type")
    principal = ui.get("principalId")
    src_ip = detail.get("sourceIPAddress")
    user_agent = detail.get("userAgent")
    when_iso = event.get("time") or detail.get("eventTime") or now_iso()

    payload = {
        "alert_type": "access_key_created",
        "severity": "HIGH",
        "source": "AWS IAM",
        "event_type": "새 Access Key 생성",
        "principal": user_arn,
        "access_key_id": access_key_id,
        "actor_type": user_type,
        "principal_id": principal,
        "arn": user_arn,
        "source_ip": src_ip,
        "user_agent": user_agent,
        "time": when_iso,
        "raw_event": detail,
    }

    account = extract_account_id(event, payload)
    region  = extract_region(event)

    # 🔹 Incident details – 요청한 형식 그대로
    incident_details = {
        "time": when_iso,
        "source": "IAM",
        "type": "새 Access Key 생성",
        "sg": "",
        "arn": user_arn,
        "resource": user_arn,
        "account": account,
        "region": region,
        "alertType": "ALERT",
        "rulesViolated": ["새 Access Key 생성"],
        "severity": "HIGH"
    }

    incident = put_incident_record(
        event_type="새 Access Key 생성",
        resource=user_arn,
        severity="HIGH",
        status="NEW",
        created_at=when_iso,
        details=incident_details,
    )
    if incident:
        payload["incident_id"] = incident["incident_id"]

    dashboard_event = to_dashboard_event(event, payload)
    post_to_ws_dashboard(dashboard_event)
    return _ret({"status": "alert_sent", "access_key_id": access_key_id})

# ---------- 메인 핸들러 ----------
def lambda_handler(event, context):
    try:
        if "awslogs" in event:
            return _ret({"status": "skipped_cwlogs"})

        src = event.get("source")
        dt  = event.get("detail-type")
        detail = event.get("detail", {}) or {}
        en  = detail.get("eventName")

        # 🔥 SG 규칙 변경으로 기존 인스턴스가 SSH open 이 되는 경우
        if src == "aws.ec2" and dt == "AWS API Call via CloudTrail" and en in ("AuthorizeSecurityGroupIngress", "ModifySecurityGroupRules"):
            return handle_sg_rule_change_affects_instances(event)

        # 인스턴스 생성/SG 교체 시 공개 SG 연결
        if src == "aws.ec2" and dt == "AWS API Call via CloudTrail" and en in ("RunInstances", "ModifyInstanceAttribute"):
            return handle_instance_with_open_sg(event)

        if src == "aws.iam" and dt == "AWS API Call via CloudTrail":
            return handle_access_key_created(event)

        return _ret({"status": "noop"})
    except Exception as e:
        print("handler error:", e)
        raise
