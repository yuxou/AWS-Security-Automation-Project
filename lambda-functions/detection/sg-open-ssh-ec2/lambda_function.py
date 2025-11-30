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

sns_client         = boto3.client("sns")
SNS_TOPIC_ARN_AUTOREM = os.environ.get("SNS_TOPIC_ARN_AUTOREM")

INCIDENT_TABLE     = os.environ.get("INCIDENT_TABLE", "Incident")
CORRELATION_TTL_SECONDS = int(os.environ.get("CORRELATION_TTL_SECONDS", "600"))
USE_EVENT_TIME     = os.environ.get("USE_EVENT_TIME", "1")
COMPAT_V1          = os.environ.get("COMPAT_V1", "1") == "1"
COMPAT_TEXT        = os.environ.get("COMPAT_TEXT", "0") == "1"

ddb_client         = boto3.client("dynamodb")
sts_client         = boto3.client("sts")
ec2_client         = boto3.client("ec2")

# 🔹 예외 인스턴스용 태그
EXCLUDE_TAG_KEY   = os.environ.get("EXCLUDE_TAG_KEY", "RemediationExclusion")
EXCLUDE_TAG_VALUE = os.environ.get("EXCLUDE_TAG_VALUE", "Ignore")


def is_instance_excluded(instance_id: str) -> bool:
    """
    특정 태그(EXCLUDE_TAG_KEY=EXCLUDE_TAG_VALUE)가 붙은 인스턴스는
    탐지/자동대응 대상에서 제외
    """
    try:
        resp = ec2_client.describe_instances(InstanceIds=[instance_id])
    except ClientError as e:
        print(f"[EXCLUDE] describe_instances error for {instance_id}:", e)
        return False

    for r in resp.get("Reservations", []):
        for inst in r.get("Instances", []):
            if inst.get("InstanceId") != instance_id:
                continue
            for tag in inst.get("Tags", []) or []:
                if tag.get("Key") == EXCLUDE_TAG_KEY and tag.get("Value") == EXCLUDE_TAG_VALUE:
                    print(f"[EXCLUDE] instance {instance_id} is excluded by tag {EXCLUDE_TAG_KEY}={EXCLUDE_TAG_VALUE}")
                    return True
    return False


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
    # 👉 요구사항: Incident 에서는 021417007719 로 고정
    if ACCOUNT_ID_OVERRIDE:
        return ACCOUNT_ID_OVERRIDE
    acct = event.get("account")
    if acct:
        return acct
    acct = (event.get("detail") or {}).get("userIdentity", {}).get("accountId")
    if acct:
        return acct
    arn = payload.get("arn") or payload.get("principal") or ""
    m = _ARN_ACCT_RE.search(arn)
    if m:
        return m.group(1)
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
                        details: dict | None = None,
                        account: str | None = None,
                        region: str | None = None,
                        source: str | None = None):
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

    acct_val = ACCOUNT_ID_OVERRIDE or account

    item = {
        "incident_id": iid,
        "event_type": event_type,
        "resource": resource or "",
        "severity": sev,      # LOW | MED | HIGH | CRITICAL
        "status": st,         # NEW | PROCESSING | MITIGATED | CLOSED
        "created_at": created,
        "updated_at": created,
    }
    if acct_val:
        item["account"] = acct_val
    if region:
        item["region"] = region
    if source:
        item["source"] = source
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
            "arn": meta["arn"],   # 일부 대시보드가 top-level 'arn'을 바로 쓰는 경우 대비
            "incident_id": meta.get("incident_id"),  # 🔹 incident_id도 같이 넣어 둠
        },
    }

# ---------- WebSocket 브로드캐스트 ----------
def _flatten_v1(v2_event: dict) -> dict:
    e = v2_event.get("event", v2_event)

    # time 정규화
    t = e.get("time")
    if not isinstance(t, (int, float)):
        try:
            t = int(datetime.fromisoformat(str(t).replace('Z', '+00:00')).timestamp() * 1000)
        except Exception:
            t = int(time.time() * 1000)

    meta = e.get("meta") or {}

    sg_list = meta.get("sg_ids") or ([meta.get("sg_id")] if meta.get("sg_id") else [])
    sg_value = ",".join([s for s in sg_list if s])

    arn_value = (
        e.get("arn")
        or meta.get("arn")
        or meta.get("principal")
        or meta.get("actor")
        or ""
    )

    # 🔹 incident_id 도 평탄화해서 top-level 로 올려줌
    incident_id = e.get("incident_id") or meta.get("incident_id")

    return {
        "time": int(t),
        "source": normalize_source(e.get("source") or "AWS EC2"),
        "type": e.get("type") or e.get("event_type") or "Unknown",
        "resource": e.get("resource") or e.get("principal") or "-",
        "account": e.get("account") or (meta.get("account_id") or ""),
        "region": e.get("region") or "",
        "severity": (e.get("severity") or "INFO").upper(),
        "sg": sg_value,
        "arn": arn_value,
        "meta": meta,
        "incident_id": incident_id,
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

    # 🔹 v1 평탄 JSON만 대시보드로 보냄
    v1_obj = _flatten_v1(
        formatted_event if formatted_event.get("kind") == "event"
        else {"kind": "event", "event": formatted_event.get("event", formatted_event)}
    )
    v1_bytes = json.dumps(_json_safe(v1_obj)).encode("utf-8") if COMPAT_V1 else None

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

    for ni in (safe_get(detail, "requestParameters", "networkInterfaceSet", "items", default=[]) or []):
        for g in (safe_get(ni, "groupSet", "items", default=[]) or []):
            gid = g.get("groupId")
            if gid:
                sg_ids.add(gid)

    gid = safe_get(detail, "requestParameters", "securityGroupId")
    if gid:
        sg_ids.add(gid)

    for it in (safe_get(detail, "responseElements", "instancesSet", "items", default=[]) or []):
        for ni in (safe_get(it, "networkInterfaceSet", "items", default=[]) or []):
            for g in (safe_get(ni, "groupSet", "items", default=[]) or []):
                gid = g.get("groupId")
                if gid:
                    sg_ids.add(gid)

    for g in (safe_get(detail, "requestParameters", "groupSet", "items", default=[]) or []):
        gid = g.get("groupId")
        if gid:
            sg_ids.add(gid)

    return list(sg_ids)

# ---------- SG 규칙 확인: SSH 월드 오픈 여부 ----------
def is_world_open_ssh_sg(sg_id: str) -> bool:
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

            if ip_proto not in ("tcp", "-1"):
                continue

            if from_port is None or to_port is None:
                port_ok = True  # all ports
            else:
                try:
                    port_ok = int(from_port) <= 22 <= int(to_port)
                except Exception:
                    port_ok = False
            if not port_ok:
                continue

            cidrs = []
            for r in perm.get("IpRanges", []):
                c = r.get("CidrIp")
                if c:
                    cidrs.append(c)
            for r in perm.get("Ipv6Ranges", []):
                c = r.get("CidrIpv6")
                if c:
                    cidrs.append(c)

            for c in cidrs:
                if c in ("0.0.0.0/0", "::/0"):
                    print(f"[SG] {sg_id} is world-open SSH (port 22, cidr={c})")
                    return True

    return False

def filter_world_open_sg_ids(sg_ids):
    world = []
    for sg_id in sg_ids:
        if is_world_open_ssh_sg(sg_id):
            world.append(sg_id)
    return world

# ---------- 핸들러들 ----------

def handle_instance_with_open_sg(event):
    """
    RunInstances 에서
    SSH open SG 가 붙은 인스턴스 배포 감지
    """
    detail = event.get("detail", {}) or {}
    en = detail.get("eventName")
    if en != "RunInstances":
        return _ret({"status": "skip_non_runinstances"})

    sg_ids = extract_sg_ids_from_event(detail)
    if not sg_ids:
        return _ret({"status": "no_sg_in_event"})

    world_sg_ids = filter_world_open_sg_ids(sg_ids)
    if not world_sg_ids:
        return _ret({"status": "no_world_open_sg", "sgs": sg_ids})

    account  = extract_account_id(event, {})
    region   = extract_region(event)

    instance_ids = []
    for it in (safe_get(detail, "responseElements", "instancesSet", "items", default=[]) or []):
        iid = it.get("instanceId")
        if iid:
            instance_ids.append(iid)
    if not instance_ids:
        iid = safe_get(detail, "requestParameters", "instanceId")
        if iid:
            instance_ids.append(iid)

    # 🔹 예외 인스턴스 필터링
    if instance_ids:
        filtered_instance_ids = [iid for iid in instance_ids if not is_instance_excluded(iid)]
        if not filtered_instance_ids:
            return _ret({
                "status": "all_instances_excluded",
                "instance_ids": instance_ids
            })
        instance_ids = filtered_instance_ids

    ui = detail.get("userIdentity", {}) or {}
    actor_arn = ui.get("arn") or ui.get("principalId") or "unknown"
    src_ip = detail.get("sourceIPAddress")
    user_agent = detail.get("userAgent")

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
        "raw_event": detail,
    }

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
        "meta": {
            "device": {
                "summary": user_agent or "unknown",
                "ua": user_agent or ""
            },
            "ip": src_ip or "",
            "api": en or ""
        }
    }

    incident = put_incident_record(
        event_type="인스턴스가 공개 SG에 연결된 상태로 배포됨",
        resource=resource_val,
        severity="CRITICAL",
        status="NEW",
        created_at=when_iso,
        details=incident_details,
        account=account,
        region=region,
        source="EC2",
    )
    if incident:
        payload["incident_id"] = incident["incident_id"]

    print("DEBUG_BEFORE_SNS_BLOCK",
          {"sns_arn": SNS_TOPIC_ARN_AUTOREM, "instance_ids": instance_ids})

    # SNS 자동대응 트리거
    if SNS_TOPIC_ARN_AUTOREM and instance_ids:
        auto_msg = {
            "time": when_iso,
            "action": "QuarantineInstance",
            "target": instance_ids[0],
            "playbook": "isolate-ec2",
            "status": "TRIGGERED",
            "account": account,
            "region": region,
        }
        if incident:
            auto_msg["incident_id"] = incident["incident_id"]

        try:
            sns_client.publish(
                TopicArn=SNS_TOPIC_ARN_AUTOREM,
                Message=json.dumps(auto_msg),
                Subject="EC2 SSH open instance auto remediation"
            )
            print("✅ SNS auto-remediation message published:",
                  json.dumps(auto_msg, ensure_ascii=False))
        except Exception as e:
            print("❌ SNS publish failed:", e)

    dashboard_event = to_dashboard_event(event, payload)
    post_to_ws_dashboard(dashboard_event)
    return _ret({"status": "alert_sent", "instance_ids": instance_ids, "sgs": world_sg_ids})

def handle_instance_start_with_open_sg(event):
    """
    Stop 상태였던 인스턴스를 StartInstances 로 기동할 때,
    이미 공개 SSH SG가 붙어 있으면 알림 + 인시던트 + 자동대응
    """
    detail = event.get("detail", {}) or {}
    en = detail.get("eventName")
    if en != "StartInstances":
        return _ret({"status": "skip_non_startinstances"})

    # 1) StartInstances 이벤트에서 인스턴스 ID 추출
    instance_ids = []
    # requestParameters 쪽
    for it in (safe_get(detail, "requestParameters", "instancesSet", "items", default=[]) or []):
        iid = it.get("instanceId")
        if iid:
            instance_ids.append(iid)
    # responseElements 쪽도 한 번 더 확인
    for it in (safe_get(detail, "responseElements", "instancesSet", "items", default=[]) or []):
        iid = it.get("instanceId")
        if iid and iid not in instance_ids:
            instance_ids.append(iid)

    if not instance_ids:
        return _ret({"status": "no_instance_in_event", "eventName": en})

    account = extract_account_id(event, {})
    region  = extract_region(event)

    ui         = detail.get("userIdentity", {}) or {}
    actor_arn  = ui.get("arn") or ui.get("principalId") or "unknown"
    src_ip     = detail.get("sourceIPAddress")
    user_agent = detail.get("userAgent")
    when_iso   = event.get("time") or detail.get("eventTime") or now_iso()

    alerted_instances = []

    for iid in instance_ids:
        # 🔹 예외 인스턴스면 건너뜀
        if is_instance_excluded(iid):
            print(f"[EXCLUDE] skip StartInstances for {iid}")
            continue

        # 2) 인스턴스에 붙은 SG 조회
        try:
            resp = ec2_client.describe_instances(InstanceIds=[iid])
        except ClientError as e:
            print("describe_instances error:", e)
            continue

        sg_ids = set()
        for r in resp.get("Reservations", []):
            for inst in r.get("Instances", []):
                if inst.get("InstanceId") != iid:
                    continue
                for sg in inst.get("SecurityGroups", []):
                    gid = sg.get("GroupId")
                    if gid:
                        sg_ids.add(gid)

        if not sg_ids:
            continue

        # 3) 공개 SSH SG 필터링
        world_sg_ids = filter_world_open_sg_ids(list(sg_ids))
        if not world_sg_ids:
            continue

        resource_val = iid

        payload = {
            "alert_type": "ec2_start_with_open_ssh",
            "severity": "CRITICAL",
            "source": "AWS EC2",
            "event_type": "공개 SG가 연결된 인스턴스가 다시 실행됨",
            "resource": resource_val,
            "account": account,
            "region": region,
            "sg_ids": world_sg_ids,
            "sg_id": world_sg_ids[0],
            "principal": actor_arn,
            "arn": actor_arn,
            "api_event": en,
            "time": when_iso,
            "raw_event": detail,
        }

        # Incident details + meta (device/ip/api)
        incident_details = {
            "time": when_iso,
            "source": "EC2",
            "type": "공개 SG가 연결된 인스턴스가 다시 실행됨",
            "sg": world_sg_ids[0],
            "arn": actor_arn,
            "resource": resource_val,
            "account": account,
            "region": region,
            "alertType": "ALERT",
            "rulesViolated": ["공개 SG가 연결된 인스턴스가 다시 실행됨"],
            "severity": "CRITICAL",
            "meta": {
                "device": {
                    "summary": user_agent or "unknown",
                    "ua": user_agent or ""
                },
                "ip": src_ip or "",
                "api": en or ""   # StartInstances
            }
        }

        incident = put_incident_record(
            event_type="공개 SG가 연결된 인스턴스가 다시 실행됨",
            resource=resource_val,
            severity="CRITICAL",
            status="NEW",
            created_at=when_iso,
            details=incident_details,
            account=account,
            region=region,
            source="EC2",
        )
        if incident:
            payload["incident_id"] = incident["incident_id"]

        # 🔔 자동대응 SNS (지금이랑 똑같이 격리 Playbook 호출)
        if SNS_TOPIC_ARN_AUTOREM:
            auto_msg = {
                "time": when_iso,
                "action": "QuarantineInstance",
                "target": iid,
                "playbook": "isolate-ec2",
                "status": "TRIGGERED",
                "account": account,
                "region": region,
            }
            if incident:
                auto_msg["incident_id"] = incident["incident_id"]

            try:
                sns_client.publish(
                    TopicArn=SNS_TOPIC_ARN_AUTOREM,
                    Message=json.dumps(auto_msg),
                    Subject="EC2 SSH open instance auto remediation (StartInstances)"
                )
                print("✅ SNS auto-remediation message published (StartInstances):",
                      json.dumps(auto_msg, ensure_ascii=False))
            except Exception as e:
                print("❌ SNS publish failed (StartInstances):", e)

        dashboard_event = to_dashboard_event(event, payload)
        post_to_ws_dashboard(dashboard_event)
        alerted_instances.append(iid)

    if not alerted_instances:
        return _ret({"status": "no_world_open_sg_on_start", "instances": instance_ids})

    return _ret({
        "status": "alert_sent_start_open_sg",
        "instances": alerted_instances,
        "eventName": "StartInstances"
    })

def handle_instance_attach_open_sg(event):
    detail = event.get("detail", {}) or {}
    en = detail.get("eventName")
    if en not in ("ModifyInstanceAttribute", "ModifyNetworkInterfaceAttribute"):
        return _ret({"status": "skip_non_modify_event"})

    # 요청 SG 목록(변경 후 SG 전체 목록)
    new_sgs = set()
    for g in safe_get(detail, "requestParameters", "groupSet", "items", default=[]) or []:
        gid = g.get("groupId")
        if gid:
            new_sgs.add(gid)

    if not new_sgs:
        return _ret({"status": "no_sg_in_event", "eventName": en})

    # 인스턴스 ID 추출
    instance_id = None
    if en == "ModifyInstanceAttribute":
        instance_id = safe_get(detail, "requestParameters", "instanceId")
    else:  # 🔹 ModifyNetworkInterfaceAttribute 인 경우 ENI -> 인스턴스 역추적
        eni_id = safe_get(detail, "requestParameters", "networkInterfaceId")
        if not eni_id:
            return _ret({"status": "no_eni_in_event"})
        try:
            resp = ec2_client.describe_network_interfaces(
                NetworkInterfaceIds=[eni_id]
            )
            nis = resp.get("NetworkInterfaces") or []
            if nis:
                att = nis[0].get("Attachment") or {}
                instance_id = att.get("InstanceId")
        except ClientError as e:
            print("describe_network_interfaces error:", e)
            return _ret({"status": "describe_eni_failed", "error": str(e)})

    if not instance_id:
        return _ret({"status": "no_instance_in_event", "eventName": en})

    # 🔹 예외 인스턴스면 바로 스킵
    if is_instance_excluded(instance_id):
        return _ret({
            "status": "excluded_instance_attach_open_sg",
            "instance": instance_id,
            "eventName": en
        })

    # 🔥 새로 추가된 SG 목록 계산
    if en == "ModifyNetworkInterfaceAttribute":
        # 콘솔에서 ENI SG를 '교체'한 케이스 → new_sgs 전체를 추가로 간주
        added_sgs = list(new_sgs)
    else:
        # ModifyInstanceAttribute 에서는 기존 SG와 차집합
        try:
            resp = ec2_client.describe_instances(InstanceIds=[instance_id])
            old_sgs = set()
            for res in resp.get("Reservations", []):
                for inst in res.get("Instances", []):
                    for sg in inst.get("SecurityGroups", []):
                        old_sgs.add(sg["GroupId"])
        except Exception as e:
            print("describe_instances error:", e)
            return _ret({"status": "describe_failed", "error": str(e)})
        added_sgs = list(new_sgs - old_sgs)

    if not added_sgs:
        return _ret({"status": "no_new_sg_added", "eventName": en})

    # 🔥 새로 추가된 SG 중 SSH open SG 찾기
    world_open_added = []
    for sg in added_sgs:
        if is_world_open_ssh_sg(sg):
            world_open_added.append(sg)

    if not world_open_added:
        return _ret({"status": "added_sgs_not_world_open", "added_sgs": added_sgs})

    # ===== 아래는 그대로 (Incident 생성 + 대시보드 전송) =====
    account = extract_account_id(event, {})
    region  = extract_region(event)
    ui = detail.get("userIdentity", {}) or {}
    actor_arn = ui.get("arn") or ui.get("principalId") or "unknown"
    when_iso = event.get("time") or detail.get("eventTime") or now_iso()

    # 🔹 메타용
    src_ip = detail.get("sourceIPAddress")
    user_agent = detail.get("userAgent")

    payload = {
        "alert_type": "ec2_existing_instance_attach_open_sg",
        "severity": "CRITICAL",
        "source": "AWS EC2",
        "event_type": "기존 인스턴스에 공개 SG가 새로 연결됨",
        "resource": instance_id,
        "account": account,
        "region": region,
        "sg_ids": world_open_added,
        "sg_id": world_open_added[0],
        "principal": actor_arn,
        "arn": actor_arn,
        "api_event": en,
        "time": when_iso,
        "raw_event": detail
    }

    incident_details = {
        "time": when_iso,
        "source": "EC2",
        "type": "기존 인스턴스에 공개 SG가 새로 연결됨",
        "sg": world_open_added[0],
        "arn": actor_arn,
        "resource": instance_id,
        "account": account,
        "region": region,
        "alertType": "ALERT",
        "rulesViolated": ["기존 인스턴스에 공개 SG가 새로 연결됨"],
        "severity": "CRITICAL",
        "meta": {
            "device": {
                "summary": user_agent or "unknown",
                "ua": user_agent or ""
            },
            "ip": src_ip or "",
            "api": en or ""
        }
    }
    incident = put_incident_record(
        event_type="기존 인스턴스에 공개 SG가 새로 연결됨",
        resource=instance_id,
        severity="CRITICAL",
        status="NEW",
        created_at=when_iso,
        details=incident_details,
        account=account,
        region=region,
        source="EC2",
    )

    if incident:
        payload["incident_id"] = incident["incident_id"]

    # 🔹 기존 인스턴스 + 공개 SG attach 도 자동 격리 트리거
    if SNS_TOPIC_ARN_AUTOREM and instance_id:
        auto_msg = {
            "time": when_iso,
            "action": "QuarantineInstance",
            "target": instance_id,
            "playbook": "isolate-ec2",
            "status": "TRIGGERED",
            "account": account,
            "region": region,
        }
        if incident:
            auto_msg["incident_id"] = incident["incident_id"]

        try:
            sns_client.publish(
                TopicArn=SNS_TOPIC_ARN_AUTOREM,
                Message=json.dumps(auto_msg),
                Subject="EC2 existing instance with SSH open SG auto remediation"
            )
            print("✅ SNS auto-remediation message published (attach_open_sg):",
                  json.dumps(auto_msg, ensure_ascii=False))
        except Exception as e:
            print("❌ SNS publish failed (attach_open_sg):", e)

    dashboard_event = to_dashboard_event(event, payload)
    post_to_ws_dashboard(dashboard_event)

    return _ret({
        "status": "alert_sent_attach_open_sg",
        "instance": instance_id,
        "added_sgs": world_open_added,
        "eventName": en
    })


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
        "severity": "HIGH",
        "meta": {
            "device": {
                "summary": user_agent or "unknown",
                "ua": user_agent or ""
            },
            "ip": src_ip or "",
            "api": "CreateAccessKey"
        }
    }

    incident = put_incident_record(
        event_type="새 Access Key 생성",
        resource=user_arn,
        severity="HIGH",
        status="NEW",
        created_at=when_iso,
        details=incident_details,
        account=account,
        region=region,
        source="IAM",
    )
    if incident:
        payload["incident_id"] = incident["incident_id"]

    dashboard_event = to_dashboard_event(event, payload)
    post_to_ws_dashboard(dashboard_event)
    return _ret({"status": "alert_sent", "access_key_id": access_key_id})

# ---------- 메인 핸들러 ----------
def lambda_handler(event, context):
    print("DEBUG_SNS_ENV:", SNS_TOPIC_ARN_AUTOREM)
    try:
        if "awslogs" in event:
            return _ret({"status": "skipped_cwlogs"})

        src = event.get("source")
        dt  = event.get("detail-type")
        detail = event.get("detail", {}) or {}
        en  = detail.get("eventName")

        # 새 인스턴스 + SSH Open SG
        if src == "aws.ec2" and dt == "AWS API Call via CloudTrail" and en == "RunInstances":
            return handle_instance_with_open_sg(event)

        # stop → start (StartInstances) 시, 이미 공개 SG가 붙어 있던 인스턴스
        if src == "aws.ec2" and dt == "AWS API Call via CloudTrail" and en == "StartInstances":
            return handle_instance_start_with_open_sg(event)

        # 기존 인스턴스에 SSH Open SG attach
        if src == "aws.ec2" and dt == "AWS API Call via CloudTrail" and en in (
                "ModifyInstanceAttribute",
                "ModifyNetworkInterfaceAttribute",
        ):
            return handle_instance_attach_open_sg(event)

        # 새 Access Key 생성
        if src == "aws.iam" and dt == "AWS API Call via CloudTrail":
            return handle_access_key_created(event)

        return _ret({"status": "noop", "en": en, "src": src, "dt": dt})
    except Exception as e:
        print("handler error:", e)
        raise
