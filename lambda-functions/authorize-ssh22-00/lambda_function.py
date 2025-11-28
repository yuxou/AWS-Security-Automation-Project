import os
import json
import time
import urllib.request
import re
import boto3
from botocore.exceptions import ClientError
from decimal import Decimal
from datetime import datetime

# ==============================
# JSON 직렬화 보조
# ==============================
def _json_safe(x):
    if isinstance(x, Decimal):
        return int(x) if x % 1 == 0 else float(x)
    if isinstance(x, dict):
        return {k: _json_safe(v) for k, v in x.items()}
    if isinstance(x, (list, tuple, set)):
        return [_json_safe(v) for v in x]
    return x

# ==============================
# 환경변수
# ==============================
WS_ENDPOINT         = os.environ.get("WS_ENDPOINT")  # https://{apiId}.execute-api.{region}.amazonaws.com/{stage}
STATE_TABLE         = os.environ.get("STATE_TABLE", "security-alerts-state-v2")
CONNECTIONS_TABLE   = os.environ.get("CONNECTIONS_TABLE", "WebSocketConnections")
ACCOUNT_ID_OVERRIDE = os.environ.get("ACCOUNT_ID_OVERRIDE")
STATE_PK            = os.environ.get("STATE_PK", "id")
HTTP_TIMEOUT        = 8

# 임계/윈도
THRESHOLD      = int(os.environ.get("THRESHOLD", "3"))         # 예: 3
WINDOW_SECONDS = int(os.environ.get("WINDOW_SECONDS", "600"))  # 예: 600(=10분)

# 이벤트 시간 사용 방식 (0이면 현재시간 사용 → 대시보드 즉시 표시)
USE_EVENT_TIME = os.environ.get("USE_EVENT_TIME", "1")

ddb_client = boto3.client("dynamodb")
sts_client = boto3.client("sts")

def ddb_resource():
    region = os.environ.get("AWS_REGION") or "us-east-1"
    try:
        region = WS_ENDPOINT.rstrip("/").split(".execute-api.", 1)[-1].split(".amazonaws.com", 1)[0] or region
    except Exception:
        pass
    return boto3.resource("dynamodb", region_name=region)

# ==============================
# 공용 유틸
# ==============================
def _ret(obj: dict):
    print(json.dumps(obj, ensure_ascii=False))
    return obj

def now_epoch() -> int:
    return int(time.time())

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

# ===== Deduplication (CloudTrail eventID 기반 멱등성) =====
def _seen_once(event_id: str) -> bool:
    """
    CloudTrail eventID를 STATE_TABLE에 기록.
    이미 처리한 적 있으면 True. TTL은 1일.
    """
    if not event_id:
        return False
    table = ddb_resource().Table(STATE_TABLE)
    now = now_epoch()
    ttl = now + 86400  # 1 day

    try:
        table.put_item(
            Item={STATE_PK: f"seen::{event_id}", "createdAt": now, "ttl": to_decimal(ttl)},
            ConditionExpression=f"attribute_not_exists({STATE_PK})",
        )
        return False  # 최초 기록
    except Exception:
        return True   # 이미 처리한 이벤트

def extract_region(event: dict) -> str:
    return event.get("region") or (event.get("detail") or {}).get("awsRegion") or ""

# ==============================
# HTTP 폴백(옵션)
# ==============================
HTTP_FALLBACK_URL = os.environ.get("HTTP_FALLBACK_URL")

def _http_fallback_send(v1_obj: dict):
    if not HTTP_FALLBACK_URL:
        return
    try:
        body = json.dumps(v1_obj).encode("utf-8")
        req = urllib.request.Request(
            HTTP_FALLBACK_URL, data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as r:
            print("[HTTP OK]", r.status)
    except Exception as e:
        print("[HTTP NG]", e)

# ==============================
# 대시보드 스키마 변환
# ==============================
def _event_time_ms(event: dict) -> int:
    if USE_EVENT_TIME == "0":
        return int(time.time() * 1000)
    t = event.get("time") or (event.get("detail") or {}).get("eventTime")
    if t:
        dt = datetime.fromisoformat(t.replace('Z', '+00:00'))
        return int(dt.timestamp() * 1000)
    return int(time.time() * 1000)

def to_dashboard_event(event, payload) -> dict:
    account_id = extract_account_id(event, payload)
    region = extract_region(event)
    resource = payload.get("resource") or payload.get("principal", "")
    src_from_event = safe_get(event, "detail", "eventSource")
    source = src_from_event or payload.get("source") or event.get("source") or "aws.unknown"
    etype = payload.get("event_type") or "EC2DeployedWithOpenSSH"
    sev = (payload.get("severity") or "CRITICAL").upper()

    meta = dict(payload)
    meta["account_id"] = account_id
    meta["eventName"] = (event.get("detail") or {}).get("eventName")
    meta["eventID"] = (event.get("detail") or {}).get("eventID") or event.get("id")

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
        },
    }

# ==============================
# WebSocket 브로드캐스트 (단일 메시지: 평탄 v1만 전송)
# ==============================
COMPAT_V1   = os.environ.get("COMPAT_V1", "1") == "1"
COMPAT_TEXT = os.environ.get("COMPAT_TEXT", "1") == "1"

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
    arn_value = meta.get("principal") or meta.get("actor") or ""

    return {
        "time": int(t),
        "source":  e.get("source")  or "ec2.amazonaws.com",
        "type":    e.get("type")    or e.get("event_type") or "Unknown",
        "resource":e.get("resource") or e.get("principal") or "-",
        "account": e.get("account") or (meta.get("account_id") or ""),
        "region":  e.get("region")  or "",
        "severity":(e.get("severity") or "INFO").upper(),
        "sg": sg_value,
        "arn": arn_value,
        "meta": meta
    }

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

    v1_obj = _flatten_v1(formatted_event if formatted_event.get("kind")=="event" else {"kind":"event","event":formatted_event.get("event",formatted_event)})
    print("[WS PAYLOAD]", json.dumps(v1_obj, ensure_ascii=False))

    data_bytes = json.dumps(_json_safe(v1_obj)).encode("utf-8")

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
                print(f"[WS OK] sent to connectionId={cid}")
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

    print(f"WS broadcast (flat-only) done: ok={ok}, gone={gone}, err={err}")
    _http_fallback_send(v1_obj)

# ==============================
# STATE: SG 오픈 마커/카운터
# ==============================
def state_table():
    return ddb_resource().Table(STATE_TABLE)

def put_sg_open_marker(sg_id: str, actor_arn: str, src_ip: str, when_iso: str):
    t = state_table()
    now = now_epoch()
    ttl = now + WINDOW_SECONDS  # 창 길이에 맞춰 만료
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

def bump_actor_counter_if_first(actor_arn: str, sg_id: str):
    """
    같은 행위자/같은 SG 조합은 윈도우 안에서 1번만 카운트.
    TTL이 지난 actor-sg 레코드는 새로 온 것으로 보고 다시 카운트.
    """
    if not actor_arn or not sg_id:
        print("[STATE] skip bump_actor_counter_if_first: empty actor or sg")
        return

    t = state_table()
    now = now_epoch()
    ttl = now + WINDOW_SECONDS
    key = {STATE_PK: f"actor-sg#{actor_arn}#{sg_id}"}

    first = False

    # 1) 우선 조건부 put 시도
    try:
        t.put_item(
            Item={**key, "ttl": to_decimal(ttl), "created": to_decimal(now)},
            ConditionExpression=f"attribute_not_exists({STATE_PK})",
        )
        print(f"[STATE] new actor-sg item created: {key[STATE_PK]}")
        first = True
    except Exception as e:
        print(f"[STATE] actor-sg put_item failed (maybe exists): {e}")
        # 이미 존재하는 경우 → TTL 확인해서 만료면 새로 취급
        try:
            r = t.get_item(Key=key)
            it = r.get("Item")
            print(f"[STATE] existing actor-sg item: {it}")
        except Exception as ge:
            print(f"[STATE] get_item error for actor-sg: {ge}")
            it = None

        if not it:
            # 이상하지만, 조회가 안 되면 새로 만들고 first로 취급
            t.put_item(Item={**key, "ttl": to_decimal(ttl), "created": to_decimal(now)})
            print(f"[STATE] recreated missing actor-sg item: {key[STATE_PK]}")
            first = True
        else:
            old_ttl = int(it.get("ttl", 0))
            if old_ttl < now:
                # TTL 지난 항목 → 새 윈도우로 보고 덮어쓰기
                t.put_item(Item={**key, "ttl": to_decimal(ttl), "created": to_decimal(now)})
                print(f"[STATE] actor-sg item expired; reset for new window: {key[STATE_PK]}")
                first = True
            else:
                print(f"[STATE] actor-sg already counted in this window: {key[STATE_PK]}")
                first = False

    if not first:
        return

    # 2) actor-count 증가 (윈도우 갱신)
    try:
        r = t.update_item(
            Key={STATE_PK: f"actor-count#{actor_arn}"},
            UpdateExpression="SET #c = if_not_exists(#c, :zero) + :one, #ttl = :ttl",
            ExpressionAttributeNames={"#c": "count", "#ttl": "ttl"},
            ExpressionAttributeValues={
                ":zero": to_decimal(0),
                ":one": to_decimal(1),
                ":ttl": to_decimal(ttl),
            },
            ReturnValues="ALL_NEW",
        )
        new_item = r.get("Attributes", {})
        print(f"[STATE] actor {actor_arn} count updated:", new_item)
    except Exception as ue:
        print(f"[STATE] update_item error for actor-count: {ue}")

def get_actor_count(actor_arn: str) -> int:
    if not actor_arn:
        return 0
    t = state_table()
    # ★ 강한 일관성 읽기: 막 업데이트한 값 바로 보이도록
    r = t.get_item(Key={STATE_PK: f"actor-count#{actor_arn}"}, ConsistentRead=True)
    it = r.get("Item") or {}
    ttl = int(it.get("ttl", 0))
    if ttl < now_epoch():
        return 0
    return int(it.get("count", 0))

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

# ==============================
# AuthorizeSecurityGroupIngress 파서
# 22/TCP 이고 0.0.0.0/0 또는 ::/0 인 경우에만 True
# ==============================
def is_world_ssh_ingress(detail: dict) -> bool:
    perms = safe_get(detail, "requestParameters", "ipPermissions", "items", default=[]) or []
    for p in perms:
        proto = (p.get("ipProtocol") or "").lower()
        try:
            from_p = int(p.get("fromPort"))
            to_p   = int(p.get("toPort"))
        except Exception:
            from_p = to_p = None

        # '6'은 TCP, CloudTrail에서 '6'으로 올 때가 있음
        if proto not in ("6", "tcp", "-1", "all"):
            continue
        if not (from_p == 22 and to_p == 22):
            continue

        # IPv4
        for r in safe_get(p, "ipRanges", "items", default=[]) or []:
            cidr = (r.get("cidrIp") or "").strip()
            if cidr == "0.0.0.0/0":
                return True
        # IPv6
        for r in safe_get(p, "ipv6Ranges", "items", default=[]) or []:
            cidr6 = (r.get("cidrIpv6") or "").strip()
            if cidr6 == "::/0":
                return True
    return False

# ==============================
# 핸들러: (A) SG SSH 오픈 → 카운팅 + 임계치 도달 시 즉시 알림(윈도우당 1회)
# ==============================
def handle_sg_ssh_open(event):
    detail = event.get("detail", {}) or {}
    if detail.get("eventName") != "AuthorizeSecurityGroupIngress":
        return _ret({"status": "skip_non_target_event"})

    event_id = detail.get("eventID")
    if _seen_once(event_id):
        return _ret({"status": "dup_event_skip", "event_id": event_id})

    # 22/TCP 월드 오픈이 아니면 카운트/마커 생성하지 않음
    if not is_world_ssh_ingress(detail):
        return _ret({"status": "skip_non_world_ssh"})

    sg_id = safe_get(detail, "requestParameters", "groupId") \
            or safe_get(detail, "responseElements", "groupId") \
            or "unknown"

    ui = detail.get("userIdentity", {}) or {}
    actor_arn = ui.get("arn") or ui.get("principalId") or "unknown"
    src_ip = detail.get("sourceIPAddress")
    when_iso = event.get("time") or detail.get("eventTime")

    # 마커 저장(참조용) + 카운트(동일 SG 중복 방지)
    put_sg_open_marker(sg_id, actor_arn, src_ip, when_iso)
    bump_actor_counter_if_first(actor_arn, sg_id)

    # 현재 누적 카운트 확인(강한 일관성 읽기)
    count = get_actor_count(actor_arn)
    if count < THRESHOLD:
        return _ret({"status": "marked_only_no_alert", "sg": sg_id, "actor": actor_arn, "count": count})

    # ★ 윈도우당 1회 알림 래치
    t = state_table()
    alert_flag_pk = f"actor-alerted#{actor_arn}"
    r = t.get_item(Key={STATE_PK: alert_flag_pk})
    if (r.get("Item") or {}).get("ttl", 0) >= now_epoch():
        return _ret({"status": "already_alerted_in_window", "actor": actor_arn, "count": count})

    t.put_item(Item={STATE_PK: alert_flag_pk, "ttl": to_decimal(now_epoch() + WINDOW_SECONDS)})

    # 임계치 도달 → 즉시 알림 전송 (이 창에서 1회만)
    account = extract_account_id(event, {"principal": actor_arn})
    region  = extract_region(event)

    payload = {
        "alert_type": "ssh_world_open_repeated",
        "severity": "CRITICAL",
        "source": "AWS CloudTrail",
        "event_type": "동일 계정 내 여러 SG에서 반복 SSH 오픈",
        "resource": sg_id,
        "account": account,
        "region": region,
        "sg_ids": [sg_id],
        "sg_id": sg_id,
        "principal": actor_arn,
        "api_event": "AuthorizeSecurityGroupIngress",
        "time": when_iso,
        "raw_event": detail,
        "count": count,
        "threshold": THRESHOLD,
    }

    dashboard_event = to_dashboard_event(event, payload)
    post_to_ws_dashboard(dashboard_event)
    return _ret({"status": "alert_sent", "sg": sg_id, "actor": actor_arn, "count": count})

# ==============================
# 핸들러: (B) RunInstances / ModifyInstanceAttribute  (보조; 인스턴스 무관이면 실사용에선 비활성화해도 OK)
# ==============================
def extract_sg_ids_from_event(detail: dict):
    sg_ids = set()
    ni_items = safe_get(detail, "requestParameters", "networkInterfaceSet", "items", default=[])
    for ni in ni_items or []:
        for g in safe_get(ni, "groupSet", "items", default=[]) or []:
            gid = g.get("groupId")
            if gid:
                sg_ids.add(gid)
    gid = safe_get(detail, "requestParameters", "securityGroupId")
    if gid:
        sg_ids.add(gid)
    inst_items = safe_get(detail, "responseElements", "instancesSet", "items", default=[]) or []
    for it in inst_items:
        nis = safe_get(it, "networkInterfaceSet", "items", default=[]) or []
        for ni in nis:
            gs = safe_get(ni, "groupSet", "items", default=[]) or []
            for g in gs:
                gid = g.get("groupId")
                if gid:
                    sg_ids.add(gid)
    gset_items = safe_get(detail, "requestParameters", "groupSet", "items", default=[]) or []
    for g in gset_items:
        gid = g.get("groupId")
        if gid:
            sg_ids.add(gid)
    return list(sg_ids)

def handle_instance_with_open_sg(event):
    detail = event.get("detail", {}) or {}
    en = detail.get("eventName")
    if en not in ("RunInstances", "ModifyInstanceAttribute"):
        return _ret({"status": "skip_non_target_event"})

    event_id = detail.get("eventID")
    if _seen_once(event_id):
        return _ret({"status": "dup_event_skip", "event_id": event_id})

    sg_ids = extract_sg_ids_from_event(detail)
    if not sg_ids:
        return _ret({"status": "no_sg_in_event"})

    markers = get_open_markers_for_sg_ids(sg_ids)
    if not markers:
        return _ret({"status": "no_open_sg_match", "sgs": sg_ids})

    actor_arn = ""
    for m in markers.values():
        actor_arn = m.get("actor") or ""
        if actor_arn:
            break

    actor_count = get_actor_count(actor_arn)
    if actor_count < THRESHOLD:
        return _ret({"status": "below_threshold_actor", "actor": actor_arn, "count": actor_count, "required": THRESHOLD})

    account = extract_account_id(event, {})
    region = extract_region(event)
    instance_ids = []
    inst_items = safe_get(detail, "responseElements", "instancesSet", "items", default=[]) or []
    for it in inst_items:
        iid = it.get("instanceId")
        if iid:
            instance_ids.append(iid)

    payload = {
        "alert_type": "ec2_deployed_open_ssh",
        "severity": "CRITICAL",
        "source": "AWS EC2",
        "event_type": "동일 계정 내 여러 SG에서 반복 SSH 오픈",
        "resource": ",".join(instance_ids) if instance_ids else ",".join(sg_ids),
        "account": account,
        "region": region,
        "sg_ids": sg_ids,
        "sg_id": sg_ids[0] if sg_ids else "",
        "principal": actor_arn,
        "matched_markers": _json_safe(markers),
        "api_event": en,
        "time": event.get("time") or detail.get("eventTime"),
        "raw_event": detail
    }

    dashboard_event = to_dashboard_event(event, payload)
    post_to_ws_dashboard(dashboard_event)
    return _ret({"status": "alert_sent", "instance_ids": instance_ids, "sgs": sg_ids})

# ==============================
# 기존: Access Key 생성 이벤트
# ==============================
def handle_access_key_created(event):
    if event.get("source") != "aws.iam":
        return _ret({"status": "skip"})
    detail = event.get("detail", {}) or {}
    if detail.get("eventName") != "CreateAccessKey":
        return _ret({"status": "skip_non_target_event"})

    event_id = detail.get("eventID")
    if _seen_once(event_id):
        return _ret({"status": "dup_event_skip", "event_id": event_id})

    access_key_id = (
        (detail.get("responseElements", {}) or {}).get("accessKey", {}) or {}
    ).get("accessKeyId", "unknown")

    ui = detail.get("userIdentity", {}) or {}
    user_arn = ui.get("arn") or ui.get("principalId") or "unknown"
    user_type = ui.get("type")
    principal = ui.get("principalId")

    src_ip = detail.get("sourceIPAddress")
    user_agent = detail.get("userAgent")
    when_iso = event.get("time") or detail.get("eventTime")

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
        "time": when_iso,
        "raw_event": detail,
    }

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

        src = event.get("source")
        dt = event.get("detail-type")
        detail = event.get("detail", {}) or {}
        en = detail.get("eventName")

        # A) SG Open SSH → 카운팅 + 임계치 도달 시 즉시 알림(윈도우당 1회)
        if src == "aws.ec2" and dt == "AWS API Call via CloudTrail" and en == "AuthorizeSecurityGroupIngress":
            return handle_sg_ssh_open(event)

        # B) RunInstances / ModifyInstanceAttribute → (보조) 임계치 충족 시 알림
        if src == "aws.ec2" and dt == "AWS API Call via CloudTrail" and en in ("RunInstances", "ModifyInstanceAttribute"):
            return handle_instance_with_open_sg(event)

        # AccessKeyCreated
        if src == "aws.iam" and dt == "AWS API Call via CloudTrail":
            return handle_access_key_created(event)

        return _ret({"status": "noop"})
    except Exception as e:
        print("handler error:", e)
        raise
