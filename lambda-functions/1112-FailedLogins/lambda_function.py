# file: lambda_function.py  (Python 3.12)
import os
import json
import time
import boto3
import traceback
import random
from botocore.exceptions import ClientError
from typing import Any, Dict
from datetime import datetime, timezone, timedelta

# ====== ENV ======
CONNECTIONS_TABLE = os.environ["CONNECTIONS_TABLE"]   # WebSocketConnections (pk: connectionId)
WS_ENDPOINT       = os.environ["WS_ENDPOINT"]         # e.g. https://xxxx.execute-api.ap-northeast-2.amazonaws.com/prod/@connections
COUNTER_TABLE     = os.environ.get("COUNTER_TABLE", "FailedLogins")
WINDOW_MIN        = int(os.getenv("WINDOW_MIN", "15"))
LOCK_MIN          = int(os.getenv("LOCK_MIN", "10"))
POLICY_NAME       = os.getenv("POLICY_NAME", "auto-temp-total-deny")
LOCK_CONSOLE_BY_LOGINPROFILE = os.getenv("LOCK_CONSOLE_BY_LOGINPROFILE", "false").lower() == "true"

# Incident 테이블 이름 (환경변수로 관리)
INCIDENT_TABLE    = os.environ.get("INCIDENT_TABLE", "Incident")

# ====== CLIENTS ======
dynamodb = boto3.resource("dynamodb")
conn_tbl = dynamodb.Table(CONNECTIONS_TABLE)
cnt_tbl  = dynamodb.Table(COUNTER_TABLE)
apigw    = boto3.client("apigatewaymanagementapi", endpoint_url=WS_ENDPOINT)
iam      = boto3.client("iam")
incident_tbl = dynamodb.Table(INCIDENT_TABLE)

# ====== COMMON HELPERS ======
def epoch_ms() -> int:
    return int(time.time() * 1000)

def ttl_in(seconds: int) -> int:
    # DynamoDB TTL은 epoch seconds
    return int(time.time()) + seconds

def now_iso() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

def generate_incident_id(prefix: str = "inc") -> str:
    """
    예: inc-20251119-153045-123  (UTC 기준 날짜/시간 + 000~999 랜덤 3자리)
    """
    ts = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    rand = random.randint(0, 999)
    return f"{prefix}-{ts}-{rand:03d}"

# ====== Incident 헬퍼 ======
def update_incident_for_action(
    incident_id: str | None,
    playbook: str,
    action_result: str,     # "SUCCEEDED" | "FAILED"
    message: str | None = None,
    action_text: str | None = None,  # action → Incident.type
    target: str | None = None,       # target → Incident.resource
    severity: str | None = None,     # Incident.severity
) -> None:
    """
    대응 함수 결과에 따라 Incident를 생성/업데이트한다.

    - action_result == "SUCCEEDED" -> status = "MITIGATED"
    - action_result == "FAILED"   -> status = "PROCESSING"

    - incident_id 가 없으면: 자동 대응용 Incident 레코드를 새로 생성
    - incident_id 가 있으면: 해당 Incident 레코드를 UpdateItem
    """
    # 1) 결과에 따른 status 결정
    if action_result == "SUCCEEDED":
        incident_status = "MITIGATED"
    elif action_result == "FAILED":
        incident_status = "PROCESSING"
    else:
        print(f"[INCIDENT] skip update for result={action_result}")
        return

    # 2) incident_id 가 없으면 → 새 Incident 생성 (자동 대응)
    if not incident_id:
        try:
            new_id = generate_incident_id(prefix="inc")
            now = now_iso()
            item: Dict[str, Any] = {
                "incident_id": new_id,
                "status": incident_status,
                "created_at": now,
                "updated_at": now,
                "last_action": playbook,
                "last_action_result": action_result,
            }
            if message:
                item["last_action_msg"] = message
            if action_text is not None:
                item["type"] = action_text        # action → type
            if target is not None:
                item["resource"] = target         # target → resource
            if severity is not None:
                item["severity"] = severity       # severity

            # 충돌을 더 안전하게 방지하고 싶다면 아래 ConditionExpression을 사용:
            # incident_tbl.put_item(Item=item, ConditionExpression="attribute_not_exists(incident_id)")
            incident_tbl.put_item(Item=item)
            print(f"[INCIDENT] created new incident_id={new_id} status={incident_status}")
        except Exception as e:
            print(f"[INCIDENT][ERROR] create failed: {e}")
            traceback.print_exc()
        return

    # 3) incident_id 가 있으면 → 기존 Incident 업데이트
    update_expr = (
        "SET #s = :s, "
        "updated_at = :u, "
        "last_action = :a, "
        "last_action_result = :r"
    )
    expr_names: Dict[str, str] = {"#s": "status"}
    expr_values: Dict[str, Any] = {
        ":s": incident_status,
        ":u": now_iso(),
        ":a": playbook,
        ":r": action_result,
    }

    if message:
        update_expr += ", last_action_msg = :m"
        expr_values[":m"] = message

    if action_text is not None:
        update_expr += ", #t = :t"
        expr_names["#t"] = "type"
        expr_values[":t"] = action_text

    if target is not None:
        update_expr += ", #res = :res"
        expr_names["#res"] = "resource"
        expr_values[":res"] = target

    if severity is not None:
        update_expr += ", severity = :sev"
        expr_values[":sev"] = severity

    try:
        print(
            f"[INCIDENT] update incident_id={incident_id} "
            f"status={incident_status} result={action_result} "
            f"type={action_text} resource={target} severity={severity}"
        )
        incident_tbl.update_item(
            Key={"incident_id": incident_id},
            UpdateExpression=update_expr,
            ExpressionAttributeNames=expr_names,
            ExpressionAttributeValues=expr_values,
        )
    except Exception as e:
        print(f"[INCIDENT][ERROR] update failed for {incident_id}: {e}")
        traceback.print_exc()

# ====== WEBSOCKET BROADCAST ======
def ws_broadcast(payload: Dict[str, Any]) -> None:
    """
    모든 연결된 WebSocket 클라이언트로 payload 전송
    """
    print("[WS] START broadcast")
    print("[WS] endpoint =", WS_ENDPOINT)
    print("[WS] payload =", json.dumps(payload, ensure_ascii=False))

    scan_kwargs: Dict[str, Any] = {}
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    sent_count = 0

    while True:
        try:
            res = conn_tbl.scan(**scan_kwargs)
        except Exception as e:
            print("[WS][ERROR] DynamoDB scan error:", e)
            traceback.print_exc()
            return

        # --------- loop over connections ---------
        items = res.get("Items", [])
        print(f"[WS] scan items len={len(items)}")
        for it in items:
            cid = it.get("connectionId")
            if not cid:
                print("[WS] item without connectionId:", it)
                continue
            try:
                apigw.post_to_connection(ConnectionId=cid, Data=data)
                sent_count += 1
                print(f"[WS] sent to connectionId={cid}")
            except apigw.exceptions.GoneException:
                print(f"[WS] GoneException for {cid}, delete from table")
                try:
                    conn_tbl.delete_item(Key={"connectionId": cid})
                except Exception as e2:
                    print(f"[WS] delete_item error for {cid}: {e2}")
            except ClientError as e:
                print(f"[WS] ClientError for {cid}: {e}")
            except Exception as e:
                print(f"[WS] unexpected error for {cid}: {e}")
                traceback.print_exc()

        if "LastEvaluatedKey" in res:
            scan_kwargs["ExclusiveStartKey"] = res["LastEvaluatedKey"]
        else:
            break

    print(f"[WS] END broadcast, sent_count={sent_count}")

def emit_action(action_ko: str, target: str, playbook: str, status: str):
    """
    status: TRIGGERED | RUNNING | SUCCEEDED | FAILED
    """
    payload = {
        "time": epoch_ms(),
        "action": action_ko,
        "target": target,
        "playbook": playbook,
        "status": status
    }
    print(f"[ACTION] emit_action status={status} target={target}")
    ws_broadcast(payload)

# ====== IAM 조치 ======
DENY_ALL_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Deny",
        "Action": "*",
        "Resource": "*"
    }]
}

def _safe_put_user_policy(user_name: str):
    print(f"[IAM] put_user_policy user={user_name}")
    iam.put_user_policy(
        UserName=user_name,
        PolicyName=POLICY_NAME,
        PolicyDocument=json.dumps(DENY_ALL_POLICY)
    )

def _safe_delete_user_policy(user_name: str):
    print(f"[IAM] delete_user_policy user={user_name}")
    try:
        iam.delete_user_policy(UserName=user_name, PolicyName=POLICY_NAME)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise

def _safe_delete_login_profile(user_name: str):
    print(f"[IAM] delete_login_profile user={user_name}")
    try:
        iam.delete_login_profile(UserName=user_name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise

def _disable_all_access_keys(user_name: str):
    print(f"[IAM] disable_all_access_keys user={user_name}")
    keys = iam.list_access_keys(UserName=user_name).get("AccessKeyMetadata", [])
    for k in keys:
        if k.get("Status") == "Active":
            iam.update_access_key(
                UserName=user_name,
                AccessKeyId=k["AccessKeyId"],
                Status="Inactive"
            )

# ====== 카운터/락 ======
def _counter_key(acct: str, user: str) -> Dict[str, str]:
    return {"pk": f"acct#{acct}#user#{user}", "sk": "counter"}

def _lock_item_key(acct: str, user: str) -> Dict[str, str]:
    return {"pk": f"acct#{acct}#user#{user}", "sk": "lock"}

def inc_failure_and_get_count(acct: str, user: str) -> int:
    r = cnt_tbl.update_item(
        Key=_counter_key(acct, user),
        UpdateExpression="ADD #c :one SET #ls=:now, #ttl=:ttl",
        ExpressionAttributeNames={"#c": "count", "#ls": "lastSeen", "#ttl": "ttl"},
        ExpressionAttributeValues={
            ":one": 1,
            ":now": epoch_ms(),
            ":ttl": ttl_in(WINDOW_MIN * 60)
        },
        ReturnValues="ALL_NEW",
    )
    c = int(r["Attributes"]["count"])
    print(f"[COUNTER] acct={acct} user={user} count={c}")
    return c

def is_locked(acct: str, user: str) -> bool:
    r = cnt_tbl.get_item(Key=_lock_item_key(acct, user))
    it = r.get("Item")
    locked = bool(it and int(it.get("lockUntil", 0)) > epoch_ms())
    print(f"[LOCK] is_locked acct={acct} user={user} -> {locked}")
    return locked

def put_lock(acct: str, user: str, until_ms: int):
    print(f"[LOCK] put_lock acct={acct} user={user} until_ms={until_ms}")
    cnt_tbl.put_item(Item={
        **_lock_item_key(acct, user),
        "lockUntil": until_ms,
        "ttl": int(until_ms / 1000) + 3600
    })

# ====== 스케줄 해제 ======
def schedule_unlock_once(acct: str, user_name: str, user_arn: str, unlock_at_ms: int,
                         incident_id: str | None = None):
    """
    unlock 스케줄에 incident_id를 같이 넣어 두면,
    나중에 unlock 시에도 Incident를 갱신할 수 있음(옵션).
    """
    region = os.environ.get("SCHEDULER_REGION", "us-east-1")
    _scheduler = boto3.client("scheduler", region_name=region)

    sched_name = f"unlock-{acct}-{user_name}-{unlock_at_ms}"
    role_arn   = os.environ["SCHEDULER_ROLE_ARN"]
    target_arn = os.environ["THIS_LAMBDA_ARN"]

    unlock_dt_utc = datetime.fromtimestamp(unlock_at_ms / 1000, tz=timezone.utc)

    min_dt = datetime.now(timezone.utc) + timedelta(seconds=90)
    if unlock_dt_utc < min_dt:
        unlock_dt_utc = min_dt

    unlock_iso_noz = unlock_dt_utc.strftime("%Y-%m-%dT%H:%M:%S")
    expr = f"at({unlock_iso_noz})"

    body: Dict[str, Any] = {
        "action": "잠금 해제",
        "playbook": "lock-signin-10m",
        "mode": "unlock",
        "account": acct,
        "userName": user_name,
        "userArn": user_arn
    }

    if incident_id:
        body["incident_id"] = incident_id

    print(f"[SCHED] create_schedule name={sched_name} expr={expr}")
    try:
        resp = _scheduler.create_schedule(
            Name=sched_name,
            ScheduleExpression=expr,
            ScheduleExpressionTimezone="UTC",
            FlexibleTimeWindow={"Mode": "OFF"},
            Target={
                "Arn": target_arn,
                "RoleArn": role_arn,
                "Input": json.dumps(body, ensure_ascii=False)
            },
            State="ENABLED",
            Description=f"Unlock {user_name} at {unlock_iso_noz}Z"
        )
        print(f"[SCHED] create_schedule OK arn={resp.get('ScheduleArn')}")
    except Exception as e:
        print(f"[SCHED][ERROR] create_schedule failed err={e}")
        traceback.print_exc()
        raise

# ====== CORE PLAYBOOK ======
def run_playbook_lock_signin_10m(acct: str, region: str, user_type: str,
                                 user_name: str, user_arn: str,
                                 incident_id: str | None = None):
    """
    콘솔 로그인 3회 실패 시 10분 잠금 대응 플레이북.

    incident_id가 넘어오면:
      - SUCCEEDED  : 해당 Incident.status = MITIGATED (type/resource/severity 포함)
      - FAILED     : 해당 Incident.status = PROCESSING

    incident_id가 없으면:
      - 자동으로 Incident 레코드를 새로 생성 (auto-타임스탬프 ID)
    """
    playbook = "lock-signin-10m"
    target   = user_arn or f"iam-user:{user_name}"
    action_ko = "콘솔 로그인 10분 잠금"

    print(f"[PLAYBOOK] start acct={acct} user={user_name} type={user_type} incident_id={incident_id}")

    # 1) TRIGGERED
    emit_action(action_ko, target, playbook, "TRIGGERED")

    try:
        # 2) RUNNING
        emit_action(action_ko, target, playbook, "RUNNING")

        if user_type != "IAMUser":
            raise RuntimeError(f"Unsupported userType for this playbook: {user_type}")

        _safe_put_user_policy(user_name)

        if LOCK_CONSOLE_BY_LOGINPROFILE:
            _safe_delete_login_profile(user_name)

        # _disable_all_access_keys(user_name)

        unlock_at = epoch_ms() + LOCK_MIN * 60 * 1000
        put_lock(acct, user_name, unlock_at)
        schedule_unlock_once(acct, user_name, user_arn or target, unlock_at, incident_id=incident_id)

        # 3) SUCCEEDED
        emit_action(action_ko, target, playbook, "SUCCEEDED")
        print("[PLAYBOOK] done SUCCEEDED")

        # SUCCEEDED → Incident(type, resource, severity(HIGH))
        update_incident_for_action(
            incident_id=incident_id,
            playbook=playbook,
            action_result="SUCCEEDED",
            message="lock-signin-10m playbook succeeded",
            action_text=action_ko,   # type
            target=target,           # resource
            severity="HIGH",
        )

    except Exception as e:
        print("[PLAYBOOK][ERROR] failed:", e)
        traceback.print_exc()
        emit_action(action_ko, target, playbook, "FAILED")

        update_incident_for_action(
            incident_id=incident_id,
            playbook=playbook,
            action_result="FAILED",
            message=str(e),
            action_text=action_ko,
            target=target,
            severity="HIGH",
        )

# ====== UNLOCK ======
def unlock_user(acct: str, user_name: str, user_arn: str, incident_id: str | None = None):
    """
    잠금 해제 시에도 Incident 로그 남김.
    - type     : "콘솔 로그인 10분 잠금 해제"
    - resource : target
    - severity : LOW
    """
    playbook = "lock-signin-10m"
    target   = user_arn or f"iam-user:{user_name}"
    action_ko= "콘솔 로그인 10분 잠금 해제"

    print(f"[UNLOCK] start acct={acct} user={user_name} incident_id={incident_id}")

    emit_action(action_ko, target, playbook, "RUNNING")
    try:
        _safe_delete_user_policy(user_name)
        emit_action(action_ko, target, playbook, "SUCCEEDED")
        print("[UNLOCK] done SUCCEEDED")

        update_incident_for_action(
            incident_id=incident_id,
            playbook=playbook,
            action_result="SUCCEEDED",
            message="lock-signin-10m unlock succeeded",
            action_text=action_ko,
            target=target,
            severity="LOW",
        )

    except Exception as e:
        print("[UNLOCK][ERROR] failed:", e)
        traceback.print_exc()
        emit_action(action_ko, target, playbook, "FAILED")
        update_incident_for_action(
            incident_id=incident_id,
            playbook=playbook,
            action_result="FAILED",
            message=str(e),
            action_text=action_ko,
            target=target,
            severity="LOW",
        )

# ====== EVENT PARSER ======
def parse_console_login_failure(event: Dict[str, Any]) -> Dict[str, Any]:
    d = event.get("detail", {}) or {}
    ui = d.get("userIdentity", {}) or {}
    rec = {
        "account": d.get("recipientAccountId") or ui.get("accountId") or event.get("account"),
        "region": d.get("awsRegion") or event.get("region"),
        "userType": ui.get("type") or "Unknown",
        "userName": ui.get("userName") or "Unknown",
        "userArn": ui.get("arn") or "",
        "success": (d.get("responseElements", {}).get("ConsoleLogin") == "Success")
    }

    # event / detail 안에 incident_id 있으면 같이 추출
    incident_id = (
        event.get("incident_id")
        or d.get("incident_id")
        or ""
    )
    if isinstance(incident_id, str):
        rec["incident_id"] = incident_id.strip() or None
    else:
        rec["incident_id"] = None

    print("[PARSE] rec =", rec)
    return rec

# ====== HANDLER ======
def handler(event, context):
    print("=== 1112-FailedLogins handler START ===")
    print(json.dumps(event, ensure_ascii=False))

    # unlock 모드
    if (event.get("mode") or "") == "unlock":
        print("[MODE] unlock")
        incident_id = event.get("incident_id")
        unlock_user(event["account"], event["userName"], event.get("userArn", ""), incident_id=incident_id)
        return {"ok": True, "mode": "unlock"}

    # 실패 이벤트 처리
    rec = parse_console_login_failure(event)
    if rec["success"]:
        print("[SKIP] success event")
        return {"ok": True, "skipped": "success event"}

    acct = str(rec["account"] or "unknown")
    user = str(rec["userName"] or "unknown")

    count = inc_failure_and_get_count(acct, user)

    if is_locked(acct, user):
        print("[INFO] already locked, skip playbook")
        return {"ok": True, "skipped": "already locked", "count": count}

    if count >= 3:
        print("[TRIGGER] count >= 3, run playbook")
        run_playbook_lock_signin_10m(
            acct,
            rec["region"],
            rec["userType"],
            rec["userName"],
            rec["userArn"],
            incident_id=rec.get("incident_id")
        )
    else:
        print("[INFO] count < 3, no playbook yet")

    print("=== 1112-FailedLogins handler END ===")
    return {"ok": True, "count": count}
