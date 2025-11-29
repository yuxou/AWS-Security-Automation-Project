import os, json, time, re, boto3
from decimal import Decimal
from datetime import datetime
from botocore.exceptions import ClientError

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
WS_ENDPOINT         = os.environ.get("WS_ENDPOINT")
CONNECTIONS_TABLE   = os.environ.get("CONNECTIONS_TABLE", "RemediationWebSocketConnections")
INCIDENT_TABLE      = os.environ.get("INCIDENT_TABLE", "Incident")
ACCOUNT_ID_OVERRIDE = os.environ.get("ACCOUNT_ID_OVERRIDE")
QUARANTINE_SG_ID    = os.environ.get("QUARANTINE_SG_ID")         # sg-08af46f4a407ece7b
STATE_TABLE         = os.environ.get("STATE_TABLE", "security-alerts-state-v2")  # 필요시
STATE_PK            = os.environ.get("STATE_PK", "id")

COMPAT_V1           = os.environ.get("COMPAT_V1", "1") == "1"

# 태그 키 (원래 SG 기록용)
TAG_KEY_MODE        = os.environ.get("TAG_KEY_MODE", "AutoRemediation")
TAG_KEY_OLD_SG      = os.environ.get("TAG_KEY_OLD_SG", "OriginalSecurityGroups")
TAG_KEY_BY          = os.environ.get("TAG_KEY_BY", "AutoRemediationBy")
REMEDIATOR_NAME     = os.environ.get("REMEDIATOR_NAME", "ec2-open-ssh-auto-remediation-20251127")

ddb = boto3.resource("dynamodb")
ec2 = boto3.client("ec2")
sts = boto3.client("sts")

# ---------- 공용 유틸 ----------
def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def _ret(obj: dict):
    print(json.dumps(obj, ensure_ascii=False))
    return obj

_ARN_ACCT_RE = re.compile(r"arn:aws:(?:iam|sts)::(\d{12}):")

def extract_account_id(payload: dict) -> str:
    if ACCOUNT_ID_OVERRIDE:
        return ACCOUNT_ID_OVERRIDE
    acct = payload.get("account")
    if acct:
        return acct
    arn = payload.get("arn") or ""
    m = _ARN_ACCT_RE.search(arn)
    if m:
        return m.group(1)
    try:
        return sts.get_caller_identity().get("Account")
    except Exception:
        return ""

# ---------- WebSocket 전송 ----------
def ddb_resource():
    region = os.environ.get("AWS_REGION") or "us-east-1"
    try:
        region = WS_ENDPOINT.rstrip("/").split(".execute-api.", 1)[-1].split(".amazonaws.com", 1)[0] or region
    except Exception:
        pass
    return boto3.resource("dynamodb", region_name=region)

def post_to_ws_dashboard(remed_obj: dict):
    """
    자동대응 WebSocket용 JSON을 '있는 그대로' 전송.
    대시보드는 action/target/status 필드를 기대하므로,
    이 함수에서는 구조를 건드리지 않는다.
    """
    if not WS_ENDPOINT or not CONNECTIONS_TABLE:
        print("WS disabled; missing env")
        return

    endpoint_url = WS_ENDPOINT.rstrip("/")
    region = os.environ.get("AWS_REGION") or "us-east-1"
    try:
        region = endpoint_url.split(".execute-api.", 1)[-1].split(".amazonaws.com", 1)[0] or region
    except Exception:
        pass

    api = boto3.client("apigatewaymanagementapi", endpoint_url=endpoint_url, region_name=region)
    table = ddb_resource().Table(CONNECTIONS_TABLE)

    payload_bytes = json.dumps(_json_safe(remed_obj)).encode("utf-8")
    print("DEBUG_WS_AUTOREM:", json.dumps(remed_obj, ensure_ascii=False))

    ok = gone = err = 0
    last_key = None

    while True:
        scan_kwargs = {"ProjectionExpression": "connectionId"}
        if last_key:
            scan_kwargs["ExclusiveStartKey"] = last_key

        try:
            resp = table.scan(**scan_kwargs)
        except Exception as e:
            print("scan connections fail:", e)
            break

        for it in resp.get("Items") or []:
            cid = it.get("connectionId")
            if not cid:
                continue
            try:
                api.post_to_connection(ConnectionId=cid, Data=payload_bytes)
                ok += 1
            except api.exceptions.GoneException:
                gone += 1
                try:
                    table.delete_item(Key={"connectionId": cid})
                except Exception:
                    pass
            except ClientError as e:
                err += 1
                print("WS send error:", e.response.get("Error", {}).get("Code"))

        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break

    print(f"WS broadcast auto-remediation: ok={ok}, gone={gone}, err={err}")

# ---------- Incident 테이블 ----------
def incident_table():
    if not INCIDENT_TABLE:
        return None
    return ddb.Table(INCIDENT_TABLE)

def update_incident_status(incident_id: str, new_status: str, note_append: str | None = None):
    tbl = incident_table()
    if not tbl or not incident_id:
        return

    update_expr = "SET #st = :st, #u = :u"
    expr_attr_names = {"#st": "status", "#u": "updated_at"}
    expr_attr_vals = {
        ":st": new_status,
        ":u": now_iso()
    }

    # note를 "덮어쓰기" 방식으로만 업데이트
    if note_append:
        update_expr += ", #note = :note"
        expr_attr_names["#note"] = "note"
        expr_attr_vals[":note"] = note_append

    try:
        tbl.update_item(
            Key={"incident_id": incident_id},
            UpdateExpression=update_expr,
            ExpressionAttributeNames=expr_attr_names,
            ExpressionAttributeValues=expr_attr_vals,
        )
        print(f"✅ Incident {incident_id} updated → {new_status}")
    except Exception as e:
        print("Incident update failed:", e)

# ---------- EC2 유틸 ----------
def describe_instance(instance_id: str):
    try:
        resp = ec2.describe_instances(InstanceIds=[instance_id])
    except ClientError as e:
        print("describe_instances error:", e)
        return None

    resvs = resp.get("Reservations") or []
    for r in resvs:
        for inst in r.get("Instances") or []:
            if inst.get("InstanceId") == instance_id:
                return inst
    return None

def get_instance_sg_ids(instance: dict) -> list[str]:
    sgs = []
    for sg in instance.get("SecurityGroups") or []:
        gid = sg.get("GroupId")
        if gid:
            sgs.append(gid)
    return sgs

def tag_instance_quarantine(instance_id: str, old_sg_ids: list[str]):
    tags = [
        {"Key": TAG_KEY_MODE,   "Value": "OpenSSHQuarantine"},
        {"Key": TAG_KEY_OLD_SG, "Value": ",".join(old_sg_ids)},
        {"Key": TAG_KEY_BY,     "Value": REMEDIATOR_NAME},
    ]
    try:
        ec2.create_tags(Resources=[instance_id], Tags=tags)
        print(f"✅ Tagged instance {instance_id} for quarantine metadata")
    except ClientError as e:
        print("create_tags failed:", e)

def apply_quarantine_sg(instance_id: str, incident_id: str | None, base_payload: dict):
    """
    실제 자동대응 핵심:
    - 인스턴스 조회 → 현재 SG 목록 확보
    - 이미 격리 SG만 있으면 -> 상태만 보고(이미 격리) 대시보드/Incident 업데이트
    - 아니면 ModifyInstanceAttribute 로 SG 교체 + 태그
    """
    inst = describe_instance(instance_id)
    if not inst:
        raise RuntimeError(f"Instance not found: {instance_id}")

    current_sgs = get_instance_sg_ids(inst)
    print(f"[AUTO-REMED] {instance_id} current SGs = {current_sgs}")

    if not QUARANTINE_SG_ID:
        raise RuntimeError("QUARANTINE_SG_ID not set in env")

    account_id = extract_account_id(base_payload)
    region = base_payload.get("region") or os.environ.get("AWS_REGION", "us-east-1")
    now_ms = int(time.time() * 1000)

    # ✅ 1) 이미 격리된 상태라면: SG 변경은 안 하고, Incident/대시보드만 업데이트
    if len(current_sgs) == 1 and current_sgs[0] == QUARANTINE_SG_ID:
        print(f"[AUTO-REMED] {instance_id} already fully quarantined; skip")

        if incident_id:
            update_incident_status(
                incident_id,
                "MITIGATED",
                note_append=f"Instance was already quarantined by {REMEDIATOR_NAME}"
            )

        # 👉 대시보드용 Remediation JSON
        ws_evt = {
            "time": now_ms,
            "action": "EC2 SSH 오픈 인스턴스 상태 확인",
            "target": instance_id,
            "status": "SUCCEEDED",  # 상태 확인도 성공으로 처리
            "incident_id": incident_id,
            "playbook": base_payload.get("playbook") or "isolate-ec2",
            "account": account_id,
            "region": region,
        }
        post_to_ws_dashboard(ws_evt)
        return "ALREADY_QUARANTINED", current_sgs

    # ✅ 2) 아직 격리 안된 경우 → SG 교체 + 태그 + Incident + WS
    try:
        ec2.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=[QUARANTINE_SG_ID]
        )
        print(f"✅ Modified SG of {instance_id} → [{QUARANTINE_SG_ID}]")
    except ClientError as e:
        print("modify_instance_attribute failed:", e)
        raise

    # 태그에 기존 SG 기록
    tag_instance_quarantine(instance_id, current_sgs)

    if incident_id:
        update_incident_status(
            incident_id,
            "MITIGATED",
            note_append=f"Auto-quarantined by {REMEDIATOR_NAME}"
        )

    ws_evt = {
        "time": now_ms,
        "action": "EC2 SSH 오픈 인스턴스 자동 격리",
        "target": instance_id,
        "status": "SUCCEEDED",
        "incident_id": incident_id,
        "playbook": base_payload.get("playbook") or "isolate-ec2",
        "account": account_id,
        "region": region,
    }
    post_to_ws_dashboard(ws_evt)

    return "QUARANTINED", current_sgs

# ---------- 메인 핸들러 ----------
def lambda_handler(event, context):
    """
    SNS → Lambda 형태 입력 가정
    """
    print("EVENT:", json.dumps(event, ensure_ascii=False))

    records = event.get("Records") or []
    results = []

    for rec in records:
        sns = rec.get("Sns") or rec.get("sns") or {}
        msg_str = sns.get("Message") or sns.get("message")
        if not msg_str:
            results.append({"status": "skip_no_message"})
            continue

        try:
            msg = json.loads(msg_str)
        except Exception as e:
            print("Message JSON parse error:", e, msg_str)
            results.append({"status": "bad_message_json"})
            continue

        # 기대 포맷:
        # {
        #   "time": "...",
        #   "action": "QuarantineInstance",
        #   "target": "i-...",
        #   "playbook": "isolate-ec2",
        #   "status": "...",
        #   "incident_id": "..."
        # }
        action   = msg.get("action")
        playbook = msg.get("playbook")
        instance_id = msg.get("target")
        incident_id = msg.get("incident_id")   # 있을 때만 Incident 업데이트

        if action != "QuarantineInstance" or playbook != "isolate-ec2":
            print("skip non-target message:", msg)
            results.append({"status": "skip_non_target_message"})
            continue

        if not instance_id:
            print("no target instance in message")
            results.append({"status": "skip_no_instance"})
            continue

        base_payload = {
            "time": msg.get("time") or now_iso(),
            "playbook": playbook,
            "action": action,
            "arn": msg.get("arn") or "",
            "account": msg.get("account") or "",
            "region": msg.get("region") or os.environ.get("AWS_REGION", "us-east-1"),
        }

        try:
            state, old_sgs = apply_quarantine_sg(instance_id, incident_id, base_payload)
            results.append({
                "status": "ok",
                "state": state,
                "instance": instance_id,
                "old_sgs": old_sgs
            })
        except Exception as e:
            print("auto-remediation failed:", e)

            # 실패한 경우 Incident 상태 및 대시보드 둘 다 업데이트
            if incident_id:
                update_incident_status(
                    incident_id,
                    "PROCESSING",  # 필요하면 FAILED로 바꿔도 됨
                    note_append=f"Auto-remediation failed: {e}"
                )

            fail_evt = {
                "time": int(time.time()*1000),
                "action": "EC2 SSH 오픈 인스턴스 자동 격리",
                "target": instance_id,
                "status": "FAILED",
                "incident_id": incident_id,
                "playbook": playbook,
                "error": str(e),
                "account": base_payload.get("account"),
                "region": base_payload.get("region"),
            }
            post_to_ws_dashboard(fail_evt)

            results.append({
                "status": "error",
                "instance": instance_id,
                "error": str(e)
            })

    return _ret({"results": results})
