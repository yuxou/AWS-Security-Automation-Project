import os
import json
import time
import re
import boto3
from botocore.exceptions import ClientError

# ===== ENV =====
WS_ENDPOINT = os.environ.get("WS_ENDPOINT")  # https://.../prod/
CONNECTIONS_TABLE = os.environ.get("CONNECTIONS_TABLE", "WebSocketConnections")
STATE_TABLE = os.environ.get("STATE_TABLE", "security-alerts-state-v2")
ACCOUNT_ID_OVERRIDE = os.environ.get("ACCOUNT_ID_OVERRIDE")
SEVERITY_ON_POSITIVE = os.environ.get("SEVERITY_ON_POSITIVE", "LOW").upper()  # 대시보드 요구: LOW|MEDIUM|HIGH|CRITICAL

# 🔹 Incident 테이블 환경변수 추가
INCIDENT_TABLE = os.environ.get("INCIDENT_TABLE", "Incident")

# ===== AWS clients =====
sts_client = boto3.client("sts")


def ddb_resource():
    region = os.environ.get("AWS_REGION") or "us-east-1"
    try:
        region = WS_ENDPOINT.rstrip("/").split(".execute-api.", 1)[-1].split(".amazonaws.com", 1)[0] or region
    except Exception:
        pass
    return boto3.resource("dynamodb", region_name=region)


def api_ws():
    endpoint_url = WS_ENDPOINT.rstrip("/")
    region = os.environ.get("AWS_REGION") or "us-east-1"
    try:
        region = endpoint_url.split(".execute-api.", 1)[-1].split(".amazonaws.com", 1)[0] or region
    except Exception:
        pass
    return boto3.client("apigatewaymanagementapi", endpoint_url=endpoint_url, region_name=region)


# ===== Helpers =====
def _ret(obj):
    print(json.dumps(obj, ensure_ascii=False))
    return obj


_ARN_ACCT_RE = re.compile(r"arn:aws:(?:iam|sts)::(\d{12}):")


def extract_account_id(event: dict, principal_arn: str = "") -> str:
    if ACCOUNT_ID_OVERRIDE:
        return ACCOUNT_ID_OVERRIDE
    acct = event.get("account") or ((event.get("detail") or {}).get("userIdentity") or {}).get("accountId")
    if acct:
        return acct
    m = _ARN_ACCT_RE.search(principal_arn or "")
    if m:
        return m.group(1)
    try:
        return sts_client.get_caller_identity().get("Account")
    except Exception:
        return ""


def extract_region(event: dict) -> str:
    return event.get("region") or (event.get("detail") or {}).get("awsRegion") or ""


def _principal(event: dict) -> str:
    ui = (event.get("detail") or {}).get("userIdentity") or {}
    return ui.get("arn") or ui.get("principalId") or "unknown"


def _sg_id_from_detail(detail: dict) -> str:
    rp = (detail.get("requestParameters") or {})
    # revoke/delete 모두 groupId가 있을 가능성이 높음
    return rp.get("groupId") or rp.get("groupName") or "unknown-sg"


def _sg_arn(region: str, account: str, sgid: str) -> str:
    # SG ARN 형식 보정: arn:aws:ec2:region:account:security-group/sg-...
    if sgid and sgid.startswith("sg-"):
        return f"arn:aws:ec2:{region}:{account}:security-group/{sgid}"
    return ""


def normalize_source(source: str) -> str:
    if not source:
        return "Unknown"

    s = source.lower().strip()

    # 로그인/STS 계열
    if "signin" in s or "sts" in s:
        return "AWS Sign-In/STS"
    # CloudTrail
    if "cloudtrail" in s:
        return "CloudTrail"
    # CloudWatch
    if "cloudwatch" in s:
        return "CloudWatch"
    # S3
    if "s3" in s:
        return "S3"
    # EC2
    if "ec2" in s:
        return "EC2"
    # 기타 서비스: "aws.xxx" or "xxx.amazonaws.com"
    if s.endswith(".amazonaws.com"):
        svc = s.split(".")[0]
        return svc.capitalize()

    return source


# ===== Incident 히스토리 유틸 =====
def incident_table():
    if not INCIDENT_TABLE:
        return None
    return ddb_resource().Table(INCIDENT_TABLE)


def generate_incident_id(prefix: str = "inc") -> str:
    """
    예: inc-20251120-143000-123
    """
    ts = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    rand = int(time.time() * 1000) % 1000  # 약간 랜덤 느낌
    return f"{prefix}-{ts}-{rand:03d}"


def put_incident_record(event_type: str,
                        resource: str,
                        severity: str,
                        status: str = "NEW",
                        details: dict | None = None,
                        created_at: str | None = None):
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
      "details": { ... }
    }
    """
    tbl = incident_table()
    if not tbl:
        print("❌ INCIDENT_TABLE not configured; skip incident logging")
        return None

    created = created_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
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
        "details": details or {}
    }

    try:
        tbl.put_item(Item=item)
        print("✅ Incident stored:", json.dumps(item, ensure_ascii=False))
        return item
    except Exception as e:
        print("incident put fail:", e)
        return None


# ===== WebSocket broadcast =====
def broadcast_to_ws(payload: dict):
    if not WS_ENDPOINT or not CONNECTIONS_TABLE:
        print("WS disabled (missing env)")
        return

    api = api_ws()
    table = ddb_resource().Table(CONNECTIONS_TABLE)
    data_bytes = json.dumps(payload).encode("utf-8")

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
                    except Exception:
                        pass

        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break

    print(f"WS broadcast: ok={ok}, gone={gone}, err={err}")


# ===== Positive feedback: SG 위험 규칙 해소 탐지 =====

def _iter_permissions(detail: dict):
    rp = (detail.get("requestParameters") or {})
    items = ((rp.get("ipPermissions") or {}).get("items")) or []
    if isinstance(items, dict):
        items = [items]
    for p in items:
        yield p or {}


def _is_world_cidr(p: dict) -> bool:
    for r in (((p.get("ipRanges") or {}).get("items")) or []):
        if (r or {}).get("cidrIp") == "0.0.0.0/0":
            return True
    for r in (((p.get("ipv6Ranges") or {}).get("items")) or []):
        if (r or {}).get("cidrIpv6") == "::/0":
            return True
    return False


def _is_ssh_22_tcp(p: dict) -> bool:
    return (str(p.get("ipProtocol") or "").lower() == "tcp" and
            p.get("fromPort") == 22 and p.get("toPort") == 22)


def handle_ec2_positive_feedback(event):
    """
    CloudTrail EC2:
      - RevokeSecurityGroupIngress: SSH 22 world-open 규칙이 제거된 경우
      - DeleteSecurityGroup: 위험 SG 자체가 삭제된 경우(정보성)
    """
    detail = event.get("detail") or {}
    ename = detail.get("eventName")
    if ename not in ("RevokeSecurityGroupIngress", "DeleteSecurityGroup"):
        return _ret({"status": "skip_event"})

    principal = _principal(event)
    account = extract_account_id(event, principal)
    region = extract_region(event)
    sgid = _sg_id_from_detail(detail)
    arn_value = _sg_arn(region, account, sgid)

    etype = None
    # Revoke: 실제로 제거한 룰이 ssh 22 / world-open 맞는지 확인
    if ename == "RevokeSecurityGroupIngress":
        removed_world_ssh = False
        for p in _iter_permissions(detail):
            if _is_ssh_22_tcp(p) and _is_world_cidr(p):
                removed_world_ssh = True
                break
        if not removed_world_ssh:
            return _ret({"status": "skip_not_target_rule"})
        etype = "SG 규칙 Revoke로 위험 해소"  # 대시보드 type

    elif ename == "DeleteSecurityGroup":
        etype = "SG Delete로 위험 해소"  # 대시보드 type (정보성)

    payload = {
        "time": int(time.time() * 1000),
        "source": normalize_source(event.get("source")),
        "type": etype,
        "resource": sgid,
        "sg": sgid,
        "arn": arn_value,
        "account": account,
        "region": region,
        "severity": SEVERITY_ON_POSITIVE  # 보통 LOW (정보성)
    }

    # === Incident details (요청 형식) ===
    event_time_iso = event.get("time") or detail.get("eventTime") or time.strftime(
        "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
    )

    incident_details = {
        "time": event_time_iso,
        "source": "EC2",
        "type": etype,
        "sg": sgid or "",
        "arn": arn_value or "",
        "resource": arn_value or sgid or "",
        "account": account or "",
        "region": region or "",
        "alertType": "ALERT",   # 형식 통일
        "rulesViolated": [etype],
        "severity": SEVERITY_ON_POSITIVE
    }

    incident = put_incident_record(
        event_type=etype,
        resource=payload["resource"],
        severity=payload["severity"],
        status="NEW",
        details=incident_details,
        created_at=event_time_iso
    )
    if incident:
        payload["incident_id"] = incident["incident_id"]

    broadcast_to_ws(payload)
    return _ret({"status": "alert_sent", "etype": etype, "sg": sgid})


def handle_config_compliant(event):
    """
    AWS Config: SG_OPEN_TO_WORLD 규칙이 COMPLIANT 로 바뀐 경우 (positive)
    """
    detail = event.get("detail") or {}
    rule = (detail.get("configRuleName") or
            ((detail.get("newEvaluationResult") or {}).get("evaluationResultIdentifier") or {}).get(
                "evaluationResultQualifier", {}).get("configRuleName"))
    compliance = ((detail.get("newEvaluationResult") or {}).get("complianceType")
                  or detail.get("newEvaluationResult", {}).get("compliance", {}).get("complianceType"))

    if str(rule or "") not in ("SG_OPEN_TO_WORLD", "SecurityGroupOpenToWorld", "sg_open_to_world"):
        return _ret({"status": "skip_rule"})

    if str(compliance or "").upper() != "COMPLIANT":
        return _ret({"status": "skip_not_compliant"})

    account = event.get("account") or ""
    region = extract_region(event)
    res = ((detail.get("newEvaluationResult") or {}).get("evaluationResultIdentifier") or {}).get(
        "evaluationResultQualifier") or {}
    resource_id = res.get("resourceId") or "unknown-sg"
    resource_arn = res.get("resourceArn") or _sg_arn(region, account, resource_id)

    payload = {
        "time": int(time.time() * 1000),
        "source": normalize_source(event.get("source")),
        "type": "규정 준수로 위험 해소",
        "resource": resource_id,
        "sg": resource_id,
        "arn": resource_arn,
        "account": account,
        "region": region,
        "severity": SEVERITY_ON_POSITIVE
    }

    event_time_iso = event.get("time") or detail.get("resultRecordedTime") or time.strftime(
        "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
    )

    incident_details = {
        "time": event_time_iso,
        "source": "Config",
        "type": "규정 준수로 위험 해소",
        "sg": resource_id or "",
        "arn": resource_arn or "",
        "resource": resource_arn or resource_id or "",
        "account": account or "",
        "region": region or "",
        "alertType": "ALERT",
        "rulesViolated": ["규정 준수로 위험 해소"],
        "severity": SEVERITY_ON_POSITIVE
    }

    incident = put_incident_record(
        event_type=payload["type"],
        resource=payload["resource"],
        severity=payload["severity"],
        status="NEW",
        details=incident_details,
        created_at=event_time_iso
    )
    if incident:
        payload["incident_id"] = incident["incident_id"]

    broadcast_to_ws(payload)
    return _ret({"status": "alert_sent", "etype": "ConfigCompliant", "resource": resource_id})


# ===== Lambda entry =====
def lambda_handler(event, context):
    try:
        src = event.get("source")
        dtype = event.get("detail-type")

        # EC2 Security Group positive events (CloudTrail)
        if src == "aws.ec2" and dtype == "AWS API Call via CloudTrail":
            return handle_ec2_positive_feedback(event)

        # AWS Config compliance change (COMPLIANT)
        if src == "aws.config" and "Compliance Change" in (dtype or ""):
            return handle_config_compliant(event)

        return _ret({"status": "noop", "src": src, "dtype": dtype})
    except Exception as e:
        print("handler error:", e)
        raise
