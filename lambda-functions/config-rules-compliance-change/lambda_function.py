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
SEVERITY_ON_ALERT = os.environ.get("SEVERITY_ON_ALERT", "HIGH").upper()  # LOW|MEDIUM|HIGH|CRITICAL

# 🔹 Incident 테이블 환경변수 추가
INCIDENT_TABLE = os.environ.get("INCIDENT_TABLE", "Incident")

# ===== AWS clients =====
sts_client = boto3.client("sts")


def ddb_resource():
    """
    WebSocketConnections / Incident 테이블이 위치한 리전을 WS_ENDPOINT에서 추론(없으면 기본 us-east-1).
    """
    region = os.environ.get("AWS_REGION") or "us-east-1"
    try:
        region = WS_ENDPOINT.rstrip("/").split(".execute-api.", 1)[-1].split(".amazonaws.com", 1)[0] or region
    except Exception:
        pass
    return boto3.resource("dynamodb", region_name=region)


def api_ws():
    """
    API Gateway Management API 클라이언트. endpoint_url은 WS stage까지 포함.
    """
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
    acct = event.get("account")
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
    # Config 이벤트는 event["region"] 필드가 일반적으로 존재
    return event.get("region") or (event.get("detail") or {}).get("awsRegion") or os.environ.get("AWS_REGION") or "us-east-1"


def _sg_arn(region: str, account: str, sgid: str) -> str:
    if sgid and sgid.startswith("sg-"):
        return f"arn:aws:ec2:{region}:{account}:security-group/{sgid}"
    return ""


def _get_config_rule_name(detail: dict) -> str:
    # 다양한 이름 케이스 지원
    rn = (detail.get("configRuleName") or "").strip()
    return rn


def _get_config_compliance(detail: dict) -> str:
    comp = (((detail.get("newEvaluationResult") or {}).get("evaluationResultIdentifier") or {})
            .get("evaluationResultQualifier") or {}).get("complianceType")
    # 일부 이벤트는 바로 newEvaluationResult.complianceType에 존재
    return (detail.get("newEvaluationResult", {}) or {}).get("complianceType") or comp or ""


def _get_sg_id_from_detail(detail: dict) -> str:
    """
    Config Compliance 이벤트에서 SG ID를 최대한 견고하게 추출.
    보통은 detail.resourceId 또는 newEvaluationResult.evaluationResultIdentifier.evaluationResultQualifier.resourceId 에 들어있음.
    """
    sgid = (detail.get("resourceId")
            or (((detail.get("newEvaluationResult") or {}).get("evaluationResultIdentifier") or {})
                .get("evaluationResultQualifier") or {}).get("resourceId")
            or "")
    return sgid


# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# source 표기 통일 함수
def normalize_source(source: str) -> str:
    """
    CloudTrail의 raw source 값(aws.signin, ec2.amazonaws.com 등)을
    대시보드에서 쓰기 좋은 사람 친화적 이름으로 통일한다.
    """
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

    # 기타 서비스: "aws.xxx" or "xxx.amazonaws.com" 형태를 사람이 읽기 쉽게 변환
    # 예: "lambda.amazonaws.com" → "Lambda"
    if s.endswith(".amazonaws.com"):
        svc = s.split(".")[0]  # lambda.amazonaws.com → lambda
        return svc.capitalize()

    # 기본적으로 원본 값 반환 (최소 변경)
    return source
# <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<


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
      "details": { ... }   # 이번에 추가
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


# ===== Scenario #8: AWS Config SG_OPEN_TO_WORLD NON_COMPLIANT =====
_ACCEPTED_RULE_NAMES = {"SG_OPEN_TO_WORLD", "SecurityGroupOpenToWorld", "security-group-open-to-world", "restricted-ssh"}


def handle_config_sg_open_world(event):
    src = event.get("source")
    print("DEBUG source =", src)  # 디버그용

    if src not in ("aws.config", "my.test.config"):
        # 진짜 엉뚱한 소스면 스킵
        return _ret({"status": "skip_src", "src": src})

    detail = event.get("detail") or {}
    rule_name = _get_config_rule_name(detail)
    if rule_name not in _ACCEPTED_RULE_NAMES:
        # 다른 규칙이면 스킵
        return _ret({"status": "skip_rule", "rule": rule_name})

    # 비준수만 (NON_COMPLIANT)
    compliance = _get_config_compliance(detail)
    if compliance != "NON_COMPLIANT":
        return _ret({"status": "skip_compliance", "compliance": compliance})

    sgid = _get_sg_id_from_detail(detail)
    region = extract_region(event)
    account = extract_account_id(event)

    arn_value = _sg_arn(region, account, sgid)

    # ===== 대시보드로 보낼 평면 JSON =====
    payload = {
        "time": int(time.time() * 1000),      # epoch millis (필수)
        "source": normalize_source(event.get("source") or "AWS Config"),
        "type": "SG_OpenToWorld 위반 감지",
        "resource": sgid,                     # SG ID
        "sg": sgid,                           # SG ID (별도 표기)
        "arn": arn_value,                     # SG ARN
        "account": account,
        "region": region,
        "severity": SEVERITY_ON_ALERT         # LOW|MED|HIGH|CRITICAL
    }

    # ===== Incident details JSON (요청 형식) =====
    event_time_iso = event.get("time") or detail.get("resultRecordedTime") or time.strftime(
        "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
    )

    incident_details = {
        "time": event_time_iso,
        "source": "Config",  # 사람이 보기 좋게
        "type": "SG_OpenToWorld 위반 감지",
        "sg": sgid or "",
        "arn": arn_value or "",
        "resource": arn_value or sgid or "",
        "account": account or "",
        "region": region or "",
        "alertType": "ALERT",
        "rulesViolated": ["SG_OpenToWorld 위반 감지"],
        "severity": SEVERITY_ON_ALERT
    }

    # 🔹 Incident 기록
    incident = put_incident_record(
        event_type=payload["type"],
        resource=payload["resource"],
        severity=payload["severity"],
        status="NEW",
        details=incident_details,
        created_at=event_time_iso
    )
    if incident:
        # 대시보드 payload에도 incident_id 포함
        payload["incident_id"] = incident["incident_id"]

    broadcast_to_ws(payload)
    return _ret({"status": "alert_sent", "rule": rule_name, "sg": sgid})


# ===== Lambda entry =====
def lambda_handler(event, context):
    try:
        print("RAW EVENT:", json.dumps(event, ensure_ascii=False))

        # source + detail-type 둘 다 체크하면서 테스트 소스도 허용
        if event.get("source") in ("aws.config", "my.test.config") and \
           event.get("detail-type") == "Config Rules Compliance Change":
            return handle_config_sg_open_world(event)

        return _ret({"status": "noop"})
    except Exception as e:
        print("handler error:", e)
        raise

