# file: lambda_function.py  (Python 3.12)
"""
MFA 이벤트(신규 등록/비활성화/우회) 탐지 → WebSocket 브로드캐스트 + Incident 저장

ENV
- CONNECTIONS_TABLE : DynamoDB 테이블명 (connectionId 저장)
- WS_ENDPOINT       : WebSocket Stage URL (https://{api-id}.execute-api.{region}.amazonaws.com/{stage})
- INCIDENT_TABLE    : Incident 테이블명 (기본값 'Incident')

포인트
- WS_ENDPOINT에서 리전 자동 추출 → 같은 리전의 DDB/APIGW 호출
- CloudTrail detail의 None 값에 대해 Null-safe 접근(특히 responseElements)
- '시도/완료/실패' 3단계 + 'MFA 새로운 등록/비활성화/우회' 구분
- 요청 사항: 비활성화 중복 알림 방지 → DeactivateMFADevice는 **전송 억제**, DeleteVirtualMFADevice만 전송
- Incident 테이블에는 meta 필드에 device + ip + MFA 메타데이터 + actor/target 저장 (incident_details 사용 안 함)
"""

import os
import re
import json
import time
import random
from datetime import datetime

import boto3
from botocore.exceptions import ClientError

# ===== ENV =====
CONNECTIONS_TABLE = os.environ.get("CONNECTIONS_TABLE", "WebSocketConnections")
WS_ENDPOINT       = os.environ["WS_ENDPOINT"]  # e.g. https://abcd.execute-api.us-east-1.amazonaws.com/prod
INCIDENT_TABLE    = os.environ.get("INCIDENT_TABLE", "Incident")

# ===== region inference from WS endpoint =====
def _infer_region_from_ws(endpoint: str) -> str:
    m = re.search(r"\.execute-api\.([a-z0-9-]+)\.amazonaws\.com", endpoint)
    return m.group(1) if m else os.environ.get("AWS_REGION", "us-east-1")

API_REGION = _infer_region_from_ws(WS_ENDPOINT)

# ===== AWS clients =====
dynamodb   = boto3.resource("dynamodb", region_name=API_REGION)
conn_table = dynamodb.Table(CONNECTIONS_TABLE)
incident_table = dynamodb.Table(INCIDENT_TABLE)
apigw      = boto3.client("apigatewaymanagementapi", endpoint_url=WS_ENDPOINT, region_name=API_REGION)

# ---------- helpers ----------
def epoch_ms_from_iso(s: str | None) -> int:
    """ISO8601 or epoch(s/ms) → epoch millis; fallback now"""
    if not s:
        return int(time.time() * 1000)
    try:
        return int(datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp() * 1000)
    except Exception:
        try:
            v = int(float(s))
            return v if v > 10**12 else v * 1000
        except Exception:
            return int(time.time() * 1000)

def _as_dict(v):
    """dict가 아니면 빈 dict로 반환(Null-safe 접근용)"""
    return v if isinstance(v, dict) else {}

def normalize_source(source: str) -> str:
    """CloudTrail raw 'source'를 사람 친화적 라벨로 통일"""
    if not source:
        return "Unknown"
    s = source.lower().strip()

    # 로그인/STS
    if "signin" in s or "sts" in s:
        return "AWS Sign-In/STS"
    # IAM
    if "iam" in s or s == "aws.iam" or "iam.amazonaws.com" in s:
        return "AWS IAM"
    if "cloudtrail" in s:
        return "CloudTrail"
    if "cloudwatch" in s:
        return "CloudWatch"
    if "s3" in s:
        return "S3"
    if "ec2" in s:
        return "EC2"

    # *.amazonaws.com → 앞부분 Capitalize
    if s.endswith(".amazonaws.com"):
        svc = s.split(".")[0]
        return svc.capitalize()

    return source

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

# ---- 상태/유형 판정: 시도/완료/실패 3단계 ----
def determine_event_type(detail: dict):
    """
    반환:
      - dict(type_str, severity, status, meta)  또는
      - None (전송 억제)

    정책:
      - 등록:   CreateVirtualMFADevice/AssociateSoftwareToken = 시도, EnableMFADevice = 완료
      - 비활성: DeleteVirtualMFADevice = 완료(전송), DeactivateMFADevice = **전송 억제**
      - 실패: errorCode 존재 시 '실패'
      - 우회: ConsoleLogin 성공 + MFAUsed No/빈값 → 완료
    """
    try:
        event_name  = str(detail.get("eventName") or "")
        event_src   = str(detail.get("eventSource") or "").lower()

        add = _as_dict(detail.get("additionalEventData"))
        mfa_used = str(add.get("MFAUsed") or add.get("mfaUsed") or "")

        error_code  = detail.get("errorCode") or _as_dict(detail.get("detail")).get("errorCode")

        # Null-safe로 ConsoleLogin 결과 추출
        re_top    = _as_dict(detail.get("responseElements"))
        re_nested = _as_dict(_as_dict(detail.get("detail")).get("responseElements"))

        console_out = (
            re_top.get("ConsoleLogin")
            or re_nested.get("ConsoleLogin")
            or re_top.get("SignInStatus")
            or re_nested.get("SignInStatus")
        )

        # 성공 판정
        if event_name == "ConsoleLogin":
            success = bool(console_out and "success" in str(console_out).lower())
        else:
            success = not bool(error_code)

        def _status(step_if_success: str) -> str:
            # 성공이면 지정된 step_if_success("시도"/"완료"), 실패면 "실패"
            return step_if_success if success else "실패"

        meta = {
            "api": event_name,
            "mfaUsed": mfa_used,
            "consoleOutcome": console_out,
            "errorCode": error_code
        }

        # ===== MFA 등록 (새로운 등록/재등록 포함) =====
        if event_name in ("CreateVirtualMFADevice", "AssociateSoftwareToken"):
            status = _status("시도")
            return {
                "type_str": f"MFA 새로운 등록: {status}",
                "severity": "HIGH" if status == "실패" else "MEDIUM",
                "status": status,
                "meta": meta
            }

        if event_name == "EnableMFADevice":
            status = _status("완료")
            return {
                "type_str": f"MFA 새로운 등록: {status}",
                "severity": "HIGH" if status == "실패" else "LOW",
                "status": status,
                "meta": meta
            }

        # ===== MFA 비활성화 =====
        if event_name == "DeactivateMFADevice":
            # 요청사항: 비활성화 중복 알림 방지 → 이 단계는 전송 억제
            return None

        if event_name == "DeleteVirtualMFADevice":
            status = _status("완료")
            return {
                "type_str": f"MFA 비활성화: {status}",
                "severity": "CRITICAL" if status == "완료" else "HIGH",
                "status": status,
                "meta": meta
            }

        # ===== 콘솔 로그인 우회(미사용) =====
        if event_name == "ConsoleLogin" or "signin" in event_src:
            if (mfa_used or "").lower() in ("no", ""):
                status = _status("완료")
                return {
                    "type_str": f"MFA 우회: {status}",
                    "severity": "CRITICAL" if status == "완료" else "HIGH",
                    "status": status,
                    "meta": meta
                }
            else:
                status = _status("완료")
                return {
                    "type_str": f"ConsoleLogin (MFA 사용): {status}",
                    "severity": "LOW",
                    "status": status,
                    "meta": meta
                }

        # ===== 기타 =====
        status = "완료" if success else "실패"
        return {
            "type_str": f"Unknown:{event_name}",
            "severity": "LOW",
            "status": status,
            "meta": meta
        }

    except Exception as e:
        return {
            "type_str": "Unknown:ParseError",
            "severity": "LOW",
            "status": "실패",
            "meta": {"error": str(e)[:200], "rawKeys": list(detail.keys())[:12]}
        }

# ---- detail 필드 추출 유틸 ----
def _extract_account(detail: dict, event: dict) -> str:
    acct = detail.get("recipientAccountId") or detail.get("account") or detail.get("awsAccountId") or ""
    if not acct:
        ui = _as_dict(detail.get("userIdentity"))
        if ui.get("accountId"):
            acct = ui["accountId"]
        elif ui.get("arn"):
            try:
                acct = ui["arn"].split(":")[4]
            except Exception:
                pass
    if not acct:
        acct = event.get("account") or event.get("accountId") or ""
    return str(acct)

def _extract_region(detail: dict, event: dict) -> str:
    return str(detail.get("awsRegion") or detail.get("region") or event.get("region") or "")

def _extract_resource(detail: dict) -> str:
    resource = ""
    resources = detail.get("resources") or _as_dict(detail.get("detail")).get("resources") or []
    if isinstance(resources, list) and resources:
        first = resources[0]
        if isinstance(first, dict):
            resource = first.get("ARN") or first.get("arn") or first.get("resourceName") or json.dumps(first, ensure_ascii=False)
        else:
            resource = str(first)
    if not resource:
        rp = _as_dict(detail.get("requestParameters"))
        for k in ("userName", "accessKeyId", "serialNumber", "userArn", "roleName", "instanceId"):
            if rp.get(k):
                resource = rp.get(k)
                break
    return str(resource or "")

# ---- ARN/RESOURCE 통일용 유틸 ----
def resolve_arn(detail: dict, user_identity: dict, account: str) -> str:
    """
    다른 Lambda와 동일한 규칙으로 ARN을 최대한 채워넣기.
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

    sess_issuer = _as_dict(_as_dict(user_identity.get("sessionContext")).get("sessionIssuer"))
    issuer_arn = (sess_issuer.get("arn") or "").strip()
    if issuer_arn:
        return issuer_arn

    if pid:
        return f"arn:aws:iam::{account}:principal/{pid}"

    req = _as_dict(detail.get("requestParameters"))
    req_uname = (req.get("userName") or req.get("username") or "").strip()
    if req_uname:
        return f"arn:aws:iam::{account}:user/{req_uname}"

    return f"arn:aws:iam::{account}:unknown"

def _build_resource_from_identity(detail: dict) -> str:
    """
    handler.py / 다른 lambda_function.py 와 동일 포맷:
    resource = "{type.lower()}/{userName or principalId or 'unknown'}"
    """
    ui = _as_dict(detail.get("userIdentity"))
    typ = ui.get("type") or ""
    user = ui.get("userName") or ""
    prn  = ui.get("principalId") or ""
    return f"{typ.lower()}/{user or prn or 'unknown'}"

# ---- payload 빌드 ----
def build_payload(event):
    detail = event.get("detail", {}) if isinstance(event, dict) else {}
    raw_source = detail.get("eventSource") or event.get("source") or ""
    human_src = normalize_source(raw_source)

    decision = determine_event_type(detail)
    if decision is None:
        # 전송 억제 케이스 (DeactivateMFADevice 등)
        return None

    etype     = decision["type_str"]
    severity  = decision["severity"]
    status    = decision["status"]
    extra     = decision["meta"]

    ui      = _as_dict(detail.get("userIdentity"))
    account = _extract_account(detail, event)
    region  = _extract_region(detail, event)

    # 👉 여기서 resource/arn을 다른 Lambda와 동일한 규칙으로 생성
    resource = _build_resource_from_identity(detail)
    arn      = resolve_arn(detail, ui, account)

    event_time = detail.get("eventTime") or event.get("time") or ""

    # ---- actor/target 정보 구성 (누가 어떤 계정/사용자의 MFA를 건드렸는지) ----
    req = _as_dict(detail.get("requestParameters"))
    actor_info = {
        "type": ui.get("type"),
        "userName": ui.get("userName"),
        "principalId": ui.get("principalId"),
        "accountId": ui.get("accountId"),
        "arn": ui.get("arn"),
    }
    target_info = {
        # MFA가 적용되는 대상 계정/사용자
        "accountId": account,
        "userName": req.get("userName") or req.get("username") or ui.get("userName"),
        "serialNumber": req.get("serialNumber"),
    }

    meta = {
        "status": status,  # "시도" | "완료" | "실패"
        **({k: v for k, v in extra.items() if v is not None}),
    }

    clean_actor = {k: v for k, v in actor_info.items() if v}
    if clean_actor:
        meta["actor"] = clean_actor

    clean_target = {k: v for k, v in target_info.items() if v}
    if clean_target:
        meta["target"] = clean_target

    payload = {
        "time": epoch_ms_from_iso(event_time),
        "source": human_src,
        "type": etype,            # ex) "MFA 비활성화: 완료"
        "resource": resource or "",
        "sg": "",
        "arn": arn or "",
        "account": str(account),
        "region": region,
        "severity": severity,
        "meta": meta,
    }
    return payload

# ---- Incident 저장 관련 ----
def _generate_incident_id(prefix: str = "inc") -> str:
    """
    예: inc-YYYYMMDD-HHMMSS-XYZ (UTC 기준, 랜덤 3자리)
    """
    ts = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    rand = random.randint(0, 999)
    return f"{prefix}-{ts}-{rand:03d}"

def _save_incident_for_mfa_event(event: dict, payload: dict) -> str | None:
    """
    MFA 관련 이벤트를 Incident 테이블에 저장.
    Incident 항목의 meta 필드에 device + ip + MFA 메타데이터를 넣는다.
    """
    try:
        detail = event.get("detail") or {}

        ua = detail.get("userAgent") or ""
        ip = detail.get("sourceIPAddress") or ""
        device_summary = _normalize_ua(ua) if ua else ""

        # WebSocket payload meta (status, api, mfaUsed, consoleOutcome, errorCode 등)
        base_meta = payload.get("meta") or {}

        incident_meta = {}

        if ua or device_summary:
            incident_meta["device"] = {
                "summary": device_summary,  # 예: "windows|chrome"
                "ua": ua,                   # 원본 UA
            }
        if ip:
            incident_meta["ip"] = ip

        # MFA 관련 메타데이터도 그대로 합침 (status, api, mfaUsed 등 + actor/target)
        incident_meta.update({k: v for k, v in base_meta.items() if v is not None})

        now_iso = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        incident_id = _generate_incident_id()

        item = {
            "incident_id": incident_id,
            "event_type": payload.get("type") or "",
            "resource": payload.get("resource") or "",
            "severity": payload.get("severity") or "LOW",
            "status": "NEW",              # 인시던트 워크플로 상태 (NEW/PROCESSING/...)
            "meta": incident_meta,        # incident_details 대신 meta 사용
            "source": payload.get("source") or "",
            "account": payload.get("account") or "",
            "region": payload.get("region") or "",
            "created_at": now_iso,
            "updated_at": now_iso,
        }

        incident_table.put_item(Item=item)
        return incident_id
    except Exception as e:
        print(f"save_incident_for_mfa_event error: {e}")
        return None

# ---- WebSocket broadcast ----
def scan_all_connection_ids() -> list:
    items, eks = [], None
    while True:
        try:
            resp = conn_table.scan(
                ProjectionExpression="connectionId",
                **({"ExclusiveStartKey": eks} if eks else {})
            )
        except Exception as e:
            print("DynamoDB scan failed:", str(e))
            break
        items.extend(resp.get("Items", []))
        eks = resp.get("LastEvaluatedKey")
        if not eks:
            break
    return items

def post_to_all_connections(payload: dict):
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    for it in scan_all_connection_ids():
        conn_id = it.get("connectionId")
        if not conn_id:
            continue
        try:
            apigw.post_to_connection(ConnectionId=conn_id, Data=data)
        except ClientError as e:
            err = e.response.get("Error", {})
            code = err.get("Code")
            if code == "410":
                # stale connection cleanup
                try:
                    conn_table.delete_item(Key={"connectionId": conn_id})
                except Exception as de:
                    print(f"Failed to delete stale connection {conn_id}: {de}")
            else:
                print(f"post_to_connection error for {conn_id}: {e}")
        except Exception as e:
            print(f"Unexpected error posting to {conn_id}: {e}")

# ---- handler ----
def lambda_handler(event, context):
    try:
        print("Received Event (truncated):", json.dumps(event)[:2000])
        payload = build_payload(event)

        if payload is None:
            print("Suppressed event (no broadcast).")
            return {"status": "suppressed"}

        # Incident 테이블 저장 (meta = device + ip + MFA 메타데이터)
        incident_id = _save_incident_for_mfa_event(event, payload)
        if incident_id:
            payload["incident_id"] = incident_id

        print("Outgoing payload:", json.dumps(payload, ensure_ascii=False))
        post_to_all_connections(payload)
        return {"status": "sent"}
    except Exception as e:
        print("Error processing event:", str(e))
        raise

# local test
if __name__ == "__main__":
    pass
