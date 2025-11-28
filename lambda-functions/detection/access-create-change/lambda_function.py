# file: lambda_function.py  (Python 3.12)
import os, json, time, ipaddress, random
from datetime import datetime, timezone
import boto3
from botocore.exceptions import ClientError

CONNECTIONS_TABLE = os.environ["CONNECTIONS_TABLE"]
WS_ENDPOINT       = os.environ["WS_ENDPOINT"]

# Incident 테이블 (환경변수 없으면 기본 'Incident')
INCIDENT_TABLE    = os.environ.get("INCIDENT_TABLE", "Incident")

dynamodb        = boto3.resource("dynamodb")
conn_table      = dynamodb.Table(CONNECTIONS_TABLE)
incident_table  = dynamodb.Table(INCIDENT_TABLE)
apigw           = boto3.client("apigatewaymanagementapi", endpoint_url=WS_ENDPOINT)

# ----- helpers -----
def epoch_ms_from_iso(s: str | None) -> int:
    if not s:
        return int(time.time() * 1000)
    try:
        # CloudTrail eventTime 예: "2025-11-10T00:12:34Z"
        return int(datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp() * 1000)
    except Exception:
        try:
            v = int(float(s))
            return v if v > 10**12 else v * 1000
        except Exception:
            return int(time.time() * 1000)

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
    # IAM
    if "iam" in s:
        return "AWS IAM"
    # 기타 서비스: "aws.xxx" or "xxx.amazonaws.com" 형태를 사람이 읽기 쉽게 변환
    if s.endswith(".amazonaws.com"):
        svc = s.split(".")[0]
        return svc.capitalize()
    return source

# CloudTrail eventName → 한글 타입 문자열
EVENT_NAME_TO_KO = {
    "CreateAccessKey": "액세스 키 생성",
    "UpdateAccessKey": "액세스 키 상태 변경",
    "DeleteAccessKey": "액세스 키 삭제",
    "CreateLoginProfile": "콘솔 비밀번호 생성",
    "UpdateLoginProfile": "콘솔 비밀번호 갱신",
    "ChangePassword": "콘솔 비밀번호 변경",
    "CreateVirtualMFADevice": "가상 MFA 디바이스 생성",
    "EnableMFADevice": "MFA 활성화",
    "DeactivateMFADevice": "MFA 비활성화",
    "DeleteVirtualMFADevice": "가상 MFA 디바이스 삭제",
    "AssociateVirtualMFADevice": "가상 MFA 연동",
    "ResyncMFADevice": "MFA 재동기화",
    "UploadSigningCertificate": "서명 인증서 업로드",
    "UpdateSigningCertificate": "서명 인증서 상태 변경",
    "DeleteSigningCertificate": "서명 인증서 삭제",
    "UploadSSHPublicKey": "SSH 공개키 업로드(CodeCommit)",
    "UpdateSSHPublicKey": "SSH 공개키 상태 변경(CodeCommit)",
    "DeleteSSHPublicKey": "SSH 공개키 삭제(CodeCommit)",
    "CreateServiceSpecificCredential": "서비스 전용 자격 증명 생성",
    "UpdateServiceSpecificCredential": "서비스 전용 자격 증명 상태 변경",
    "ResetServiceSpecificCredential": "서비스 전용 자격 증명 재설정",
    "DeleteServiceSpecificCredential": "서비스 전용 자격 증명 삭제",
    "TagUser": "사용자 태그 추가",
    "UntagUser": "사용자 태그 제거",
    "AttachUserPolicy": "사용자 정책 연결(관리형)",
    "DetachUserPolicy": "사용자 정책 분리(관리형)",
    "PutUserPolicy": "사용자 인라인 정책 추가/갱신",
    "DeleteUserPolicy": "사용자 인라인 정책 삭제",
    "CreateUser": "IAM 사용자 생성",
    "UpdateUser": "IAM 사용자 수정",
    "DeleteUser": "IAM 사용자 삭제"
}

def build_severity(detail: dict) -> str:
    """
    간단한 기준:
    - 루트 계정, MFA 비활성화/비밀번호 변경/액세스 키 생성: CRITICAL/HIGH
    - 그 외 변경/Delete/Update는 MEDIUM, 태깅/조회성 낮은 변경은 LOW
    """
    user_type = (detail.get("userIdentity", {}) or {}).get("type", "")
    event_name = detail.get("eventName", "")
    mfa_used   = ((detail.get("userIdentity", {}) or {}).get("sessionContext", {}) or {}).get("attributes", {}).get("mfaAuthenticated", "false").lower() == "true"

    if user_type == "Root":
        # 루트로 자격 증명 조작
        if event_name in ("CreateAccessKey", "ChangePassword", "DeactivateMFADevice"):
            return "CRITICAL"
        return "HIGH"

    # 특히 위험
    if event_name in ("CreateAccessKey", "ChangePassword", "DeactivateMFADevice", "DeleteVirtualMFADevice"):
        return "HIGH" if mfa_used else "CRITICAL"

    # 권한/정책 편집
    if event_name in ("AttachUserPolicy", "DetachUserPolicy", "PutUserPolicy", "DeleteUserPolicy"):
        return "MEDIUM" if mfa_used else "HIGH"

    # 일반 업데이트/삭제
    if any(k in event_name for k in ("Update", "Delete", "Reset")):
        return "MEDIUM"

    # 기본
    return "LOW"

def _get_requester_arn(detail: dict) -> str:
    ui = detail.get("userIdentity", {}) or {}
    arn = ui.get("arn") or ui.get("sessionIssuer", {}).get("arn") or ""
    return str(arn)

def _target_resource(detail: dict) -> str:
    # 대상 유저/키/디바이스 등 표시 (가능한 값 우선 사용)
    params = detail.get("requestParameters", {}) or {}
    # accessKey
    if "accessKeyId" in params:
        return f"accessKeyId:{params.get('accessKeyId')}"
    # userName
    if "userName" in params:
        return f"user:{params.get('userName')}"
    # mfa
    if "serialNumber" in params:
        return f"mfa:{params.get('serialNumber')}"
    # ssh key / signing cert id
    for k in ("SSHPublicKeyId", "certificateId", "serviceSpecificCredentialId"):
        if k in params:
            return f"{k}:{params.get(k)}"
    # 없으면 이벤트 ID
    return detail.get("eventID", "")

def broadcast(payload: dict):
    # CONNECTIONS_TABLE의 모든 connectionId에 송신 (죽은 연결은 정리)
    scan_kwargs = {}
    while True:
        resp = conn_table.scan(**scan_kwargs)
        items = resp.get("Items", [])
        for it in items:
            cid = it.get("connectionId")
            if not cid:
                continue
            try:
                apigw.post_to_connection(ConnectionId=cid, Data=json.dumps(payload).encode("utf-8"))
            except apigw.exceptions.GoneException:
                # 끊어진 연결 정리
                try:
                    conn_table.delete_item(Key={"connectionId": cid})
                except Exception:
                    pass
            except Exception as e:
                # 로깅만
                print(f"post_to_connection error: {e}")
        if "LastEvaluatedKey" in resp:
            scan_kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
        else:
            break

# ===== Incident 관련 유틸 =====
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

def _generate_incident_id(prefix: str = "inc") -> str:
    """
    예: inc-YYYYMMDD-HHMMSS-XYZ (UTC 기준, 랜덤 3자리)
    """
    ts = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    rand = random.randint(0, 999)
    return f"{prefix}-{ts}-{rand:03d}"

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
    ua         = detail.get("userAgent") or ""
    ip         = detail.get("sourceIPAddress") or ""
    event_name = detail.get("eventName") or ""

    device_summary = _normalize_ua(ua) if ua else ""

    meta: dict = {}

    if ua or device_summary:
        meta["device"] = {
            "summary": device_summary,  # 예: "windows|chrome"
            "ua": ua,                   # 원본 UA
        }
    if ip:
        meta["ip"] = ip

    if event_name:
        meta["api"] = event_name

    # 액세스 키 상세 정보
    params = detail.get("requestParameters", {}) or {}
    resp   = detail.get("responseElements", {}) or {}
    ui     = detail.get("userIdentity", {}) or {}

    if event_name in ("CreateAccessKey", "UpdateAccessKey", "DeleteAccessKey"):
        ak_meta: dict = {}

        owner_type = ui.get("type")
        owner_name = params.get("userName") or ui.get("userName")
        if owner_type == "Root":
            # Root는 userName 이 없으니 구분용
            owner_name = "RootAccount"

        if owner_type:
            ak_meta["owner_type"] = owner_type
        if owner_name:
            ak_meta["owner"] = owner_name

        access_key_id = None
        status        = None

        # CreateAccessKey 응답: responseElements.accessKey.accessKeyId / status
        ak_block = resp.get("accessKey")
        if isinstance(ak_block, dict):
            access_key_id = ak_block.get("accessKeyId") or access_key_id
            status        = ak_block.get("status") or status

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

def _save_incident_for_iam_event(detail: dict, payload: dict, incident_meta: dict | None = None) -> str | None:
    """
    IAM 자격 증명/정책 관련 이벤트를 Incident 테이블에 저장.
    Incident 항목의 meta 필드에 device + ip + 액세스 키 상세 메타데이터를 넣는다.
    """
    try:
        # handler 쪽에서 만든 meta 재사용, 없으면 여기서 새로 생성
        if incident_meta is None:
            incident_meta = _build_common_meta(detail)

        now_iso = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        incident_id = _generate_incident_id()

        item = {
            "incident_id": incident_id,
            "event_type": payload.get("type") or "",
            "resource": payload.get("resource") or "",
            "severity": payload.get("severity") or "LOW",
            "status": "NEW",             # 인시던트 상태 (NEW/PROCESSING/...)
            "meta": incident_meta,       # incident_details 대신 meta 사용
            "source": payload.get("source") or "",
            "account": payload.get("account") or "",
            "region": payload.get("region") or "",
            "created_at": now_iso,
            "updated_at": now_iso,
        }

        incident_table.put_item(Item=item)
        return incident_id
    except Exception as e:
        print(f"save_incident_for_iam_event error: {e}")
        return None

# ----- handler -----
def lambda_handler(event, context):
    # EventBridge → CloudTrail 이벤트
    detail       = event.get("detail", {}) or {}
    event_time   = detail.get("eventTime") or event.get("time")
    event_source = detail.get("eventSource") or ""
    event_name   = detail.get("eventName") or ""

    # ✅ 생성 이벤트(CreateAccessKey)는 이 Lambda에서는 알림/Incident 저장 안 함
    if event_name == "CreateAccessKey":
        return {"ok": True, "skipped": "CreateAccessKey"}

    # 공통 meta (디바이스, IP, 액세스 키 상세 등)
    common_meta = _build_common_meta(detail)

    payload = {
        "time": epoch_ms_from_iso(event_time),
        "source": normalize_source(event_source),                # 예: "AWS Sign-In/STS", "Iam" 등
        "type": EVENT_NAME_TO_KO.get(event_name, event_name),    # 한글 타입 (없으면 원문)
        "sg": "",                                                # 본 시나리오엔 SG 없음 → 빈 문자열
        "arn": _get_requester_arn(detail),                       # 호출 주체 ARN
        "resource": _target_resource(detail),                    # 대상 리소스
        "account": str(detail.get("userIdentity", {}).get("accountId", event.get("account", ""))),
        "region": str(detail.get("awsRegion", event.get("region", ""))),
        "severity": build_severity(detail),
        "meta": common_meta                                      # 프론트로도 동일 meta 전달
    }

    # Incident 테이블에 저장 (meta = device + ip + accessKey 등)
    incident_id = _save_incident_for_iam_event(detail, payload, common_meta)
    if incident_id:
        payload["incident_id"] = incident_id

    broadcast(payload)
    return {"ok": True, "sent": True, "payload": payload}
