import os
import json
import urllib.request
import datetime

SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL")

# ============================
# 시간대
# ============================
KST = datetime.timezone(datetime.timedelta(hours=9))

def parse_to_kst(iso_str):
    try:
        dt = datetime.datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        dt_kst = dt.astimezone(KST)
        return dt_kst.strftime("%Y-%m-%d %H:%M:%S KST")
    except Exception:
        return iso_str  # 변환 실패 시 그대로 사용

# ============================
# Slack 전송 함수
# ============================
def send_slack_message(payload: dict):
    if not SLACK_WEBHOOK_URL:
        print("❌ Slack Webhook URL이 설정되지 않음.")
        return False

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        SLACK_WEBHOOK_URL,
        data=data,
        headers={"Content-Type": "application/json"}
    )

    try:
        with urllib.request.urlopen(req) as resp:
            print(f"Slack Response: {resp.getcode()}")
            return resp.getcode() == 200
    except Exception as e:
        print(f"❌ Slack 전송 실패: {e}")
        return False


# ============================
# 아이콘 매핑
# ============================
STATUS_ICON = {
    "NEW": "🚨",
    "TRIGGERED": "🚨",
    "PROCESSING": "⚙️",
    "MITIGATED": "✅",
    "SUCCEEDED": "✅",
    "FAILED": "❌"
}

SEVERITY_ICON = {
    "CRITICAL": "🔥",
    "HIGH": "⚠️",
    "MEDIUM": "🔶",
    "LOW": "ℹ️",
    "INFO": "💡"
}

# ============================
# Slack 메시지 템플릿
# ============================
def build_slack_payload(record):
    incident_id = record["incident_id"]
    resource = record.get("resource", "Unknown")
    status = record.get("status", "NEW")
    severity = record.get("severity", "INFO")
    event_type = record.get("event_type", "Unknown Event")

    created_at = parse_to_kst(record.get("created_at", ""))
    updated_at = parse_to_kst(record.get("updated_at", ""))

    now_kst = datetime.datetime.now(KST).strftime("%Y-%m-%d %H:%M:%S KST")

    payload = {
        "text": f"{STATUS_ICON.get(status, 'ℹ️')} 보안 인시던트 업데이트",
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*인시던트 ID:* {incident_id}\n"
                        f"*발생 이벤트:* `{event_type}`\n"
                        f"*대상 리소스:* {resource}\n"
                        f"*상태:* {STATUS_ICON.get(status)} {status}\n"
                        f"*심각도:* {SEVERITY_ICON.get(severity)} {severity}"
                    )
                }
            },
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"🕒 생성: {created_at}"},
                    {"type": "mrkdwn", "text": f"🔄 업데이트: {updated_at}"},
                    {"type": "mrkdwn", "text": f"전송 시각: {now_kst}"}
                ]
            }
        ]
    }

    return payload


# ============================
# Lambda 핸들러
# ============================
def lambda_handler(event, context):
    print("📥 Received DynamoDB Stream Event")
    print(json.dumps(event))

    for record in event.get("Records", []):
        if record["eventName"] not in ["INSERT", "MODIFY"]:
            continue  # 인서트/수정만 Slack 보냄

        if "NewImage" not in record["dynamodb"]:
            continue

        new_image = record["dynamodb"]["NewImage"]

        # DynamoDB JSON → Python dict 변환
        incident = {k: list(v.values())[0] for k, v in new_image.items()}

        print(f"📝 Parsed Incident: {incident}")

        payload = build_slack_payload(incident)
        send_slack_message(payload)

    return {"statusCode": 200, "body": "Slack notifications sent"}
