# incident-slack-sender
이 Lambda 함수는 DynamoDB `Incident` 테이블에서 **신규 생성 및 수정 이벤트**를 감지하여 **Slack으로 실시간 알림**을 전송합니다.

---

## 1. 함수 개요 (Overview)
- DynamoDB `Incident` 테이블의 `INSERT` 및 `MODIFY` 이벤트 감지  
- Slack 메시지로 상태, 심각도, 이벤트 유형, 대상 리소스, 생성/업데이트 시각 전송  
- 모든 시간은 **한국 표준시(KST)** 기준으로 표시  

---

## 2. 동작 조건 & 트리거 (Conditions & Trigger)
- **트리거 소스:** DynamoDB Streams (`Incident` 테이블)  
- **이벤트 종류:** `INSERT`, `MODIFY`  
- **배치 처리:** 현재는 단일 레코드 기준 처리  
- **사용 예시:** 신규 인시던트 생성 시 Slack으로 알림 전송  

---

## 3. 처리 로직 (Logic)
1. Lambda가 DynamoDB 스트림 이벤트 수신  
2. `NewImage`에서 인시던트 데이터 추출  
3. 시간 변환 (UTC → KST)  
4. Slack 메시지 생성 (`build_slack_payload`)  
5. Slack Webhook 전송 (`send_slack_message`)  
6. 전송 결과 로그 출력  

---

## 4. 환경 변수 (Environment Variables)
| Key | 설명 |
| --- | --- |
| `SLACK_WEBHOOK_URL` | Slack Webhook URL |

---

## 5. 사용 리소스 & 의존성 (Resources & Dependencies)
- **AWS 리소스:** DynamoDB(`Incident`), CloudWatch Logs  
- **Python 라이브러리:** `os`, `json`, `urllib.request`, `datetime`  

---

## 6. IAM 권한 (IAM Permissions)
- DynamoDB Streams 읽기:  
  - `dynamodb:DescribeStream`  
  - `dynamodb:GetRecords`  
  - `dynamodb:GetShardIterator`  
- CloudWatch Logs: 로그 기록  
- Lambda 실행 역할에 최소 권한 정책  

---

## 7. 한계 및 향후 과제 (Limitations & TODO)
| 한계 | 향후 과제 |
| ---- | --------- |
| Slack Webhook 실패 시 재시도 없음 | 재시도 로직 추가 또는 DLQ 활용 |
| DynamoDB 스트림 이벤트 처리 단순화 | 배치 처리, 중복 제거 로직 개선 |
| 상태/심각도 아이콘 고정 | 정책 기반 또는 사용자 정의 매핑 확장 |
| Slack 메시지 포맷 하드코딩 | 템플릿 외부화, 다국어 지원 |
| Webhook URL 환경 변수 외부 노출 가능성 | Secrets Manager 또는 Parameter Store 사용 |

---

## 8. Slack 메시지 예시
```json
{
  "text": "🚨 보안 인시던트 업데이트",
  "blocks": [
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "*인시던트 ID:* inc-20251127-123456-001\n*발생 이벤트:* `퍼블릭 버킷 정책 삭제 위험`\n*대상 리소스:* my-bucket\n*상태:* 🚨 NEW\n*심각도:* ⚠️ HIGH"
      }
    },
    {
      "type": "context",
      "elements": [
        {"type": "mrkdwn", "text": "🕒 생성: 2025-11-27 21:34:56 KST"},
        {"type": "mrkdwn", "text": "🔄 업데이트: 2025-11-27 21:34:56 KST"},
        {"type": "mrkdwn", "text": "전송 시각: 2025-11-27 21:35:10 KST"}
      ]
    }
  ]
}
