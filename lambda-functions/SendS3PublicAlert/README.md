# SendS3PublicAlert Lambda Function

## 1. 함수 개요 (What)
S3 퍼블릭 액세스 이벤트, GuardDuty, Config 이벤트를 감지하고,  
DynamoDB에 상태를 저장하며, Incident DB에 기록 후 WebSocket을 통해 알림을 전송하는 AWS Lambda 함수입니다.

---

## 2. 동작 조건 & 트리거 (When / From Where)
- **Trigger**
  - S3 / S3Control 이벤트 (CloudTrail 기반)
  - GuardDuty 이벤트
  - AWS Config Rule 위반 이벤트
- **조건**
  - 이벤트가 퍼블릭 액세스 또는 보안 위반 관련일 때만 처리

---

## 3. 처리 로직 요약 (How)
1. 이벤트 수신 및 source 확인
2. S3 / GuardDuty / Config 이벤트별 분석
3. Alert 객체 생성
4. DynamoDB(Alert State Table)에 상태 저장
5. Incident DB에 신규 인시던트 생성 또는 업데이트
6. WebSocket 연결된 클라이언트에 알림 전송

---

## 4. 환경변수 (Environment Variables)
| 변수명 | 설명 | 기본값 |
|--------|------|--------|
| `WS_ENDPOINT` | WebSocket 엔드포인트 URL | 없음 |
| `TARGET_REGION` | Lambda 및 리소스 사용 리전 | `us-east-1` |
| `CONNECTIONS_TABLE` | WebSocket 연결 관리 테이블 | `WebSocketConnections` |
| `ALERT_STATE_TABLE` | Alert 상태 저장 테이블 | `security-alerts-state-v2` |
| `INCIDENT_TABLE_NAME` | Incident DB 테이블 이름 | 없음 |

---

## 5. 사용 리소스 / 의존성 (Dependencies)
- **AWS 서비스**
  - DynamoDB (Alert State, Connections, Incident DB)
  - API Gateway WebSocket
  - CloudTrail, GuardDuty, Config 이벤트
- **Python 라이브러리**
  - `boto3`
  - `json`, `os`, `datetime`, `time`, `random`

---

## 6. IAM 권한 (Required IAM Permissions)
- `dynamodb:PutItem`, `dynamodb:UpdateItem`, `dynamodb:Scan`, `dynamodb:DeleteItem`
- `execute-api:ManageConnections` (WebSocket 메시지 전송)
- Lambda가 사용하는 모든 리소스에 대한 읽기/쓰기 권한 필요

---

## 7. 한계 / TODO (Limitations / TODO)
- 현재 WebSocket 전송 실패 시 삭제만 수행, 재시도 로직 없음
- GuardDuty 이벤트 내 일부 필드 누락 시 기본값 사용
- Incident 업데이트 시 상태만 변경 가능, 세부 필드 업데이트 미지원
- 향후 S3 이벤트 유형 추가 및 Severity 자동 조정 필요
