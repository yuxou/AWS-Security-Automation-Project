## 1. 함수 개요 (Overview)
이 Lambda 함수는 자동 대응(Remediation) 시스템에서 사용되는 WebSocket 채널의
$disconnect 라우트에서 실행되며, 자동 대응(Remediation) 클라이언트 또는 Dashboard가 WebSocket 연결을 종료할 때
해당 connectionId 를 DynamoDB 테이블에서 삭제합니다.

주요 기능:
1. WebSocket 연결 종료 이벤트를 감지
2. 종료된 connectionId 를 DynamoDB CONNECTIONS_TABLE에서 삭제
3. Remediation WebSocket 연결 상태를 지속적으로 정리하여 대시보드와 자동 대응 모듈이 정확한 연결 목록을 유지하도록 합니다.

---
## 2. 동작 조건 & 트리거 (Conditions & Trigger)
### 이벤트 소스
API Gateway WebSocket – `$disconnect` route

### 처리 대상 이벤트
| 구분                               | 이벤트              | 설명                                               |
| -------------------------------- | ---------------- | ------------------------------------------------ |
| Remediation WebSocket Disconnect | `$disconnect` 호출 | 자동 대응(Remediation) 채널의 WebSocket 연결이 끊어질 때 실행됩니다 |


---
## 3. 처리 로직 요약 (Logic Flow)
### 1. WebSocket → $disconnect → Lambda 호출
- Remediation Dashboard 또는 Agent가 WebSocket 연결을 닫으면 자동 실행됩니다.
### 2. connectionId 추출
```python
cid = event["requestContext"]["connectionId"]
```
### 3. DynamoDB 삭제
저장되어 있던 Remediation 웹소켓 연결을 삭제합니다.
```python
table.delete_item(Key={'connectionId': conn_id})
```
### 4. 성공 응답 반환
- HTTP 200
- `"disconnected"` 반환

---
## 4. 환경 변수 (Environment Variables)
| 이름                | 예시                                | 설명                                             |
| ----------------- | --------------------------------- | ---------------------------------------------- |
| CONNECTIONS_TABLE | `RemediationWebSocketConnections` | Remediation WebSocket 연결 정보를 저장하는 DynamoDB 테이블 |

---
## 5. 사용 리소스 / 의존성 (Dependencies)
### AWS 리소스
   - DynamoDB
      - CONNECTIONS_TABLE (PK: connectionId)
   - API Gateway WebSocket – Remediation 전용 `$disconnect` Route
### Python 패키지
   - boto3
   - os

---
## 6. 필요한 IAM 권한 (Required IAM Permissions)
이 Lambda가 정상 동작하려면 다음 권한이 반드시 필요합니다.
### 1. DynamoDB 권한
- dynamodb:DeleteItem
- dynamodb:GetItem (선택적)
리소스 예:
```css
arn:aws:dynamodb:{region}:{account-id}:table/{CONNECTIONS_TABLE}
```
### 2. CloudWatch Logs 권한
- AWSLambdaBasicExecutionRole (기본 로그 기록)

---
## 7. 한계 & TODO (Limitations / TODO)
### 한계
- 연결 종료 후 추가적인 처리(알림, 로깅 강화 등)는 수행하지 않습니다.
- 비정상 종료(네트워크 단절) 시 disconnect 호출이 누락될 수 있습니다.
- Remediation 연결 상태 모니터링 기능은 포함되어 있지 않습니다.
### TODO
- Remediation Agent 상태 모니터링 기능 추가
- 비정상 종료 트래킹 및 자동 정리 기능 확장
- disconnect 시 연결 메타데이터 로그 기록 강화