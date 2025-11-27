## 1. 함수 개요 (Overview)
이 Lambda 함수는 API Gateway WebSocket의 $disconnect 라우트에서 실행되며, Incident WebSocket 채널로 연결된 사용자가 연결을 종료할 때 DynamoDB에서 해당 connectionId 를 삭제합니다.

주요 기능:
1. WebSocket 연결 종료 이벤트를 감지
2. 종료된 connectionId 를 DynamoDB CONNECTIONS_TABLE에서 삭제
3. 연결 해제 로그를 CloudWatch에 기록
이 함수는 Incident 대시보드 또는 실시간 대응 시스템에서 불필요한 WebSocket 연결 정보가 누적되지 않도록 관리하는 역할을 수행합니다.

---
## 2. 동작 조건 & 트리거 (Conditions & Trigger)
### 이벤트 소스
API Gateway WebSocket – `$disconnect` route

### 처리 대상 이벤트
| 구분                   | 이벤트              | 설명                        |
| -------------------- | ---------------- | ------------------------- |
| WebSocket Disconnect | `$disconnect` 호출 | Incident WebSocket 연결이 끊어질 때 실행됩니다 |

---
## 3. 처리 로직 요약 (Logic Flow)
### 1. WebSocket → $disconnect → Lambda 호출
- 클라이언트 브라우저 또는 앱에서 WebSocket 연결을 종료하면 Lambda가 자동 실행됩니다.
### 2. event 로그 출력
전체 이벤트(JSON)를 CloudWatch Logs에 기록합니다.
### 3. connectionId 추출
```python
cid = event["requestContext"]["connectionId"]
```
### 4. DynamoDB 삭제
다음 코드로 connectionId 를 기반으로 항목을 삭제합니다.
```python
table.delete_item(Key={"connectionId": cid})
```
### 5. 삭제 성공/실패 로그 출력
- 정상 삭제: `[onDisconnectIncident] delete_item OK`
- 실패: 오류 메시지 출력
### 6. 성공 응답 반환
- HTTP 200
- `"disconnected"` 반환

---
## 4. 환경 변수 (Environment Variables)
| 이름                | 예시                             | 설명                                          |
| ----------------- | ------------------------------ | ------------------------------------------- |
| CONNECTIONS_TABLE | `IncidentWebSocketConnections` | Incident WebSocket 연결 정보를 저장하는 DynamoDB 테이블 |


---
## 5. 사용 리소스 / 의존성 (Dependencies)
### AWS 리소스
   - DynamoDB
      - CONNECTIONS_TABLE (PK: connectionId)
   - API Gateway WebSocket – $disconnect Route
### Python 패키지
   - boto3
   - json
   - os

---
## 6. 필요한 IAM 권한 (Required IAM Permissions)
이 Lambda가 정상 동작하려면 다음 권한이 반드시 필요합니다.
### 1. DynamoDB 권한
- dynamodb:DeleteItem
- dynamodb:PutItem (선택적)
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
- connectionId 외의 부가 정보(clientId, region 등)는 처리하지 않습니다.
- 연결 종료 시 특별한 후처리(알림, 로그 백업 등)는 수행하지 않습니다.
- 비정상 WebSocket 종료(네트워크 장애)의 경우 disconnect 이벤트가 누락될 수 있습니다.
### TODO
- disconnect 시 사용자 정보 기반 후처리 기능 추가
- 비정상 종료 여부 감지 기능 개선
- 오래된 connectionId 정리 자동화 기능 고도화