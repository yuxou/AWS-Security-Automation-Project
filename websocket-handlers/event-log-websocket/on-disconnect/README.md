## 1. 함수 개요 (Overview)
이 Lambda 함수는 API Gateway WebSocket의 $disconnect 라우트에서 실행되며,
웹 클라이언트가 WebSocket 연결을 종료할 때 호출됩니다.

주요 기능:
1. WebSocket 연결 종료 이벤트를 감지
2. connectionId 를 DynamoDB에서 제거하여 불필요한 연결 정보가 누적되지 않도록 함
3. 시스템의 실시간 연결 상태를 정확하게 유지하여 대시보드 연결 상태 표시가 올바르게 작동하도록 함
이 함수는 보안 히스토리 실시간 스트림(History WebSocket) 의 연결 수명주기 관리에 필수적인 구성 요소입니다.

---
## 2. 동작 조건 & 트리거 (Conditions & Trigger)
### 이벤트 소스
API Gateway WebSocket – `$disconnect` route

### 처리 대상 이벤트
| 구분                   | 이벤트              | 설명                        |
| -------------------- | ---------------- | ------------------------- |
| WebSocket Disconnect | `$disconnect` 호출 | 클라이언트가 소켓 연결을 닫을 때 트리거됩니다 |

---
## 3. 처리 로직 요약 (Logic Flow)
### 1. WebSocket → $disconnect → Lambda 호출
- 클라이언트 브라우저 또는 앱에서 WebSocket 연결을 종료하면 Lambda가 자동 실행됩니다.
### 2. connectionId 추출
```python
cid = event["requestContext"]["connectionId"]
```
### 3. DynamoDB 삭제
다음 코드로 연결된 레코드를 삭제합니다.
```python
table.delete_item(Key={"connectionId": cid})
```
### 4. 응답
- HTTP 200
- `"disconnected"` 반환

---
## 4. 환경 변수 (Environment Variables)
| 이름                | 예시                                  | 설명                                   |
| ----------------- | ----------------------------------- | ------------------------------------ |
| CONNECTIONS_TABLE | `SecurityEventWebSocketConnections` | 보안 이벤트 WebSocket 연결 저장용 DynamoDB 테이블 |

---
## 5. 사용 리소스 / 의존성 (Dependencies)
### AWS 리소스
   - DynamoDB
      - CONNECTIONS_TABLE (PK: connectionId)
   - API Gateway WebSocket – $disconnect Route
### Python 패키지
   - boto3
   - os
   - botocore.exceptions

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
- 비정상 종료(네트워크 단절, 탭 강제 종료 등) 시 disconnect 호출이 누락될 가능성이 있음
- connectionId 외의 메타데이터 삭제 처리는 포함되지 않음
- 별도의 connection cleanup 스케줄러는 포함되어 있지 않습니다.
### TODO
- History WebSocket 연결 상태 추적 기능 개선
- disconnect 시 상세 접속 정보(IP, User-Agent) 로그 강화
- 중복 connection 자동 정리 기능 추가
