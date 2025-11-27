## 1. 함수 개요 (Overview)
이 Lambda 함수는 API Gateway WebSocket의 $disconnect 라우트에서 실행되며,
웹 클라이언트가 WebSocket 연결을 종료할 때 호출됩니다.

주요 기능:
1. WebSocket 연결 종료 이벤트를 감지
2. 종료된 connectionId 를 DynamoDB CONNECTIONS_TABLE에서 삭제
3. 연결 해제 로그를 CloudWatch에 기록
본 함수는 WebSocket 연결 상태 관리를 위한 필수 모듈로, 연결이 끊어진 사용자의 connectionId 를 정리하여 테이블 누적을 방지합니다

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
conn_id = event['requestContext']['connectionId']
```
### 3. 로그 기록
연결 해제 이벤트를 CloudWatch Logs에 출력합니다.
### 4. DynamoDB 삭제
다음 코드로 연결된 레코드를 삭제합니다.
```python
table.delete_item(Key={'connectionId': conn_id})
```
### 5. 응답
- HTTP 200
- `"disconnected"` 반환

---
## 4. 환경 변수 (Environment Variables)
| 이름                | 예시                             | 설명                                 |
| ----------------- | ------------------------------ | ---------------------------------- |
| CONNECTIONS_TABLE | `IncidentWebSocketConnections` | WebSocket 연결 정보를 저장하는 DynamoDB 테이블 |

---
## 5. 사용 리소스 / 의존성 (Dependencies)
### AWS 리소스
   - DynamoDB
      - CONNECTIONS_TABLE (PK: connectionId)
   - API Gateway WebSocket – $disconnect Route
### Python 패키지
   - boto3
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
- 삭제는 connectionId 기준 단일 항목만 제거
- 부가 정보(clientId, region 등)를 활용한 후처리 기능은 포함되어 있지 않음
- 비정상 종료(네트워크 단절 등) 시 disconnect 호출이 누락될 가능성이 있음
### TODO
- orphaned connection 자동 정리 기능 확장
- 소켓 종료 원인 분석 및 로그 강화
- 사용자 정보 기반 disconnect 후속 처리 로직 추가
