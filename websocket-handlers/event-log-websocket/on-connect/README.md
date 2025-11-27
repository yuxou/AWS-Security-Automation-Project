## 1. 함수 개요 (Overview)
이 Lambda 함수는 API Gateway WebSocket의 $connect 라우트에서 실행되며,
웹 클라이언트가 처음 WebSocket에 연결할 때 연결 정보를 DynamoDB에 저장 합니다.

주요 기능:
1. WebSocket 연결 생성 시 ConnectionId 저장
2. queryStringParameters로 전달되는 clientId, account, region 값을 함께 기록
3. 소스 IP(sourceIp) 저장
4. TTL(24시간) 자동 만료 설정
이 함수는 WebSocket 대시보드 또는 실시간 알림 시스템에서 연결된 사용자 목록을 유지하기 위한 기본 연결 처리 모듈입니다.

---
## 2. 동작 조건 & 트리거 (Conditions & Trigger)
### 이벤트 소스
API Gateway WebSocket – `$connect` route

### 처리 대상 이벤트
| 구분                | 이벤트           | 설명                             |
| ----------------- | ------------- | ------------------------------ |
| WebSocket Connect | `$connect` 호출 | 클라이언트가 WebSocket 연결을 처음 열 때 발생 |

---
## 3. 처리 로직 요약 (Logic Flow)
### 1. WebSocket Client → $connect → Lambda 호출
- API Gateway가 새로운 WebSocket 연결을 수립하면 Lambda가 호출됩니다.
### 2. Connection 정보 추출
- `connectionId`
- `queryStringParameters.clientId`
- `queryStringParameters.account`
- `queryStringParameters.region`
- `requestContext.identity.sourceIp`
### 3. TTL(24시간) 생성
```python
expire_at = int(time.time()) + 86400
```
### 4. DynamoDB CONNECTIONS_TABLE에 저장
저장 항목:
- connectionId
- createdAt (epoch ms)
- ttl
- clientId (옵션)
- account (옵션)
- region (옵션)
- sourceIp (옵션)
### 5. 응답
- HTTP 200
- `"connected"` 반환

---
## 4. 환경 변수 (Environment Variables)
| 이름                | 예시                             | 설명                                        |
| ----------------- | ------------------------------ | ----------------------------------------- |
| CONNECTIONS_TABLE | `IncidentWebSocketConnections` | 연결된 WebSocket 클라이언트 목록을 저장하는 DynamoDB 테이블 |

---
## 5. 사용 리소스 / 의존성 (Dependencies)
### AWS 리소스
   - DynamoDB
      - CONNECTIONS_TABLE (PK: connectionId)
   - API Gateway WebSocket — $connect Route
### Python 패키지
   - boto3
   - json
   - time
   - os

---
## 6. 필요한 IAM 권한 (Required IAM Permissions)
이 Lambda가 정상 동작하려면 다음 권한이 반드시 필요합니다.
### 1. DynamoDB 권한
- dynamodb:PutItem
- dynamodb:UpdateItem (선택적)
- dynamodb:GetItem (선택적)
리소스 예:
```css
arn:aws:dynamodb:{region}:{account-id}:table/{CONNECTIONS_TABLE}
```
### 2. CloudWatch Logs 권한
- AWSLambdaBasicExecutionRole
   - 로그 출력

---
## 7. 한계 & TODO (Limitations / TODO)
### 한계
- 기존 연결을 삭제(cleanup)하는 로직이 없음
   - 오래된 연결이 계속 누적될 수 있음
- TTL은 24시간으로 고정
- clientId/account/region은 신뢰 기반 입력값이며 검증 기능 없음
### TODO
- 오래된 connectionId 자동 정리(Cleanup) 기능 추가
- 연결 중복 방지 로직 추가
- clientId 인증·검증 기능 확장
- region/account 기반 연결 분류 기능 개선
