## 1. 함수 개요 (Overview)
이 Lambda 함수는 API Gateway WebSocket의 $connect 라우트에서 실행되며,
클라이언트가 WebSocket 연결을 생성할 때 DynamoDB에 연결 정보를 저장합니다.

주요 기능:
1. WebSocket 연결 생성 시 ConnectionId 저장
2. TTL 값을 기반으로 연결 정보를 일정 시간(기본 24시간) 후 자동 만료되도록 설정
3. WebSocket 연결 관련 로그를 기록하여 모니터링 및 디버깅에 활용
이 함수는 WebSocket 사용자 관리, 실시간 알림 시스템, 연결 상태 추적을 위한 필수 구성 요소입니다.

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
```python
cid = event["requestContext"]["connectionId"]
```
### 3. queryStringParameters 파싱
| 필드       | 설명           | 기본값     |
| -------- | ------------ | ------- |
| clientId | 접속 클라이언트 식별자 | unknown |
| account  | AWS 계정 ID    | (빈 문자열) |
| region   | AWS 리전       | (빈 문자열) |
### 4. TTL 생성
TTL 기본값: 24시간
```python
ttl = now_sec + TTL_HOURS * 3600
```

### 5. DynamoDB Item 생성
저장 항목:
| 필드           | 설명                 |
| ------------ | ------------------ |
| connectionId | WebSocket 고유 ID    |
| createdAt    | epoch milliseconds |
| ttl          | 만료 시간              |
| clientId     | 사용자 식별자            |
| account      | 선택적                |
| region       | 선택적                |
### 5. DynamoDB에 PutItem 저장
History WebSocket 클라이언트 목록에 추가합니다.
### 6. 응답
- HTTP 200
- `"connected"` 반환

---
## 4. 환경 변수 (Environment Variables)
| 이름                | 예시                             | 설명                                 |
| ----------------- | ------------------------------ | ---------------------------------- |
| CONNECTIONS_TABLE | `IncidentWebSocketConnections` | WebSocket 연결 정보를 저장하는 DynamoDB 테이블 |
| TTL_HOURS         | `24`                           | 연결 정보를 유지할 TTL(시간 단위)              |

---
## 5. 사용 리소스 / 의존성 (Dependencies)
### AWS 리소스
   - DynamoDB
      - CONNECTIONS_TABLE (PK: connectionId)
   - API Gateway WebSocket — `$connect` Route
### Python 패키지
   - boto3
   - botocore.exceptions
   - time
   - os

---
## 6. 필요한 IAM 권한 (Required IAM Permissions)
이 Lambda가 정상 동작하려면 다음 권한이 반드시 필요합니다.
### 1. DynamoDB 권한
- dynamodb:PutItem
- dynamodb:GetItem
- dynamodb:DeleteItem (TTL 외 정리 시)
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
- TTL 외의 불필요한 연결(clean-up) 로직은 포함되어 있지 않습니다.
- IP 주소, User-Agent 등 상세 접속 정보는 저장하지 않습니다.
- clientId/account/region 값은 검증 없이 저장됩니다.
### TODO
- 접속 IP, User-Agent 로그 저장 기능 확장
- History 구독 스트림 재접속 판단을 위한 heartbeat 관리 기능 추가
- 중복 연결 방지 또는 연결 수 제한 기능 추가