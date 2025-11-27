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
```python
cid = event["requestContext"]["connectionId"]
```
### 3. queryStringParameters 파싱
| 필드       | 설명             | 기본값     |
| -------- | -------------- | ------- |
| clientId | 대시보드/Agent 식별자 | unknown |
| account  | AWS 계정 ID      | 빈 문자열   |
| region   | AWS 리전         | 빈 문자열   |
### 4. source IP 추출
다음 우선순위로 클라이언트 IP를 얻습니다:
1. `requestContext.identity.sourceIp`
2. `X-Forwarded-For` 또는 `x-forwarded-for` 헤더
3. 둘 다 없으면 빈 문자열
### 5. TTL 계산
```python
ttl = now_sec + TTL_HOURS * 3600
```
### 6. DynamoDB 저장 항목 구성
| 필드           | 설명                 |
| ------------ | ------------------ |
| connectionId | WebSocket 연결 ID    |
| createdAt    | epoch milliseconds |
| ttl          | 만료 시각(epoch sec)   |
| clientId     | 기본값 unknown        |
| account      | 선택적                |
| region       | 선택적                |
| sourceIp     | 클라이언트의 실제 IP       |
### 7. DynamoDB PutItem 저장
```python
table.put_item(Item=item)
```
### 8. 응답
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
   - botocore.exceptions
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
- 접속 IP를 기반으로 클라이언트 식별하므로 프록시나 NAT 환경에서는 정확도가 떨어질 수 있음
- TTL 만료 외에 비정상 종료 정리 로직은 포함되어 있지 않음
- clientId, account, region 값의 유효성 검증 기능이 없음
### TODO
- userAgent, browser fingerprint 등 추가 클라이언트 정보 저장 확장
- 비정상 종료 연결 식별 후 자동 정리 기능 추가
- 여러 지역/계정 기반 대시보드 라우팅 고도화
- TTL 기반 청소 작업의 CloudWatch 자동화 추가
