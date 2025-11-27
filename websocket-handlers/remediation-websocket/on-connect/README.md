## 1. 함수 개요 (Overview)
이 Lambda 함수는 자동 대응(Remediation) 시스템에서 사용되는 WebSocket 채널의
$connect 라우트에서 실행되며, 자동 대응 모듈(Remediation Dashboard 또는 Agent)이 WebSocket에 연결될 때
해당 connectionId 및 관련 메타데이터를 DynamoDB에 저장합니다.

주요 기능:
1. Remediation WebSocket 연결 생성 시 connectionId 를 등록
2. 자동 대응 요청을 전송하는 클라이언트(Remediation Agent)의 clientId, account, region 값을 저장
3. Remediation 알림 및 조치 결과를 특정 사용자/계정/리전으로 라우팅하기 위한 연결 식별 정보를 유지

---
## 2. 동작 조건 & 트리거 (Conditions & Trigger)
### 이벤트 소스
API Gateway WebSocket – `$connect` route (자동 대응 채널)

### 처리 대상 이벤트
| 구분                            | 이벤트           | 설명                                 |
| ----------------------------- | ------------- | ---------------------------------- |
| Remediation WebSocket Connect | `$connect` 호출 | 자동 대응 모듈 또는 Dashboard가 연결할 때 실행됩니다 |

---
## 3. 처리 로직 요약 (Logic Flow)
### 1. Remediation WebSocket → $connect → Lambda 실행
- 자동 대응 기능을 제공하는 클라이언트가 WebSocket에 연결하면 Lambda가 호출됩니다.
### 2. Connection 정보 추출
```python
conn_id = event['requestContext']['connectionId']
```
### 3. queryStringParameters 파싱
Remediation 에이전트 또는 UI에서 전달할 수 있는 값들입니다.
| 필드       | 설명                               | 기본값     |
| -------- | -------------------------------- | ------- |
| clientId | 연결한 Remediation Agent 또는 UI의 식별자 | unknown |
| account  | 대상 AWS 계정 ID                     | None    |
| region   | Remediation 처리가 필요한 리전           | None    |
### 4. DynamoDB CONNECTIONS_TABLE에 저장
저장 항목:
| 필드           | 설명                             |
| ------------ | ------------------------------ |
| connectionId | Remediation WebSocket 연결 고유 ID |
| createdAt    | 연결 생성 시각(epoch ms)             |
| clientId     | Remediation Agent 또는 UI가 전달한 값 |
| account      | 선택적                            |
| region       | 선택적                            |
### 5. DynamoDB PutItem 수행
자동 대응 연결 목록 테이블에 해당 연결을 저장합니다.
```python
table.put_item(Item=item)
```
### 6. 응답
- HTTP 200
- `"connected"` 반환

---
## 4. 환경 변수 (Environment Variables)
| 이름                | 예시                                | 설명                                                    |
| ----------------- | --------------------------------- | ----------------------------------------------------- |
| CONNECTIONS_TABLE | `RemediationWebSocketConnections` | 자동 대응(Remediation) WebSocket 연결 정보를 저장하는 DynamoDB 테이블 |


---
## 5. 사용 리소스 / 의존성 (Dependencies)
### AWS 리소스
   - DynamoDB
      - CONNECTIONS_TABLE (PK: connectionId)
   - API Gateway WebSocket — Remediation 전용 $connect Route
### Python 패키지
   - boto3
   - time
   - os

---
## 6. 필요한 IAM 권한 (Required IAM Permissions)
이 Lambda가 정상 동작하려면 다음 권한이 반드시 필요합니다.
### 1. DynamoDB 권한
- dynamodb:PutItem
- dynamodb:GetItem (선택)
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
- TTL 자동 만료 필드가 존재하지 않아 오래된 Remediation 연결이 누적될 수 있습니다.
- clientId, account, region 값은 검증 없이 저장됩니다.
- Remediation WebSocket 특성상 추가적인 인증·권한 검증이 필요할 수 있습니다.
### TODO
- TTL(시간 기반 자동 삭제) 추가
- 클라이언트 인증(clientId 검증) 기능 추가
- Remediation 처리 대상 계정/리전 기반 라우팅 고도화
- Remediation Agent 상태 모니터링 기능 확장