## 1. 함수 개요 (Overview)
이 Lambda 함수는 Incident 대시보드 WebSocket의 구독(subscribe) 라우트에서 실행되며, 클라이언트가 WebSocket 연결을 통해 인시던트 히스토리를 요청할 때 다음 기능을 수행합니다.

주요 기능:
1. WebSocket 연결 정보(connectionId)의 TTL 및 기본 필드(createdAt, clientId)를 갱신
2. Incident 테이블을 조건 필터(Severity, Status, Cursor, Limit) 기반으로 조회
3. 클라이언트 연결이 끊긴(GoneException) 경우 DynamoDB에서 해당 connectionId를 삭제
이 함수는 Incident 대시보드의 실시간 데이터 구독 및 페이징 처리의 핵심 엔드포인트입니다.

---
## 2. 동작 조건 & 트리거 (Conditions & Trigger)
### 이벤트 소스
API Gateway WebSocket – Subscribe Route (`@connections`)

### 처리 대상 이벤트
| 구분           | 이벤트                      | 설명                                |
| ------------ | ------------------------ | --------------------------------- |
| Subscribe 요청 | WebSocket 메시지(body JSON) | 인시던트 히스토리 요청 및 필터 적용              |
| TTL/기본값 갱신   | connectionId 업데이트        | 사용자의 WebSocket 연결을 유지하기 위한 TTL 관리 |
| Cursor 기반 조회 | created_at < cursor      | 과거 인시던트 히스토리 페이징                  |
| 필터 기반 조회     | severity/status          | 선택 필터로 Incident 스캔                |

---
## 3. 처리 로직 요약 (Logic Flow)
### 1. WebSocket Subscribe 요청 수신
- 이벤트 body(JSON)를 파싱합니다.
- 필터 조건(cursor, severity, status) 및 limit 값을 추출합니다.
### 2. connectionId 정보(upsert) 갱신
다음 항목을 존재하지 않을 경우에만 저장합니다.
| 필드        | 설명                 |
| --------- | ------------------ |
| createdAt | 연결 최초 생성 시간(ms)    |
| ttl       | TTL_HOURS 기준 만료 시간 |
| clientId  | 기본값 "unknown"      |
사용 코드 예:
```python
conn_tbl.update_item(
    Key={"connectionId": cid},
    UpdateExpression="SET ...",
)
```
### 3. Incident 테이블 스캔 + 필터 적용
- FilterExpression 생성
- Cursor 조건(created_at < cursor) 적용
- severity / status 값 is_in 필터 적용
- 최대 limit × 3 까지 읽어서 과도한 스캔을 방지합니다.
### 4. created_at 기준 내림차순 정렬
날짜/epoch 혼합 입력에도 대응하기 위해 파싱 로직을 포함합니다.
### 5. nextCursor 계산
조회한 항목 중 마지막(created_at) 값을 다음 요청 커서로 제공합니다.
### 6. WebSocket 응답 전송
결과 페이로드 구조:
```json
{
  "kind": "incident_history",
  "incidents": [...],
  "nextCursor": "..."
}
```
전송 API:
```python
apigw.post_to_connection(ConnectionId=cid, Data=...)
```
### 6. 연결이 끊긴 경우 삭제
GoneException(410) 발생 시 connectionId를 DynamoDB에서 삭제합니다.

---
## 4. 환경 변수 (Environment Variables)
| 이름                | 예시                             | 설명                              |
| ----------------- | ------------------------------ | ------------------------------- |
| INCIDENT_TABLE    | `Incidents`                    | 인시던트 데이터 저장 DynamoDB 테이블        |
| CONNECTIONS_TABLE | `IncidentWebSocketConnections` | 구독 중인 WebSocket 연결 목록           |
| WS_ENDPOINT       | API Gateway WebSocket endpoint | post_to_connection 호출에 사용       |
| TTL_HOURS         | `24`                           | connectionId TTL 관리 시간(기본 24시간) |

---
## 5. 사용 리소스 / 의존성 (Dependencies)
### AWS 리소스
   - DynamoDB
      - INCIDENT_TABLE
      - CONNECTIONS_TABLE
   - API Gateway WebSocket Management API
   - CloudWatch Logs
### Python 패키지
   - boto3
   - botocore
   - dateutil.parser
   - decimal
   - os, json, time 등 표준 라이브러리

---
## 6. 필요한 IAM 권한 (Required IAM Permissions)
이 Lambda가 정상 동작하려면 다음 권한이 반드시 필요합니다.
### 1. DynamoDB 권한
- dynamodb:Scan
- dynamodb:GetItem
- dynamodb:UpdateItem
- dynamodb:DeleteItem (연결 만료 정리 시)
### 2. API Gateway WebSocket 권한
- execute-api:ManageConnections
   - post_to_connection 호출용 권한
예시 리소스:
```json
arn:aws:execute-api:{region}:{account}:{api-id}/{stage}/POST/@connections/*
```
### 3. CloudWatch Logs 권한
- AWSLambdaBasicExecutionRole (기본 로그 기록)

---
## 7. 한계 & TODO (Limitations / TODO)
### 한계
- DynamoDB Scan 기반이므로 대량 데이터 처리 시 성능 비용이 증가할 수 있습니다.
- created_at 값이 문자열/epoch 혼용일 수 있어 파싱 비용이 존재합니다.
- TTL 관리가 단순 시간 기반이며 사용자 활동 기반 고도화는 미포함입니다.
### TODO
- GSI 기반 정렬 및 페이징 구조로 확장
- severity/status 필드 표준화 및 인덱싱 개선
- cursor 기반 페이지네이션 안정성 고도화
- connection 상태 모니터링 및 실시간 지표 확장