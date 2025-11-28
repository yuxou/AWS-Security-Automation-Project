## 1. 함수 개요 (Overview)
WebSocket 클라이언트가 “구독”을 시작할 때 호출되는 Lambda로, 현재 connectionId를 Connections 테이블에 TTL과 함께 업서트하고, Incident 테이블에서 최근 인시던트 목록을 필터·페이징하여 해당 연결로 즉시 푸시합니다. 410(Gone) 응답 시에는 연결을 정리합니다.

주요 기능:
- connectionId 업서트(생성 시간, TTL, clientId 기본값 저장)
- 요청 바디의 조건으로 Incident 스캔(커서, 심각도, 상태 필터)
- 최신순 정렬 후 지정 개수만 푸시, 다음 페이지 커서 제공
- post_to_connection 오류 처리(410 시 delete, Forbidden/기타는 보존)

---
## 2. 동작 조건 & 트리거 (Conditions & Trigger)
### 이벤트 소스
- API Gateway WebSocket: 라우트 subscribe에 매핑된 Lambda 핸들러.
호출 시 event.requestContext.connectionId와 요청 바디(JSON)가 전달됩니다.

### 요청 바디(옵션)
| 필드         | 타입                 | 설명                                                        |   |
| ---------- | ------------------ | --------------------------------------------------------- | - |
| `limit`    | number             | 반환 최대 건수(1~200, 기본 50)                                    |   |
| `cursor`   | string/number      | `created_at` 기준 “이 값보다 과거”만 조회                            |   |
| `severity` | string or string[] | 필터: Incident 심각도(예: `"LOW"`, `["MEDIUM","HIGH"]`)         |   |
| `status`   | string or string[] | 필터: Incident 상태(예: `"NEW"`, `["PROCESSING","MITIGATED"]`) |   |

---
## 3. 처리 로직 요약 (Logic Flow)
### 1. 연결 업서트(Upsert)
- `connectionId`를 키로 `createdAt(ms)`, `ttl(sec)`, `clientId`를 `if_not_exists`로 설정하여 기존 긴 TTL을 덮어쓰지 않음.
- 업서트 후 `get_item`으로 저장 내용을 로그에 남김(오류 허용).
### 2. Incident 조회
- 요청 바디로 `limit` 보정(1~200) 후, `cursor`/`severity`/`status`를 조합해 FilterExpression 생성.
- scan을 반복 호출하며 누적(최대 `limit * 3`까지), 이후 `created_at` 내림차순 정렬.
- `sliced = items[:limit]`, `nextCursor = sliced[-1].created_at`(정확히 `limit`개일 때만 제공).
### 3. 푸시 & 연결 정리
- `{ kind: "incident_history", incidents: [...], nextCursor }` 페이로드를 현재 `connectionId`로 전송.
- 410(Gone) 발생 시 해당 `connectionId`를 삭제. `Forbidden`/기타 오류는 삭제하지 않음.

---
## 4. 환경 변수 (Environment Variables)
| 이름                  | 예시                                                      | 설명                          |   |
| ------------------- | ------------------------------------------------------- | --------------------------- | - |
| `INCIDENT_TABLE`    | `Incident`                                              | 인시던트 히스토리 테이블 이름            |   |
| `CONNECTIONS_TABLE` | `IncidentWebSocketConnections`                          | 구독 연결 보관 테이블                |   |
| `WS_ENDPOINT`       | `https://{api}.execute-api.{region}.amazonaws.com/prod` | API GW Management API 엔드포인트 |   |
| `TTL_HOURS`         | `24`                                                    | 연결 TTL 시간(초로 환산 저장)         |   |

---
## 5. 사용 리소스 / 의존성 (Dependencies)
### AWS 리소스
   - DynamoDB
     - CONNECTIONS_TABLE (WebSocket 연결 ID 저장)
     - INCIDENT_TABLE (Incident 저장)
   - API Gateway WebSocket
     - post_to_connection() 사용
   - CloudTrail + EventBridge
### Python 패키지
   - 표준: os, json, time, typing
   - AWS SDK: boto3, botocore.exceptions.ClientError
   - DynamoDB 조건식: boto3.dynamodb.conditions.Attr

---
## 6. 필요한 IAM 권한 (Required IAM Permissions)
### 1. DynamoDB 권한
#### 1.1 `IncidentWebSocketConnections`
   - "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Scan", "dynamodb:DeleteItem"
#### 1.2 `Incident`
   - "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Scan", "dynamodb:DeleteItem"
### 2. API Gateway WebSocket 연결 관리 권한
   - "execute-api:ManageConnections"
   - Resource : "arn:aws:execute-api:us-east-1:*:egtwu3mkhb/prod/POST/@connections/*"
   - WebSocket 대시보드에 실시간 이벤트 push, 연결이 죽은 클라이언트 자동 삭제

---
## 7. 한계 & TODO (Limitations / TODO)
   - `scan` 기반 필터링이므로 대규모 테이블에서 비용/지연이 증가할 수 있음(향후 GSI/Query 전환 검토).
   - `created_at` 자료형이 문자열/숫자 혼재 시 정렬/커서 오동작 가능(스키마 일관성 필요).
   - `Forbidden` 오류는 연결을 삭제하지 않으므로, 권한 불일치가 지속될 경우 전송 실패가 반복될 수 있음.
   - TODO
       - `created_at` 파티션/정렬키 도입 및 Query 기반 페이지네이션
       - `clientId` 식별/업데이트 프로토콜
       - 서버측 보존 정책(TTL) 알림 및 자동 연장 로직
