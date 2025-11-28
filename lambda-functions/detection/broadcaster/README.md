## 1. 함수 개요 (Overview)
이 Lambda 함수는 EventBridge로 유입되는 CloudTrail ConsoleLogin 이벤트를 받아서, 이벤트에서 핵심 필드를 추출·정규화하고(성공/실패, 사용자, ARN, 지역, UA, IP), 공용 IP이면 외부 Geo API로 지역 정보(국가/도/도시/위도/경도)를 조회하여 meta.geo에 병합하고, 필요 시 Incident 테이블에 신규 인시던트 생성, 현재 연결된 모든 WebSocket 클라이언트에 브로드캐스트합니다.

주요 기능:
- WS 엔드포인트 자동 보정: WS_ENDPOINT에 스킴이 없으면 https://를 붙여 사용.
- Incident 저장 시 부동소수점 안전 변환: float → Decimal 재귀 변환 후 Put.
- 심각도 규칙: 실패이면서 MFA 미사용(또는 불명) → HIGH, 그 외 실패 → MEDIUM, 성공 → LOW.
- 연결 정리 옵션: Gone/LimitExceeded에서 삭제 코드는 주석 처리(로그만 남김).

---
## 2. 동작 조건 & 트리거 (Conditions & Trigger)
### 이벤트 소스
EventBridge(CloudTrail 기반)

### 처리 대상 이벤트
| 조건                                   | 설명                                |
| ------------------------------------ | --------------------------------- |
| `detail.eventName == "ConsoleLogin"` | 해당 이벤트만 처리. 그 외 이벤트는 스킵 로그 후 무시.  |

### 해제 트리거
- EventBridge Scheduler가 mode=unlock 입력으로 동일 Lambda 호출 → 잠금 해제 수행

---
## 3. 처리 로직 요약 (Logic Flow)
### 1. 이벤트 정규화
- 단건/배열/`Records` 형태를 모두 `candidates`로 정규화.
### 2. 로그인 필드 추출 (`extract_login_fields`)
- 성공/실패, 사용자/계정/리전, `resource`, `arn` 복원(`resolve_arn`)
- `meta.device.ua`, `meta.ip` 세팅, 공용 IP면 `ip-api.com`으로 Geo 조회 후 `meta.geo` 병합.
### 3. 심각도 산정 (`build_severity`)
- 실패+MFA 미사용/불명=HIGH, 실패=MEDIUM, 성공=LOW.
### 4. Incident 저장(옵션) (`save_incident_if_needed`)
- `type`이 존재하면 Incident를 생성: `incident_id`, `event_type`, `resource`, `severity`, `status=NEW`, `meta`, `source/account/region`, `created_at/updated_at`.
- `float → Decimal` 재귀 변환 후 Put. 생성 시 `incident_id` 반환.
### 5. 브로드캐스트 (`post_to_all`)
- `TABLE_NAME`을 스캔하여 각 `connectionId`로 `post_to_connection`.
- `GoneException`/`LimitExceededException`은 로그만 남기고 보존(주석 해제 시 즉시 삭제 가능).
### 6. 종료 응답
- 처리 건수 로그, `{"statusCode": 200}` 반환

---
## 4. 환경 변수 (Environment Variables)
| 이름               | 예시                                                                  | 설명                              |
| ---------------- | ------------------------------------------------------------------- | ------------------------------- |
| `TABLE_NAME`     | `WebSocketConnections`                                              | WebSocket 연결 보관용 DynamoDB 테이블.  |
| `WS_ENDPOINT`    | `abcd.execute-api.ap-northeast-2.amazonaws.com/prod` 또는 `https://…` | 스킴이 없으면 코드가 `https://`를 붙여 보정.  |
| `INCIDENT_TABLE` | `Incident`(기본값)                                                     | 인시던트 저장 DynamoDB 테이블.           |

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
   - 표준: os, json, time, datetime, ipaddress, urllib.request, decimal.Decimal, random
   - AWS SDK: boto3, botocore.exceptions.ClientError

---
## 6. 필요한 IAM 권한 (Required IAM Permissions)
### 1. DynamoDB 권한
#### 1.1 `WebSocketConnections_V2`
   - "dynamodb:Scan", "dynamodb:DeleteItem"
#### 1.2 `Incident`
   - "dynamodb:PutItem", "dynamodb:Scan", "dynamodb:DeleteItem", "dynamodb:DescribeTable"
### 2. API Gateway WebSocket 연결 관리 권한
   - "execute-api:ManageConnections"
   - Resource : "arn:aws:execute-api:us-east-1:*:egtwu3mkhb/prod/POST/@connections/*"
   - WebSocket 대시보드에 실시간 이벤트 push, 연결이 죽은 클라이언트 자동 삭제

---
## 7. 한계 & TODO (Limitations / TODO)
   - 외부 IP Geo 의존: 외부 서비스 가용성/정확도에 영향 받음(요청 제한, VPC NAT 필요).
   - 대규모 연결 환경에서 스캔 기반 브로드캐스트는 비용/지연 증가.
   - TODO
       - 연결 테이블에 파티션 전략(GSI) 도입 후, 구독 그룹별 선택적 브로드캐스트
       - WebSocket Gone 자동 삭제 플래그 운영 옵션화
       - Geo 캐시/사내 Geo 서비스 연동(요율·지연 완화)