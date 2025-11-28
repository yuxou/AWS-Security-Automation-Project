## 1. 함수 개요 (Overview)
이 Lambda는 CloudTrail 관리 이벤트 중 IAM 사용자의 Access Key 사용을 받아, 국가 / ASN / AWS 리전이 평소와 다르거나 최근 N일(기본 7일) 동안 보지 못한 값일 때 대시보드(WebSocket) 와 Incident 테이블로 알림을 보내는 역할을 합니다.
- GeoIP(국가/ASN) 및 AWS 리전 기준의 베이스라인 학습 & 이상 탐지 
- 최근 N일 미접속(stale) 재등장 시 재알림 
- 중복 알림 억제 윈도우(초 단위) 옵션 
- 대시보드 알림 포맷으로 변환 후 API Gateway WebSocket 브로드캐스트 
- Incident 테이블에 details 필드로 기록

---
## 2. 동작 조건 & 트리거 (Conditions & Trigger)
| 구분               | 조건                                                                                   |
| ---------------- | ------------------------------------------------------------------------------------ |
| EventBridge 트리거  | `detail-type = "AWS API Call via CloudTrail"`                                        |
| 내부 필터            | `userIdentity.type`이 **IAMUser**인 이벤트만 처리 (assumed-role 등은 스킵)                       |
| Access Key 필요    | `userIdentity.accessKeyId`가 없는 이벤트는 스킵                                               |
| 탐지 조건(둘 중 하나 이상) | ① **처음 보는** 국가/ASN/리전 등장 ② **최근 N일(기본 7일)** 동안 보지 못한 국가/ASN/리전의 **재등장**              |
| 억제(옵션)           | `SUPPRESS_SECONDS > 0`인 경우 동일 (accessKeyId, country, asn, region) 조합은 억제 창 동안 재알림 스킵 |

---
## 3. 처리 로직 (Logic) 
### 3.1. 수신/필터링
- CloudTrail 관리 이벤트만 수신 → IAMUser + AccessKeyId가 없으면 즉시 스킵.

### 3.2. 컨텍스트 추출
- sourceIPAddress로 GeoIP 조회(국가/ASN), awsRegion 추출, 사용자 ARN 확정(assumed-role이면 issuer가 user/*면 그 ARN 사용).

### 3.3. 베이스라인 갱신 & 이상 판단
- DynamoDB security-alerts-state-v2에 AccessKey별로 countries/asns/regions와 *_last_seen(에포크) 저장/갱신.
- 처음 보는 값이거나, 마지막 본 지 STALE_DAYS일 이상이면 이상으로 판단.

### 3.4. 중복 억제(옵션)
- SUPPRESS_SECONDS가 설정돼 있으면, 동일 조합은 억제 창 내 재알림 스킵.

### 3.5. Incident 기록
- Incident 테이블에 details로 요약 JSON 저장(시간/소스/타입/ARN/계정/리전/규칙/심각도 등).

### 3.6. 대시보드 브로드캐스트
- API Gateway Management API를 통해 WebSocketConnections_v2에 등록된 모든 커넥션으로 알림 전송.

### 3.7. 로그/결과
- 상태(JSON) 출력 및 예외 시 로깅.
---
## 4. 환경 변수 (Environment Variables) 
| Key                           | Value 예시                                                | 설명                                                     |
| ----------------------------- |---------------------------------------------------------| ------------------------------------------------------ |
| `WS_ENDPOINT`                 | `https://xxxx.execute-api.us-east-1.amazonaws.com/prod` | API Gateway WebSocket 엔드포인트(스테이지 포함)                   |
| `STATE_TABLE`                 | `security-alerts-state-v2`                              | Access Key 베이스라인/마지막 본 시각을 저장하는 DynamoDB 테이블           |
| `CONNECTIONS_TABLE`           | `WebSocketConnections_v2`                               | 활성 WebSocket 연결을 보관하는 DynamoDB 테이블(컬럼: `connectionId`) |
| `INCIDENT_TABLE`              | `Incident`                                              | Incident 히스토리 적재용 DynamoDB 테이블                         |
| `STALE_DAYS`                  | `7`                                                     | 마지막 관측 후 **N일 이상** 지난 값이면 재알림(기본 7)                    |
| `SUPPRESS_SECONDS`            | `0` 또는 `300`                                            | 중복 알림 억제 창(초). 0 이면 비활성화                               |
| `FORCE_IP`                    | `3.3.3.3`                                               | 테스트용 고정 IP(GeoIP 강제)                                   |
| `HTTP_TIMEOUT`                | `8`                                                     | GeoIP HTTP 타임아웃(초)                                     |
| `STATE_PK_ATTR`               | `id`                                                    | `STATE_TABLE`의 파티션 키 이름                                |
| `IGNORE_PRINCIPAL_SUBSTRINGS` | `assumed-role/`                                         | *(현 버전은 IAMUser 필터로 대체되어 실사용 없음 / 호환용)*                |

---
## 5. 사용 리소스 및 의존성 (Resources & Dependencies) 
### 5.1. AWS
- DynamoDB
  - security-alerts-state-v2 (베이스라인/last_seen/억제키 저장)
  - WebSocketConnections_v2 (커넥션 목록)
  - Incident (Incident 기록, 필드: details)
- API Gateway (WebSocket): 관리 API(post_to_connection) 사용
- CloudWatch Logs: 함수 로그
- STS: GetCallerIdentity (계정 ID 조회 백업)

### 5.2. 외부 서비스
- ipinfo.io : GeoIP 조회(국가/ASN)

### 5.3. 런타임
- Python 3.x, boto3
---
## 6. IAM 권한 (IAM Permissions)

### 6.1. CloudWatch Logs
- 로그 그룹/스트림 생성 및 로그 쓰기
- CreateLogGroup, CreateLogStream, PutLogEvents
### 6.2. STS: GetCallerIdentity
### 6.3. API Gateway(WebSocket)
- execute-api:ManageConnections (해당 리전/계정의 WebSocket 스테이지에 대한 커넥션 관리)
### 6.4. DynamoDB
- security-alerts-state-v2: GetItem, PutItem (베이스라인/last_seen/억제키 저장·조회)
- WebSocketConnections_v2: Scan, GetItem, DeleteItem (활성 커넥션 조회 및 정리)
- Incident: PutItem (Incident 레코드 기록)

---
## 7. 한계 및 향후 과제 (Limitations & TODO)
| 한계                                               | 향후 과제                                    |
| ------------------------------------------------ | ---------------------------------------- |
| 외부 GeoIP(ipinfo.io) 의존 → 네트워크 문제 시 국가/ASN 미확정 가능 | 사내/자체 GeoIP 캐시 또는 대안 API 도입, 타임아웃/재시도 강화 |
| 초기 1회는 **학습**만 수행(알림 없음)                         | 초기 온보딩 모드에서도 경고(LOW) 발송 옵션 추가            |
| **IAMUser만** 탐지(assumed-role 단독 사용 시 스킵)         | 역할 세션도 사용자인증 소스로 매핑해 허용하는 고급 모드 추가       |
| EventBridge/CloudTrail 특성상 동일 이벤트 중복 도착 가능       | `eventId` 기반 **멱등성 키** 저장으로 완전 중복 제거     |
| 억제키/베이스라인을 **단일 테이블**에 저장 → 테이블 잠금/경합 가능성        | 억제 상태 전용 테이블 분리, TTL 활용해 자동 정리           |
| WebSocket 커넥션 정리 중 AccessDenied/삭제 실패 가능         | 재시도 및 Dead-letter 큐/백오프 도입               |
| Incident 스키마 단순(`details`만 저장)                   | 태그/플랫폼/팀/상태 전이 로그 등 확장 스키마 도입            |
| 리전 추출 로직이 원 이벤트에 의존                              | 서비스별 예외 케이스(글로벌 서비스 등) 보강                |


