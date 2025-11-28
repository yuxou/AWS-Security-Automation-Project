## 1. 함수 개요 (Overview)
이 Lambda 함수는 로그인 계열 이벤트(콘솔 로그인 + STS 세션 시작 신호)를 분석해 Impossible Travel(짧은 시간 내 물리적으로 불가능한 위치 간 로그인)을 탐지하는 역할을 한다.

---
## 2. 동작 조건 & 트리거 (Conditions & Trigger)
### 2.1 EventBridge 규칙
- detail-type: "AWS Console Sign In via CloudTrail" & source: "aws.signin"
  - 콘솔 로그인 성공(responseElements.ConsoleLogin == "Success")만 처리
- detail-type: "AWS API Call via CloudTrail" & detail.eventSource: "sts.amazonaws.com" & detail.eventName ∈ {AssumeRole, AssumeRoleWithSAML, AssumeRoleWithWebIdentity, GetSessionToken, GetFederationToken, GetCallerIdentity} 
  - STS 기반 인증 신호로 간주하여 동일 탐지 로직 적용

### 2.2 탐지 조건(핵심)
- 동일 주체(principal)의 이전 로그인 좌표/시각과 현재 로그인 좌표/시각을 비교 
- 비교 윈도우: WINDOW_MINUTES(기본 10분)
- 허용 속도: SPEED_THRESHOLD_KMH(기본 900km/h)
- 산출 속도 > 임계치 → Impossible Travel 알림 발송 및 Incident 기록

---
## 3. 처리 로직 (Logic) 
### 1. 인증 컨텍스트 추출 
- 콘솔 로그인/STS 이벤트에서 (principal, userType, sourceIP, whenISO, authKind) 추출
### 2. GeoIP 조회
- ipinfo.io에서 lat/lon/city/country/asn 조회
### 3. 상태 로드/갱신
- STATE_TABLE(DynamoDB)에 이전 로그인 상태(connectionId = "impossible_travel:last_login#<principal>")를 읽고 현재 로그인 정보를 즉시 갱신(최신값 저장 보장)
### 4. 판정
- 이전 기록 없으면 베이스라인 생성 후 종료
- 시간 차(minutes)가 윈도우 초과면 종료
- 이전/현재 좌표의 대권거리 → 속도(km/h) 산출, 임계 초과 시 탐지 성공
### 5. 알림/저장
- 대시보드 스키마(v2, v1, flat)로 변환하여 WebSocket 브로드캐스트
- Incident 테이블에 1건 저장(incident_id 부여, 요청 포맷 포함)
### 6. (옵션) 자동대응
- ACTION_MODE ∈ {semi_auto, full_auto}이고 **화이트리스트(국가/ASN)**를 벗어나면
- IAMUser인 경우 full_auto에서 로그인 차단/Access Key 비활성화 시도
- 결과는 대시보드용 페이로드에 포함

---
## 4. 환경 변수 (Environment Variables) 
| Key                         | Value                                                          | 설명                                |
| --------------------------- |----------------------------------------------------------------| --------------------------------- |
| `WS_ENDPOINT_EVENTS`        | `https://egtwu3mkhb.execute-api.us-east-1.amazonaws.com/prod/` | **이벤트** 채널 WebSocket 관리 API 엔드포인트 |
| `WS_ENDPOINT_ACTIONS`       | `https://3y9ayspfp3.execute-api.us-east-1.amazonaws.com/prod/` | **액션** 채널 WebSocket 관리 API 엔드포인트  |
| `STATE_TABLE`               | `security-alerts-state`                                        | 이전 로그인 상태 저장용 DDB                 |
| `CONNECTIONS_TABLE_EVENTS`  | `WebSocketConnections_v2`                                      | 이벤트 채널 접속자 목록 DDB                 |
| `CONNECTIONS_TABLE_ACTIONS` | `RemediationWebSocketConnections`                              | 액션 채널 접속자 목록 DDB                  |
| `INCIDENT_TABLE`            | `Incident`                                                     | Incident 히스토리 DDB                 |
| `WINDOW_MINUTES`            | `10`                                                           | 비교 윈도우(분)                         |
| `SPEED_THRESHOLD_KMH`       | `900`                                                          | 불가능 이동 속도 임계값                     |
| `ACTION_MODE`               | `alert_only`                                                   | `semi_auto` | `full_auto`                       | 자동대응 동작 모드                        |
| `ALLOWED_COUNTRIES`         | 예: `KR,US`                                                     | 화이트리스트 국가(있으면 해당 국가는 자동차단 제외)     |
| `ALLOWED_ASN`               | 예: `AS4766,AS15169`                                            | 화이트리스트 ASN                        |

---
## 5. 사용 리소스 및 의존성 (Resources & Dependencies) 
### 5.1 DynamoDB
- security-alerts-state: connectionId(PK) 기반 상태 저장 
- Incident: Incident 기록(이벤트 히스토리)
- WebSocketConnections_v2, RemediationWebSocketConnections: 접속자 목록(브로드캐스트 대상)

### 5.2 API Gateway (WebSocket Management API)
- Events: egtwu3mkhb / Actions: 3y9ayspfp3 (stage: prod)

### 5.3 외부 의존성
- ipinfo.io(GeoIP) — VPC 환경이면 아웃바운드 egress 필요

### 5.4 Python 라이브러리
- 표준: json, time, re, urllib.request, datetime, math 
- AWS SDK: boto3, botocore.exceptions

---
## 6. IAM 권한 (IAM Permissions)
### 1. DynamoDB 접근 권한
- dynamodb:GetItem, dynamodb:PutItem, dynamodb:UpdateItem, dynamodb:DeleteItem, dynamodb:Scan
- Impossible Travel 탐지 및 WebSocket 연결 관리에 필요한 DynamoDB 접근 권한

### 2. WebSocket(API Gateway) 연결 관리

- execute-api:ManageConnections 
  - WebSocket 엔드포인트로 메시지 전송 
  - 끊긴 connection 삭제 처리
  - 실시간 이벤트 및 자동대응 로그 전송
- 브라우저로 실시간 메시지를 Push 하기 위해 필요한 권한

### 3. STS 이용
- sts:GetCallerIdentity
- 계정 ID 역추출을 위해 사용될 수 있는 권한
---
## 7. 한계 및 향후 과제 (Limitations & TODO)
| 구분                   | 내용                                                       |
| -------------------- | -------------------------------------------------------- |
| **한계 (Limitations)** |                                                          |
| GeoIP 정확도            | 상용 VPN/프록시/모바일 망 핑퐁 등으로 **오탐** 가능 → MaxMind DB로 전환/보강 권장 |
| 첫 로그인 베이스라인          | 첫 이벤트는 비교 대상이 없어 **탐지 없음**(베이스라인만 저장)                    |
| 시간 동기화               | CloudTrail 이벤트 타임스탬프/리전 레이턴시/시계 불일치 시 경계값 근처 오탐 가능       |
| 연결자 없는 경우            | WebSocket 연결 테이블이 비어 있으면 알림 브로드캐스트는 **ok=0**으로 끝남(오류 아님) |
| **향후 과제 (TODO)**     |                                                          |
| 화이트리스트 정책 고도화        | 국가/ASN 외에 CIDR, 사용자/역할 단위 정책 필요                          |
| STS 다양성              | 더 많은 인증 플로우(SSO/IdC 등) 패턴 확장을 지속 반영                      |
| Rate Limit/재시도       | WS 전송 시 대량 연결 환경의 재시도/백오프 로직 정교화                         |
| 자동대응 가드레일            | `semi_auto`에서 승인 워크플로, `full_auto`에서 예외리스트/비상해제 룰 필요     |


