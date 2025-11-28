## 1. 함수 개요 (Overview)
이 Lambda 함수는 EC2 공개 SG 배포 + IAM Access Key 생성과 같은 보안 위험 이벤트를 감지해서
1차 상관관계를 분석하고 밑에 두 가지의 역할을 한다.
- Incident 테이블(DynamoDB)에 인시던트 이력 저장
- WebSocket 대시보드로 알림 이벤트 전송

- 추가 기능
  - AuthorizeSecurityGroupIngress / ModifySecurityGroupRules 이벤트 시 SG 오픈 마커 기록 
  - 이후 RunInstances / ModifyInstanceAttribute 이벤트에서 공개 SG가 연결된 인스턴스 배포 여부 탐지 
  - 탐지 시 Incident 테이블에 인시던트 생성 및 WebSocket 대시보드로 알림 발송 
  - CreateAccessKey 이벤트 발생 시 새 Access Key 생성 인시던트 기록 및 대시보드 알림 
  - 대시보드 구버전 호환을 위한 v2 이벤트 + v1 평탄(flat) JSON + (옵션) 텍스트 요약 전송 
  - 이벤트 소스명을 AWS Sign-In/STS, CloudTrail, CloudWatch, S3, EC2 등으로 표준화( normalize_source() )

---
## 2. 동작 조건 & 트리거 (Conditions & Trigger)
| 구분                      | 조건                                                                | 트리거되는 이벤트(CloudTrail eventName)                                   | 설명                                              |
| ----------------------- | ----------------------------------------------------------------- | ----------------------------------------------------------------- | ----------------------------------------------- |
| **SG 오픈 마커 기록**         | `source = aws.ec2`<br>`detail-type = AWS API Call via CloudTrail` | • `AuthorizeSecurityGroupIngress`<br>• `ModifySecurityGroupRules` | 공개 SG(0.0.0.0/0) 오픈 또는 SG 규칙 수정 시 마커 기록         |
| **공개 SG 연결 인스턴스 배포 탐지** | `source = aws.ec2`<br>`detail-type = AWS API Call via CloudTrail` | • `RunInstances`<br>• `ModifyInstanceAttribute`                   | SG 오픈 후 일정 시간 내 공개 SG가 연결된 인스턴스가 배포되면 경고 이벤트 생성 |
| **생성된 Access Key 감지**   | `source = aws.iam`<br>`detail-type = AWS API Call via CloudTrail` | • `CreateAccessKey`                                               | 새 IAM Access Key 생성 시 인시던트 기록 및 대시보드 알림 발생      |
| **기본 패스 처리 (noop)**     | 그 외 모든 이벤트                                                        | 해당 없음                                                             | 해당 Lambda가 처리하지 않는 이벤트는 `noop` 으로 종료            |

---
## 3. 처리 로직 (Logic) 
### 3.1 SG 오픈 마커 기록 (handle_sg_ssh_open)
- AuthorizeSecurityGroupIngress / ModifySecurityGroupRules 이벤트인지 확인
- 이벤트에서 SG ID 추출
  - requestParameters.groupId 
  - responseElements.groupId
- userIdentity에서 행위자 ARN/Principal ID 추출
- 소스 IP, 이벤트 시간을 가져옴
- STATE 테이블(security-alerts-state-v2)에 다음 형태로 마커 저장
  - 파티션 키: STATE_PK = "id", 값: sg-open#{sg_id}
  - type = "sg_open", sg_id, actor, src_ip, when_iso, ttl, created 
  - ttl = now + CORRELATION_TTL_SECONDS (기본 600초)
- 상태 로그(marked_sg_open) 출력 후 종료

### 3.2 인스턴스 + 공개 SG 상관관계 탐지 (handle_instance_with_open_sg)
- RunInstances / ModifyInstanceAttribute 이벤트인지 확인 
- 이벤트에서 SG ID 목록 추출 (extract_sg_ids_from_event)
  - requestParameters.networkInterfaceSet.items[].groupSet.items[].groupId
  - requestParameters.securityGroupId 
  - responseElements.instancesSet.items[].networkInterfaceSet.items[].groupSet.items[].groupId 
  - requestParameters.groupSet.items[].groupId
- SG 목록이 없으면 종료
- STATE 테이블에서 각 SG에 대한 마커 조회 (get_open_markers_for_sg_ids)
  - 유효 TTL(현재 시간보다 크거나 같은 경우)인 마커만 사용
- 매칭되는 마커가 없으면 no_open_sg_match 로깅 후 종료
- 마커 중 하나에서 행위자 ARN 추출
- 이벤트에서 Instance ID 목록 추출
  - responseElements.instancesSet.items[].instanceId
- 리소스 문자열 구성 
  - 인스턴스 ID가 있으면 i-xxxx, 없으면 SG ID 리스트
- Incident details JSON 구성 
  - source = "EC2"
  - type = "인스턴스가 공개 SG에 연결된 상태로 배포됨"
  - sg, arn, resource, account, region, alertType = "ALERT", rulesViolated, severity = "CRITICAL"
- Incident 테이블에 인시던트 레코드 생성 (put_incident_record)
  - incident_id, event_type, resource, severity, status, created_at, updated_at, details 
- payload에 incident_id 추가 후 to_dashboard_event() 호출해 대시보드 이벤트 구조로 변환 
- post_to_ws_dashboard()로 WebSocket 연결된 모든 클라이언트에 브로드캐스트 
  - v2 이벤트 JSON 
  - v1 평탄 JSON (대시보드 구버전 호환용)

### 3.3 새 Access Key 생성 인시던트 (handle_access_key_created)
- source = aws.iam, eventName = CreateAccessKey 인지 확인
- 이벤트에서 새로 생성된 Access Key ID 추출
  - responseElements.accessKey.accessKeyId
- userIdentity에서 사용자 ARN, 타입, Principal ID 추출
- Source IP, User-Agent, 이벤트 시간 추출
- Incident details JSON 구성
  - source = "IAM"
  - type = "새 Access Key 생성"
  - resource = 사용자 ARN, arn = 사용자 ARN, alertType = "ALERT", rulesViolated, severity = "HIGH"
- Incident 테이블에 인시던트 기록 (put_incident_record)
- payload에 incident_id 추가 후 대시보드 이벤트로 변환 & WebSocket 브로드캐스트

### 3.4 공통 유틸/로직
- extract_account_id()
  - 이벤트의 account, detail.userIdentity.accountId, payload의 ARN, 마지막으로 sts:GetCallerIdentity() 순서로 계정 ID 추출 
- normalize_source()
  - signin / sts / cloudtrail / cloudwatch / s3 / ec2 포함 여부로 소스명을 표준화
- _event_time_ms()
  - USE_EVENT_TIME 값에 따라 이벤트 시간 또는 현재 시간(ms) 사용
- _flatten_v1()
  - v2 이벤트 구조를 대시보드 구버전에서 사용하던 v1 평탄 구조로 변환 
  - sg_ids/sg_id를 합쳐 sg 필드로 전달
- post_to_ws_dashboard()
  - WebSocketConnections_v2 테이블에서 모든 connectionId 스캔 
  - API Gateway Management API로 메시지 전송 
  - 연결 끊김(Gone) 시 해당 connectionId를 테이블에서 삭제

---
## 4. 환경 변수 (Environment Variables) 
| Key                   | Value                                                       | 설명                                                      |
| --------------------- |-------------------------------------------------------------| ------------------------------------------------------- |
| `ACCOUNT_ID_OVERRIDE` | `021417007719`                                              | 계정 ID를 강제로 지정할 때 사용. 값이 있으면 이벤트/STS에서 추출하지 않고 이 값을 사용   |
| `COMPAT_TEXT`         | `0`                                                         | WebSocket으로 텍스트 요약 메시지를 보낼지 여부. `1`이면 요약 문자열도 전송        |
| `COMPAT_V1`           | `1`                                                         | v1 평탄(flat) JSON 이벤트를 함께 보낼지 여부. 대시보드 구버전 호환용           |
| `CONNECTIONS_TABLE`   | `WebSocketConnections_v2`                                   | WebSocket 활성 연결 목록을 저장하는 DynamoDB 테이블명                  |
| `INCIDENT_TABLE`      | `Incident`                                                  | 보안 인시던트 이력을 저장하는 DynamoDB 테이블명                          |
| `STATE_PK`            | `id`                                                        | STATE 테이블의 파티션 키 이름. `sg-open#{sg_id}` 형태로 키를 구성        |
| `STATE_TABLE`         | `security-alerts-state-v2`                                  | SG 오픈 마커 등 상관관계용 상태 정보를 저장하는 DynamoDB 테이블명              |
| `USE_EVENT_TIME`      | `0` 또는 `1`                                                  | `1`: 이벤트 시간(`eventTime`) 사용, `0`: Lambda 실행 시점을 시간으로 사용 |
| `WS_ENDPOINT`         | `https://egtwu3mkhb.execute-api.us-east-1.amazonaws.com/prod` | API Gateway WebSocket 엔드포인트 URL (stage 포함)              |

---
## 5. 사용 리소스 및 의존성 (Resources & Dependencies) 
### 5.1. AWS 리소스
- DynamoDB
  - `security-alerts-state-v2` : SG 오픈 마커(state) 저장 
  - `WebSocketConnections_v2` : WebSocket 클라이언트 연결 ID 관리 
  - `Incident` : 보안 인시던트 이력 저장
- API Gateway WebSocket
  - 엔드포인트: `WS_ENDPOINT` 환경변수로 주입 
  - Lambda 함수가 `@connections/*` 엔드포인트로 메시지 전송
- CloudWatch Logs 
  - Lambda 실행 로그 및 디버그 정보 저장 
- STS 
  - sts:GetCallerIdentity 로 계정 ID 확인
- IAM / EC2 / CloudTrail / EventBridge 
  - CloudTrail 관리 이벤트 → EventBridge Rule → Lambda 트리거

### 5.2. 코드/라이브러리 의존성

- Python 표준 라이브러리 
  - os, json, time, random, re 
  - datetime (ISO 시간 파싱 및 타임스탬프 계산)
  - decimal.Decimal (DynamoDB Number 타입 호환)
  - urllib.request (현재 코드에서는 사용 예정 여부에 따라 남겨짐)

- 외부 라이브러리 
  - boto3 
  - botocore.exceptions.ClientError
---
## 6. IAM 권한 (IAM Permissions)
### 6.1 DynamoDB 접근
- STATE / WebSocketConnections 테이블
  - `security-alerts-state-v2`, `WebSocketConnections_v2` 테이블에 대해 다음 작업 허용
  - `PutItem` : SG 오픈 마커 저장, WebSocket 연결 관리
  - `DeleteItem` : 끊어진 WebSocket 연결 삭제
  - `Scan` : 활성 connectionId 전체 조회
  - `DescribeTable`, `GetItem`, `Query` : 상태 조회 및 디버깅/확장 여지를 위해 허용

- Incident 테이블
  - `Incident` 테이블에 대해 다음 작업 허용
    - `PutItem` : 새로운 인시던트 레코드 생성
    - `UpdateItem` : 인시던트 상태/세부 정보 갱신(향후 확장용)

### 6.2 WebSocket 연결 관리
- API Gateway WebSocket 엔드포인트
  - 리소스 : `arn:aws:execute-api:us-east-1:021417007719:egtwu3mkhb/prod/POST/@connections/*`
  - 액션 : `execute-api:ManageConnections` - WebSocket 클라이언트로 데이터 전송 및 연결 종료

### 6.3 STS 계정 정보 조회
- 액션 : `sts:GetCallerIdentity` - Lambda 실행 주체의 AWS Account ID 확인용

### 6.4 CloudWatch Logs (기본 Lambda 실행 역할)
- AWSLambdaBasicExecutionRole 에 포함된 권한
  - `logs:CreateLogGroup`, `logs:CreateLogStream`, `logs:PutLogEvents`
- Lambda 함수의 실행 로그 및 디버그 메시지 기록용

---
## 7. 한계 및 향후 과제 (Limitations & TODO)
| 한계                                                            | 향후 과제                                                                 |
| ------------------------------------------------------------- | --------------------------------------------------------------------- |
| SG 오픈 → 인스턴스 배포 상관관계가 **단일 계정/리전 + 고정 TTL(기본 600초)** 에만 기반    | 여러 리전/멀티 계정 환경에서의 상관관계 지원 및 TTL 동적 조정(이벤트 타입별 다른 TTL)                 |
| 현재 탐지 범위가 **공개 SG 연결 인스턴스 + 새 Access Key 생성**에 한정             | GuardDuty/Config/CloudTrail 다른 고위험 이벤트(권한 상승, 루트 계정 사용 등)로 시나리오 확장    |
| Incident 상태는 생성 시 `NEW`로만 기록되고, **자동/수동 조치에 따른 상태 변경 로직 없음**  | 대시보드/자동대응 Lambda와 연동하여 `PROCESSING / MITIGATED / CLOSED` 상태 변경 플로우 구현 |
| WebSocket 브로드캐스트 시 단순 스캔 + 전송만 수행, **재시도/지수 백오프/배치 전송 전략 부재** | 대량 연결 환경에서도 안정적인 전송을 위해 재시도 로직, 배치 처리, 실패 지표 수집 추가                    |
| 이벤트 필터(`eventName` 리스트)가 코드에 하드코딩 되어 있어 **정책/규칙 변경에 취약**      | DynamoDB/Parameter Store/환경변수 기반의 동적 규칙 관리로 전환                        |
| Incident `details` 구조는 현재 프로젝트 대시보드에 맞춰 고정된 스키마               | 향후 외부 시스템 연동을 위해 스키마 버전 필드 추가 및 스키마 문서화 필요                            |
| `urllib.request` 등 일부 유틸은 현재 코드에서 사용하지 않음                     | 실제 사용하지 않는 의존성 제거, 코드 정리 및 주석 보완                                      |

