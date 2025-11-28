## 1. 함수 개요 (Overview)
이 Lambda 함수는 AWS Config에서 보안 그룹이 “세상에 공개(0.0.0.0/0)” 된 상태로 평가될 때
대시보드(WebSocket)와 Incident 테이블로 알림/이력을 보내는 역할을 한다.

- AWS Config 규칙(예: restricted-ssh, SG_OPEN_TO_WORLD 등)의 규정 위반(NON_COMPLIANT) 이벤트 수신
- 해당 보안 그룹 ID / ARN / 계정 / 리전 정보를 추출해 실시간 대시보드 WebSocket으로 알림 전송 
- 같은 내용을 DynamoDB Incident 테이블에 인시던트 이력으로 저장

CloudWatch Logs 에 내부 디버깅/상태 로그 남김
---
## 2. 동작 조건 & 트리거 (Conditions & Trigger)
| 항목                              | 내용                                                                                                           |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| 이벤트 소스 (`source`)               | `aws.config` (실운영), `my.test.config` (CloudShell 테스트용)                                                       |
| 이벤트 타입 (`detail-type`)          | `Config Rules Compliance Change`                                                                             |
| Config 규칙 이름 (`configRuleName`) | `SG_OPEN_TO_WORLD`, `SecurityGroupOpenToWorld`, `security-group-open-to-world`, `restricted-ssh` 중 하나일 때만 처리 |
| 컴플라이언스 상태                       | `newEvaluationResult.complianceType == "NON_COMPLIANT"` 인 경우에만 알림 생성                                         |
| 트리거                             | 위 조건에 맞는 이벤트가 **EventBridge 규칙**을 통해 Lambda로 전달될 때 실행                                                        |

---
## 3. 처리 로직 (Logic) 
### 3.1. 이벤트 수신 & 필터링
- `event["source"]` 가 `aws.config` 또는 `my.test.config`인지 확인
- `detail-type` 이 `Config Rules Compliance Change` 인지 확인
- `detail.configRuleName` 가 허용된 규칙 목록에 포함되는지 확인
- `detail.newEvaluationResult.complianceType` 가 `NON_COMPLIANT` 이 아니면 종료
### 3.2. 보안 그룹 및 메타데이터 추출
- `detail.resourceId` 또는 `detail.newEvaluationResult.evaluationResultIdentifier.evaluationResultQualifier.resourceId` 에서 보안 그룹 ID(sg-...) 추출 
- 이벤트에서 리전(region), 계정 ID(account) 추출
- `arn:aws:ec2:{region}:{account}:security-group/{sgid}` 형태로 SG ARN 생성

### 3.3. 대시보드용 페이로드 구성
- 공통 스키마에 맞춰 평면 JSON 생성
  - `time` : 현재 시각(epoch millis)
  - `source` : `normalize_source()` 로 사람이 보기 좋은 이름으로 변환 (예: aws.config → Aws.config → 규칙에 따라 문자열 가공)
  - `type` : `"SG_OpenToWorld 위반 감지"`
  - `resource` / sg : 보안 그룹 ID
  - `arn` : 보안 그룹 ARN
  - `account`, `region`
    - `severity` : 환경변수 SEVERITY_ON_ALERT 값 (예: HIGH)

### 3.4. Incident 이력 저장
- put_incident_record() 호출
  - Incident ID 생성(예: inc-20251120-143000-123)
  - DynamoDB Incident 테이블에 아래 필드 저장 `incident_id`, `event_type`, `resource`, `severity`, `status("NEW")`, `created_at`, `updated_at`, `details(JSON)`
- 성공 시, 반환된 `incident_id` 를 대시보드 페이로드에도 추가

### 3.5. WebSocket 브로드캐스트
- `CONNECTIONS_TABLE` (예: `WebSocketConnections_v2`) 를 스캔해서 모든 `connectionId` 조회
- API Gateway Management API(`execute-api:ManageConnections`) 로 각 커넥션에 JSON 페이로드 전송
- 끊어진 커넥션(GoneException) 은 DynamoDB에서 삭제
- 전송 성공/실패/삭제 개수 로그 출력

### 3.6. 결과 반환
- 최종적으로 `{"status": "alert_sent", "rule": "...", "sg": "..."}` 형태의 JSON을 로그에 남기고 종료

---
## 4. 환경 변수 (Environment Variables) 
| Key                 | Value                                                          | 설명                                                                             |
| ------------------- | -------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| `CONNECTIONS_TABLE` | `WebSocketConnections_v2`                                      | 대시보드 WebSocket 클라이언트 목록을 저장하는 DynamoDB 테이블 이름 (`connectionId` 키)               |
| `INCIDENT_TABLE`    | `Incident`                                                     | 인시던트 이력을 저장하는 DynamoDB 테이블 이름 (`incident_id` 파티션 키)                            |
| `SEVERITY_ON_ALERT` | `HIGH`                                                         | 이 Lambda에서 발생시키는 알림의 기본 심각도 (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL` 중 하나)         |
| `STATE_TABLE`       | `security-alerts-state-v2`                                     | 기타 상태/카운터 저장용 DynamoDB 테이블. (이 함수에서는 주로 Incident 로직만 사용하지만, 공통 유틸과의 호환을 위해 유지) |
| `WS_ENDPOINT`       | `https://egtwu3mkhb.execute-api.us-east-1.amazonaws.com/prod/` | API Gateway WebSocket Management API 엔드포인트(URL). 이 주소로 알림을 전송하여 대시보드에 실시간 표시   |

---
## 5. 사용 리소스 및 의존성 (Resources & Dependencies) 
### 5.1. AWS Config
- 보안 그룹 오픈을 감시하는 규칙
  - 예: restricted-ssh, SG_OPEN_TO_WORLD, SecurityGroupOpenToWorld 등
- 규칙의 Compliance 상태가 NON_COMPLIANT 로 변할 때 EventBridge로 이벤트 전달

### 5.2. Amazon EventBridge
- 이벤트 패턴
  - `source`: `aws.config`
  - `detail-type`: `Config Rules Compliance Change`
  - `detail.configRuleName`: 위 규칙 이름들 중 하나
- 타겟: 본 Lambda 함수

### 5.3. AWS Lambda
- 이 README가 설명하는 함수
- Python 런타임(3.13) + 기본 `boto3`, `botocore`, `json`, `time`, `re` 등 표준 라이브러리 사용

### 5.4. Amazon DynamoDB
- `WebSocketConnections_v2`
  - 연결된 WebSocket 클라이언트들의 `connectionId` 를 저장
- `Incident`
  - 인시던트 상세 기록 저장
  - 스키마 예: `incident_id` (PK), `event_type`, `resource`, `severity`, `status`, `created_at`, `updated_at`, `details`

### 5.5. Amazon API Gateway (WebSocket)
- 대시보드와 연결된 `WebSocket API`
- `WS_ENDPOINT` 로 지정된 URL을 통해 Management API 호출 (`@connections/{connectionId}` 로 메시지 전송)

### 5.6. Amazon CloudWatch Logs
- Lambda 실행 로그, 디버그 정보, WS 전송 결과 로그 저장

---
## 6. IAM 권한 (IAM Permissions)
### 6.1. WebSocket 관리용 DynamoDB 접근
- `WebSocketConnections_v2` 테이블에 대해:
  - `dynamodb:Scan` : 모든 connectionId 조회
  - `dynamodb:DeleteItem` : 끊어진 WebSocket 커넥션 정리

### 6.2. WebSocket 연결 관리 (API Gateway Management API)
- 리소스: arn:aws:execute-api:us-east-1:021417007719:*/prod/POST/@connections/*
- 권한 - execute-api:ManageConnections : 특정 connectionId 로 메시지 전송 및 정리

### 6.3. 로그 기록 (기본 실행 역할 포함)
- 리소스: *
- 권한
  - `logs:CreateLogGroup` 
  - `logs:CreateLogStream` 
  - `logs:PutLogEvents`

### 6.4. Incident 테이블 쓰기 권한
- 리소스: arn:aws:dynamodb:us-east-1:021417007719:table/Incident
- 권한:
  - dynamodb:PutItem : 인시던트 신규 생성 
  - dynamodb:UpdateItem : 인시던트 상태/내용 업데이트(필요 시 확장 가능)

---
## 7. 한계 및 향후 과제 (Limitations & TODO)
| 한계                                                                                                     | 향후 과제                                                                                               |
| ------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------- |
| 현재는 **SSH(22/TCP) + 0.0.0.0/0, ::/0** 만 감지하며, 다른 포트(3389/RDP 등)나 넓은 CIDR(예: /8, /16)은 탐지하지 않음          | 감지 대상을 포트/프로토콜/네트워크 대역별로 설정 가능하게 확장 (예: 환경변수로 포트 리스트, 허용 CIDR 범위 지정)                                |
| 카운트 기준이 **행위자 ARN 단위**라서, 여러 사용자가 같은 계정에서 조금씩 나눠서 오픈하는 경우는 임계치에 도달하지 않을 수 있음                           | 계정 전체 기준, IAM Role 기준 등 다양한 집계 단위를 지원하고, 대시보드에서 필터링 가능하도록 메타데이터 확장                                  |
| TTL 기반 윈도우(슬라이딩 방식)에 의존하기 때문에, 테이블 파티션 키(`STATE_PK`)에 이벤트가 많이 몰릴 경우 DynamoDB 핫 파티션 가능성 존재              | 파티션 설계를 개선하고, CloudWatch 지표 기반으로 읽기/쓰기 용량 및 파티션 키 설계 튜닝                                             |
| WebSocket 대시보드에 의존하므로, 대시보드가 연결되어 있지 않거나 WebSocket 에러가 발생하면 알림이 사용자에게 보이지 않을 수 있음                      | SNS, 이메일, Slack Webhook 등 다른 채널과 연동하여 **다중 채널 알림** 지원. HTTP 폴백 엔드포인트 고도화                            |
| RunInstances / ModifyInstanceAttribute 보조 로직은 인스턴스와 SG 매칭만 수행하며, 실제로 트래픽이 발생했는지(실제 SSH 접속 시도)는 확인하지 않음 | VPC Flow Logs, GuardDuty, CloudWatch Metric Filter 등과 연계하여 “실제 접속 시도 + 월드 오픈”을 함께 볼 수 있는 상관분석 로직 추가 |
| 현재 Access Key 생성 이벤트에 대해서는 단순 발생 알림만 제공하며, 키 회전 정책, MFA 여부 등은 고려하지 않음                                  | IAM 보안 베스트 프랙티스(키 회전 주기, 루트 계정 사용 여부, MFA 활성화 여부 등)를 함께 점검하여 보안 점수 형태로 대시보드에 추가 표시                  |
