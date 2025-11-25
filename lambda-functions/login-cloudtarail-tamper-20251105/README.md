## 1. 함수 개요 (Overview)

이 Lambda 함수는 AWS 계정 내 보안 위험도가 높은 2가지 행동을 실시간으로 감지하고 대응하는 역할을 합니다.
- IAM Access Key 생성 이벤트 감지 → 알림X
- 로그인 직후 CloudTrail 설정 변경 시도 감지 → 알림O
---
## 2. 동작 조건 & 트리거 (Conditions & Trigger)

### 1. Console Login 성공 이벤트 
   - source: aws.signin 
   - detail-type: AWS Console Sign In via CloudTrail 
   - 조건: ConsoleLogin = "Success"
   - 동작: 로그인 상태 저장만 수행 (알림 X)
### 2. STS AssumeRole 성공 이벤트
   - source: aws.sts 
   - detail-type: AWS API Call via CloudTrail 
   - eventName: AssumeRole 
   - 동작: 로그인 이벤트로 간주 → 로그인 상태 저장 (알림 X)
### 3. CloudTrail Tamper 시도 
   - 다음 API 호출 감지 시 “CloudTrail 변경 시도”로 판단:StopLogging, DeleteTrail, UpdateTrail, PutEventSelectors, UpdateTrailStatus, CreateTrail 
   - 조건 만족 시
     - Incident 테이블에 “NEW” 상태로 히스토리 저장 
     - WebSocket 대시보드에 실시간 보안 이벤트 알림 전송 
   - “로그인 직후 tamper 시도인지” 판단하기 위해 STATE_TABLE 의 recent login 기록 사용
---
## 3. 처리 로직 (Logic)

### 1. 로그인 성공 처리 (handle_login_success)
   - ARN / PrincipalId 기준으로 로그인 시간 저장 
   - WebSocket 알림은 보내지 않음 → 다른 알림과 충돌 방지 목적
### 2. CloudTrail Tamper 처리 (handle_cloudtrail_tamper)
   - 최근 로그인 시각 비교 (예: 60초 이내)
   - Incident 테이블에 레코드 생성 
     - incident_id 자동 생성 
     - 상태는 "NEW"
   - 대시보드 알림 JSON 생성 및 WebSocket 전송
### 3. Access Key 생성 처리 (handle_access_key_created)
   - 최근 리전 활동 여부 확인 
     - 최근 7일 이내 기록 있음 → 알림 스킵 
     - 없으면 히스토리 생성 + 대시보드 전송 
   - Incident 테이블 기록 생성 
   - WebSocket 대시보드 알림 전송
### 4. Incident 기록 전송 (put_incident_record)

---
## 4. 환경 변수 (Environment Variables) 
| **Key**                   | **Value**                          | **설명**                                            |
| ------------------------- | ---------------------------------- | ------------------------------------------------- |
| **CONNECTIONS_TABLE**     | WebSocketConnections_v2            | 실시간 알림을 전송할 WebSocket 연결 목록을 저장하는 DynamoDB 테이블    |
| **INCIDENT_TABLE**        | Incident                           | 새로 생성한 보안 인시던트(Incident) 히스토리 기록용 테이블             |
| **REGION**                | us-east-1                          | 기본 리전(없어도 자동 추출되지만 명시하면 안정적)                      |
| **REGION_WINDOW_SECOND**  | 604800                             | AccessKeyCreated 이벤트의 “최근 리전 사용 여부” 판단 기준(7일)     |
| **STATE_PK_NAME**         | connectionId                       | security-alerts-state 테이블의 PK 이름                  |
| **STATE_TABLE**           | security-alerts-state              | 로그인 기록 및 리전 활동 기록 저장용 DynamoDB 테이블                |
| **TAMPER_WINDOW_SECONDS** | 60                                 | CloudTrail Tamper 감지 시 "얼마나 최근 로그인했는가" 판단하는 시간(초) |
| **WS_ENDPOINT**           | wss://…(API Gateway WebSocket URL) | 대시보드가 실시간 알림을 받는 WebSocket 엔드포인트                  |

---
## 5. 사용 리소스 및 의존성 (Resources & Dependencies)

### 1. AWS 리소스
- DynamoDB
- security-alerts-state 
  - WebSocketConnections 
  - Incident 
  - API Gateway WebSocket 
  - CloudTrail 
  - STS / IAM 이벤트 
  - EventBridge 트리거

### 2. Python 라이브러리
- boto3 
- botocore 
- urllib (GeoIP)
- random, re, json

---
## 6. IAM 권한 (IAM Permissions)

### 1. CloudWatch Logs 권한

- logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents 
- Lambda 디버깅 / 오류 분석 / 실행 로그 기록

### 2. DynamoDB 권한

#### 2.1 security-alerts-state
- dynamodb:GetItem, dynamodb:PutItem, dynamodb:UpdateItem, dynamodb:DeleteItem, dynamodb:Scan
- 로그인 기록·지역 사용 기록을 저장하고 읽기 위해 필요

#### 2.2 WebSocketConnections_v2
- dynamodb:GetItem, dynamodb:PutItem, dynamodb:UpdateItem, dynamodb:DeleteItem, dynamodb:Scan
- 현재 접속 중인 WebSocket 클라이언트 목록 관리

#### 2.3 Incident
- dynamodb:PutItem, dynamodb:GetItem, dynamodb:UpdateItem, dynamodb:Query, dynamodb:Scan
- 인시던트 히스토리(Incident DB)에 저장/조회

### 3. API Gateway WebSocket 연결 관리 권한
- execute-api:ManageConnections 
- Resource : arn:aws:execute-api:us-east-1:*:egtwu3mkhb/prod/POST/@connections/*
- WebSocket 클라이언트에 실시간 이벤트 전송, 끊긴 connection 정리

### 4. sts 권한
- sts:GetCallerIdentity 
- 이벤트에 account 정보가 없을 경우 AWS 계정 ID fallback 추출
---
## 7. 한계 및 향후 과제 (Limitations & TODO)
| 한계                               | 향후 과제                                       |
| -------------------------------- |---------------------------------------------|
| Incident는 단순 “NEW” 저장만 됨         | “PROCESSING, MITIGATED, CLOSED” 업데이트 API 필요 |
| 이벤트당 Incident 1건 생성(중복 가능)       | 동일 리소스 연속 이벤트 dedup 기능 추가 가능                |
| CloudTrail Tamper만 로그인 윈도우 기반 판단 | AccessKey 생성에도 로그인 기반 위험도 부여 가능             |
| WebSocket 장애 시 retry 없음          | 재전송 큐 또는 DLQ 고려                             |
| 리전 최근 활동 로직 시간이 고정적              | 사용자별 커스텀 window 적용 가능                       |



