# SendS3PublicAlert Lambda Function

## 1. 함수 개요 (Overview)
이 Lambda 함수는 AWS 계정 내 보안 위험도가 높은 S3 퍼블릭 액세스 관련 이벤트, GuardDuty 이벤트, Config Rule 위반을 실시간으로 감지하고 대응합니다.  
- S3 / S3Control 퍼블릭 액세스 변경 → 알림 O  
- GuardDuty 보안 이벤트 → 알림 O  
- Config Rule 위반 → 알림 O  

---

## 2. 동작 조건 & 트리거 (Conditions & Trigger)

### 1. S3 / S3Control 이벤트
- source: `aws.s3` / `aws.s3control`
- eventName: PutBucketAcl, PutObjectAcl, DeleteBucketAcl, PutBucketPolicy, DeleteBucketPolicy, PutPublicAccessBlock, PutAccountPublicAccessBlock, PutBucketWebsite, PutBucketCors, PutBucketOwnershipControls
- 동작: 퍼블릭 액세스 관련 이벤트 감지 → Incident DB 생성 → WebSocket 알림 전송

### 2. GuardDuty 이벤트
- source: `aws.guardduty`
- eventType: GuardDuty Finding
- 동작: Severity 기반 이벤트 처리 → Incident DB 생성 → WebSocket 알림 전송

### 3. Config Rule 위반
- source: `aws.config`
- configRuleName: s3-bucket-public-read-prohibited, s3-bucket-public-write-prohibited
- 동작: NON_COMPLIANT일 경우 → Incident DB 생성 → WebSocket 알림 전송

---

## 3. 처리 로직 (Logic)

### 1. lambda_handler
- 이벤트 source/type 판별 → 알맞은 분석 함수 호출
- alert 객체 생성 → DynamoDB 저장 → Incident DB 저장 → WebSocket 전송

### 2. analyze_s3_event
- CloudTrail 기반 S3 이벤트 분석
- bucketName / objectKey 추출
- Severity 매핑 → alert 생성

### 3. analyze_guardduty_event
- GuardDuty 이벤트 분석
- severity 점수 기반 HIGH/MEDIUM/LOW 지정
- alert 생성

### 4. analyze_config_event
- Config Rule 위반 이벤트 분석
- NON_COMPLIANT 시 alert 생성

### 5. save_alert_to_dynamodb
- ALERT_STATE_TABLE에 alert 상태 저장

### 6. send_incident_to_db
- INCIDENT_TABLE_NAME에 incident 생성 또는 업데이트

### 7. post_to_all_active_connections
- CONNECTIONS_TABLE 스캔 → 모든 WebSocket 연결에 alert 전송
- 끊긴 connection 제거

---

## 4. 환경 변수 (Environment Variables)
| **Key**                   | **Value / Example**                          | **설명**                                            |
| ------------------------- | ------------------------------------------ | ------------------------------------------------- |
| **ALERT_STATE_TABLE**     | security-alerts-state-v2                    | Alert 상태 저장 DynamoDB 테이블                  |
| **CONNECTIONS_TABLE**     | WebSocketConnections_v2                     | WebSocket 연결 관리 테이블                       |
| **INCIDENT_TABLE_NAME**   | Incident                                    | Incident DB 테이블                               |
| **TARGET_REGION**         | us-east-1                                   | Lambda 및 리소스 기본 리전                       |
| **WS_ENDPOINT**           | wss://egtwu3mkhb.execute-api.us-east-1/prod/ | WebSocket 알림 전송 엔드포인트                  |

---

## 5. 사용 리소스 및 의존성 (Resources & Dependencies)

### 1. AWS 리소스
- DynamoDB: ALERT_STATE_TABLE, CONNECTIONS_TABLE, INCIDENT_TABLE_NAME
- API Gateway WebSocket
- CloudTrail, GuardDuty, Config 이벤트
- EventBridge 트리거

### 2. Python 라이브러리
- `boto3`, `botocore`, `json`, `os`, `datetime`, `time`, `random`

---

## 6. IAM 권한 (IAM Permissions)

### 1. CloudWatch Logs
- logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents

### 2. DynamoDB
- ALERT_STATE_TABLE: GetItem, PutItem, UpdateItem, DeleteItem, Scan
- CONNECTIONS_TABLE: GetItem, PutItem, UpdateItem, DeleteItem, Scan
- INCIDENT_TABLE_NAME: PutItem, GetItem, UpdateItem, Query, Scan

### 3. API Gateway WebSocket
- execute-api:ManageConnections
- Resource: `arn:aws:execute-api:us-east-1:*:egtwu3mkhb/prod/POST/@connections/*`

### 4. STS
- sts:GetCallerIdentity (account 정보 fallback용)

---

## 7. 한계 및 향후 과제 (Limitations & TODO)
| 한계 | 향후 과제 |
| ---- | --------- |
| Incident는 단순 “NEW” 저장 | 상태 업데이트 API 구현 (PROCESSING, MITIGATED, CLOSED) |
| 이벤트당 Incident 1건 생성(중복 가능) | 동일 리소스 연속 이벤트 dedup 기능 추가 |
| WebSocket 실패 시 retry 없음 | 재전송 큐 또는 DLQ 적용 |
| 일부 이벤트 필드 누락 시 기본값 사용 | 필드 검증 및 보강 로직 추가 |
| Severity 매핑 고정 | 동적 매핑 및 정책 기반 확장 |

