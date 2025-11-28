# Remediation Lambda Function

## 1. 함수 개요 (Overview)
이 Lambda 함수는 S3 퍼블릭 정책을 자동으로 탐지하고 제거(Remediation)하며,  
실시간 WebSocket 알림과 DynamoDB 인시던트 기록을 관리합니다.

- 퍼블릭 S3 정책 감지 → Incident DB 기록 → WebSocket 알림  
- 정책 제거 성공/실패 여부 WebSocket 전송 → 상태 업데이트  

---

## 2. 동작 조건 & 트리거 (Conditions & Trigger)

### 1. S3 버킷 정책 이벤트
- EventBridge / CloudTrail에서 S3 버킷 관련 이벤트 수신  
- event source: `aws.s3`  
- 조건: 버킷 정책 변경 시 이벤트 수신 (`requestParameters.bucketName` 존재)  
- 동작:
  1. Incident DB에 "PROCESSING" 상태 기록
  2. WebSocket에 "TRIGGERED" 상태 전송
  3. 퍼블릭 정책 여부 판단
  4. 퍼블릭 정책이면 삭제 수행
  5. 삭제 완료 후 Incident DB 상태 업데이트
  6. WebSocket에 최종 상태 (`MITIGATED` / `FAILED` / `Not public`) 전송

---

## 3. 처리 로직 (Logic)

### 1. lambda_handler
- 이벤트 수신 → bucketName 추출 → S3 클라이언트 초기화
- Incident 생성 → WebSocket "TRIGGERED" 전송
- 정책 조회 → 퍼블릭 여부 판단 → 필요 시 삭제 수행
- Incident 상태 업데이트 → WebSocket 최종 상태 전송

### 2. save_incident
- INCIDENT_TABLE에 인시던트 생성
- incident_id 자동 생성, 생성/갱신 시간 기록

### 3. update_incident_status
- Incident 상태 업데이트 (PROCESSING, MITIGATED, FAILED)
- 선택적 노트(note) 기록 가능

### 4. is_public_policy
- 정책의 Statement 검토 → 퍼블릭 액세스 여부 판단
- 위험 액션: s3:GetObject, s3:ListBucket, s3:*

### 5. delete_bucket_policy
- S3 클라이언트로 버킷 정책 삭제
- 성공 시 `True`, 실패 시 `False` 반환

### 6. post_remediation_status
- REMEDIATION_CONNECTIONS_TABLE의 모든 WebSocket 연결에 상태 전송
- 끊긴 connection 제거

### 7. generate_remediation_json
- WebSocket 전송용 JSON 생성
- 필드: time, action, target, playbook, status

---

## 4. 환경 변수 (Environment Variables)
| **Key**                        | **Value / Example**                          | **설명**                                            |
| ------------------------------- | ------------------------------------------ | ------------------------------------------------- |
| **REMEDIATION_WS_ENDPOINT**     | wss://xxx.execute-api.us-east-1/prod/       | WebSocket 알림 엔드포인트                         |
| **REGION_WS**                   | us-east-1                                   | WebSocket API Gateway 리전                        |
| **AWS_REGION**                  | us-east-1                                   | Lambda 실행 및 S3 리전 기본값                     |
| **REMEDIATION_CONNECTIONS_TABLE** | RemediationWebSocketConnections           | WebSocket 연결 관리 테이블                        |
| **INCIDENT_TABLE_NAME**         | Incidents                                   | 인시던트 DB 테이블                                 |

---

## 5. 사용 리소스 및 의존성 (Resources & Dependencies)

### 1. AWS 리소스
- DynamoDB: INCIDENT_TABLE, REMEDIATION_CONNECTIONS_TABLE
- API Gateway WebSocket
- S3

### 2. Python 라이브러리
- boto3, botocore.exceptions, json, os, datetime, time, random

---

## 6. IAM 권한 (IAM Permissions)

### 1. DynamoDB
- INCIDENT_TABLE: PutItem, UpdateItem
- REMEDIATION_CONNECTIONS_TABLE: GetItem, Scan, DeleteItem

### 2. S3
- s3:GetBucketPolicy, s3:DeleteBucketPolicy

### 3. API Gateway WebSocket
- execute-api:ManageConnections
- Resource: `arn:aws:execute-api:REGION:*:*/POST/@connections/*`

### 4. CloudWatch Logs
- logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents

---

## 7. 한계 및 향후 과제 (Limitations & TODO)
| 한계 | 향후 과제 |
| ---- | --------- |
| 퍼블릭 정책 감지만 수행 후 삭제 | 정책 삭제 정책 강화 / 승인 프로세스 추가 |
| WebSocket 실패 시 retry 없음 | 재전송 큐 또는 DLQ 고려 |
| Incident 단순 상태 기록 | Incident 상세 로그/이력 관리 개선 |
| S3 정책 판단 고정 | 세밀한 위험도 평가 (읽기/쓰기 구분) |
| Lambda 단일 버킷 처리 | 병렬 처리 또는 배치 처리 개선 |

