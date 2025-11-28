## 1. 함수 개요 (Overview)
이 Lambda 함수는 AWS 계정 내 보안 위험도가 높은 2가지 행동을 실시간으로 감지하고 대응하는 역할을 합니다.
- CloudTrail 관리 이벤트 중 중요 서비스에서 중요 API 호출
- 호출이 평소 사용하지 않는 리전(사용자별 베이스라인 밖)인 경우

---
## 2. 동작 조건 & 트리거 (Conditions & Trigger)

### 2.1. EventBridge 관리 이벤트 트리거

- source : `ec2.amazonaws.com`, `s3.amazonaws.com`, `iam.amazonaws.com`, `lambda.amazonaws.com`, `rds.amazonaws.com`, `eks.amazonaws.com`
- detail-type : `AWS API Call via CloudTrail` 
- 동작 
  - 기본적으로 모든 관리 이벤트를 Lambda로 전달 
  - Lambda 내부에서 중요 서비스 & 중요 이벤트 목록 기준으로 1차 필터링 수행

### 2.2. 중요 서비스 + 중요 이벤트 필터링
- 다음 eventName 중 하나가 호출될 때만 “리전 기반 탐지 로직” 실행
  - EC2 : `RunInstances`, `StartInstances`, `StopInstances`, `TerminateInstances`
  - S3 : `CreateBucket`, `PutBucketAcl`, `PutBucketPolicy`, `DeleteBucket`
  - IAM : `CreateAccessKey`, `DeleteAccessKey` / `AttachUserPolicy`, `AttachRolePolicy`, `PutUserPolicy`, `PutRolePolicy`
  - Lambda (2015 API) : `CreateFunction20150331`, `UpdateFunctionConfiguration20150331`, `DeleteFunction20150331`
  - RDS : `CreateDBInstance`, `ModifyDBInstance`, `DeleteDBInstance`

### 2.3. 리전 추출 및 평소 사용 리전(Baseline) 비교
- 이벤트의 `region` 또는 `detail.awsRegion` 값 사용 
- 비교 대상
  - 환경변수 `USUAL_REGIONS`에서 제공한 기본 허용 리전 
  - 사용자별 베이스라인(`security-alerts-state-v2` DynamoDB)
- 조건 : 이벤트 리전이 **허용된 리전 집합에 없을 때만** 이상징후로 판단

### 2.4. LEARNING_MODE 동작

- LEARNING_MODE = true 
  - 처음 보는 리전이면:
    - 해당 리전을 사용자 베이스라인에 자동 추가 
    - LOW 알림 전송
    - Incident 테이블에도 기록

- LEARNING_MODE = false 
  - 베이스라인에 없는 리전이면:
    - SEVERITY_ON_ALERT(HIGH 등) 으로 경보 알림 전송 
    - Incident 테이블에 NEW 상태로 기록

### 2.5. 보안 이벤트 알림 전송 및 Incident 히스토리 기록 조건
- 아래 조건을 모두 충족할 경우 WebSocket 대시보드로 알림 발송
  - 중요 서비스 + 중요 이벤트 
  - 이벤트 리전이 허용 리전 집합에 포함되지 않음
    - `LEARNING_MODE=false` (운영 모드) 또는 `LEARNING_MODE=true`이면서 새로운 리전이 처음 발견됨
- 알림에는 다음 정보 포함
  - 실행 주체 ARN (`arn`)
  - sg 필드에는 ARN tail (`user/tester`)
  - 이벤트 발생 리전
  - 리소스(eventName)
  - 사람 친화적 source (`normalize_source` 적용)

---
## 3. 처리 로직 (Logic) 

### 3.1. EventBridge → Lambda로 CloudTrail 관리 이벤트가 들어옴.

### 3.2. Lambda가 eventSource/eventName을 중요 목록으로 1차 필터링.

### 3.3. 주체(principal) & 리전(region) 추출
- principal = event.detail.userIdentity.arn || principalId
- region = event.region || event.detail.awsRegion

### 3.4. 베이스라인 조회/갱신
- DDB security-alerts-state-v2에서 키 baseline_regions::{principal} 조회 
- USUAL_REGIONS(환경변수 시드)과 합쳐 허용 리전 집합 구성 
- LEARNING_MODE=true이고 미지의 리전이면:
  - 베이스라인에 추가 후 LOW 알림(type="LearnBaselineRegion") 전송 + Incident 기록

### 3.5. 운영 모드 경보
- LEARNING_MODE=false이면서 허용 집합에 없는 리전 → HIGH/MEDIUM/…(환경변수) 알림 전송 
- 알림 페이로드엔 사람이 읽기 쉬운 source 정규화(normalize_source) 적용 
- sg/arn 필드에는 실행 주체의 IAM ARN을 넣어 맥락 강화 
- 동일 내용을 Incident 테이블에도 기록(incident_id 생성)

### 3.6. 전송
- DDB WebSocketConnections_v2를 스캔하며 API Gateway Management API(post_to_connection)로 대시보드 브로드캐스트 
- Gone 커넥션은 테이블에서 정리

---
## 4. 환경 변수 (Environment Variables) 
| Key                   | 예시 값                                                           | 설명                                                     |
| --------------------- | -------------------------------------------------------------- | ------------------------------------------------------ |
| `WS_ENDPOINT`         | `https://egtwu3mkhb.execute-api.us-east-1.amazonaws.com/prod/` | API Gateway **WebSocket** 관리 엔드포인트(https 형식)           |
| `CONNECTIONS_TABLE`   | `WebSocketConnections_v2`                                      | WebSocket 연결 ID를 보관하는 DDB 테이블명                         |
| `STATE_TABLE`         | `security-alerts-state-v2`                                     | 베이스라인(사용자별 허용 리전) 저장 테이블명                              |
| `INCIDENT_TABLE`      | `Incident`                                                     | 알림 히스토리(Incident) 저장 DDB 테이블명                          |
| `USUAL_REGIONS`       | `us-east-1` *(쉼표구분 가능)*                                        | 계정 공통의 “평소 사용하는 리전” 시드 집합                              |
| `LEARNING_MODE`       | `false`                                                        | `true`=새 리전을 **학습**하며 LOW 알림 / `false`=베이스라인 밖은 **경보** |
| `SEVERITY_ON_ALERT`   | `HIGH`                                                         | 운영 모드 경보 심각도(`LOW/MEDIUM/HIGH/CRITICAL`)               |
| `WINDOW_SECONDS`      | `300`                                                          | (예비 값) 창(window) 길이—본 시나리오에선 주 로직에서 직접 사용하진 않음         |
| `ACCOUNT_ID_OVERRIDE` | *(빈 값)*                                                        | 강제 계정 ID 지정 시 사용(테스트/멀티어카운트 시)                         |
| `AWS_REGION`          | *(람다 기본)*                                                      | SDK 기본 리전—WS/DDB 클라이언트 리전 결정에 사용                       |

---
## 5. 사용 리소스 및 의존성 (Resources & Dependencies) 

### 5.1. Amazon CloudTrail: 관리 이벤트 기록

### 5.2. Amazon EventBridge Rule: CloudTrail 관리 이벤트 → Lambda 트리거

### 5.3. AWS Lambda: 본 감지/전송 함수(Python 3.11, 외부 라이브러리 없음 / boto3 내장)

### 5.4. Amazon DynamoDB
- security-alerts-state-v2 : 사용자별 허용 리전 베이스라인 저장(id, regions, updatedAt, expiresAt)
- WebSocketConnections_v2 : { connectionId } 스캔 후 WebSocket 브로드캐스트 
- Incident : 알림 히스토리(incident_id, event_type, resource, severity, status, created_at, updated_at)

### 5.5. Amazon API Gateway (WebSocket): 대시보드로 알림 전송(Management API)

### 5.6. CloudWatch Logs: 함수 로그

---
## 6. IAM 권한 (IAM Permissions)

### 6.1. CloudWatch Logs 권한
- logs:CreateLogGroup
- logs:CreateLogStream
- logs:PutLogEvents
- 목적: 디버깅, 오류 분석, 함수 실행 추적

### 6.2. DynamoDB 권한
- `security-alerts-state-v2`
  - dynamodb:GetItem, PutItem, UpdateItem, DeleteItem, Scan
  - “평소 사용 리전(Baseline Region)” 저장, 사용자별 baseline 조회/추가, TTL 기반 상태 관리

- `WebSocketConnections_v2`
  - dynamodb:GetItem, PutItem, UpdateItem, DeleteItem, Scan**
  - 현재 접속 중인 WebSocket 클라이언트 connectionId 목록 관리, 끊긴 연결 정리(GoneException 처리)

- `Incident`
  - dynamodb:PutItem, GetItem, UpdateItem, Query, Scan**
  - 중요 이벤트 발생 시 Incident 히스토리 생성/조회, NEW → MITIGATED → CLOSED 같은 상태 확장 가능

### 6.3. API Gateway WebSocket 연결 관리 권한
- execute-api:ManageConnections 
- Resource : arn:aws:execute-api:us-east-1:*:egtwu3mkhb/prod/POST/@connections/*
- WebSocket 대시보드에 실시간 이벤트 push, 연결이 죽은 클라이언트 자동 삭제

### 6.4. STS 권한
- sts:GetCallerIdentity
- CloudTrail event 안에 account 정보가 없을 경우 fallback 계정 ID로 사용

---
## 7. 한계 및 향후 과제 (Limitations & TODO)
| 한계                                                       | 향후 과제                                   |
| -------------------------------------------------------- | --------------------------------------- |
| 베이스라인 자동 학습으로 인해 원치 않는 리전이 허용 리스트에 포함될 가능성 있음            | 베이스라인 변경 시 관리자 승인/검토 절차 추가              |
| 중요 서비스·이벤트 목록이 고정이라 신규 AWS 서비스 자동 반영 불가                  | 서비스 API 목록을 자동 갱신하는 메커니즘 추가             |
| ARN이 사용자 단위로만 표기되어 AssumeRole 세션 등 복잡한 identity 흐름 표시 제한 | STS sessionName / role chain 추적 개선      |
| EventBridge·CloudTrail 전달 지연 시 탐지 타이밍에 오차 발생             | 이벤트 지연 보정(Delay Tolerance) 추가 가능        |
| 리전 기반 탐지로 IP 기반 이동 경로(Impossible Travel)처럼 정교한 분석 불가     | IP·Geo 기반 이동 탐지 로직과 결합한 Hybrid 탐지 모델 고려 |
