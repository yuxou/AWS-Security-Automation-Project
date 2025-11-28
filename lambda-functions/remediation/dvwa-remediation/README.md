## 1. 함수 개요 (Overview)
이 Lambda 함수는 DVWA 대상 외부 취약점 스캐너 탐지 시 자동 대응(격리) 작업을 수행하고, 그 결과를 WebSocket 대시보드(Actions 채널)로 전송하는 역할을 한다.
- CloudWatch Alarm(State = `ALARM`) 이벤트 수신
- DVWA 인스턴스를 격리용 보안 그룹(SG)으로 교체하여 외부 접속 차단
- 원본 이벤트를 S3에 아카이브
- 자동대응 결과를 WebSocket(자동대응 로그 영역)으로 브로드캐스트

---

## 2. 동작 조건 & 트리거 (Conditions & Trigger)
### 2.1. 이벤트 소스 및 타입
- `source = "aws.cloudwatch"`
- `detail-type = "CloudWatch Alarm State Change"`
- `detail.state.value = "ALARM"` 인 경우에만 자동대응 수행

### 2.2. 트리거
- 위 조건을 만족하는 CloudWatch Alarm 이벤트를 이 Lambda 로 전달하는 EventBridge Rule 이 설정되어 있어야 한다.
- 예: DVWA 대상 스캐너 탐지용 메트릭(`dvwa-scanner-detect-20251107` 등)에 대한 CloudWatch Alarm

### 2.3. 전제 조건
- `DVWA_INSTANCE_ID` 환경변수에 지정된 EC2 인스턴스가 존재해야 함
- `QUARANTINE_SG_ID` 환경변수에 지정된 격리용 SG가 사전에 생성되어 있어야 함
- Actions WebSocket 연결 시 `RemediationWebSocketConnections`(또는 v2 테이블)에 `connectionId`가 저장되고 있어야 함

---

## 3. 처리 로직 (Logic) 
### 3.1. **이벤트 확인**
- `source` / `detail-type` / `state.value`가 조건에 맞지 않으면 `skip` 리턴
- `state.value == "ALARM"` 일 때만 이후 단계 진행

### 3.3. S3 아카이브**
- 수신한 이벤트 전체(JSON)를 `ARCHIVE_BUCKET` 아래 `scanner/{timestamp}-{uuid}.json` 형식의 키로 저장
- 버킷 미설정 시 아카이브는 생략하고 경고 로그만 남김

### 3.3. DVWA 인스턴스 격리
- `DVWA_INSTANCE_ID` 로 EC2 인스턴스 조회
- 첫 번째 네트워크 인터페이스의 `NetworkInterfaceId` 추출
- 해당 ENI 의 보안 그룹 목록을 `QUARANTINE_SG_ID` 하나로 교체
  → 결과적으로 외부에서 DVWA 로의 HTTP 접근이 차단됨

### 3.4. HTTP 차단 상태 기록
- 현재 구조에서는 “격리 SG 한 개만 부여” 자체가 HTTP 차단 역할을 하기 때문에 별도의 Ingress 변경 없이 상태만 로그에 기록

### 3.5. Actions WebSocket 알림 전송
- Alarm ARN/Region/Account 정보를 정리해 짧은 ARN(`...:alarm`)과 풀 ARN 생성
- 자동대응 결과(아카이브 정보, 격리 결과, 상태)를 포함한 페이로드 생성
- `CONNECTIONS_TABLE_ACTIONS`(예: `RemediationWebSocketConnections`) 을 Scan 해 모든 `connectionId` 조회
- API Gateway Management API(`WS_ENDPOINT_ACTIONS`) 로 모든 Actions 채널 연결에 브로드캐스트
- 끊어진 연결(GoneException)은 테이블에서 삭제

---
## 4. 환경 변수 (Environment Variables) 

| Key                       | 예시 값                                                    | 설명                                                                                     |
| ------------------------- | --------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `ARCHIVE_BUCKET`         | `layer3-dvwa-scanner-archive`                             | 스캐너 탐지 이벤트 원문을 저장할 S3 버킷 이름. `scanner/{timestamp}-{uuid}.json` 로 저장 |
| `CONNECTIONS_TABLE_ACTIONS` | `RemediationWebSocketConnections`                         | **자동대응(Actions)용 WebSocket 연결 정보가 저장된 DynamoDB 테이블 이름**               |
| `DVWA_INSTANCE_ID`       | `i-0878037a43d4895d0`                                     | 격리 대상 DVWA EC2 인스턴스 ID                                                           |
| `QUARANTINE_SG_ID`       | `sg-08af46f4a407ece7b`                                    | 격리 시 적용할 **격리용 보안 그룹 ID**                                                   |
| `REGION`                 | `us-east-1`                                               | 기본 AWS 리전. 설정 없을 경우 `AWS_REGION` 또는 `us-east-1` 사용                        |
| `STATE_TABLE`            | `security-alerts-state-v2`                                | 보안 알림 상태 저장용 DynamoDB 테이블 이름. **현재 이 함수 코드에서는 직접 사용하지 않음** |
| `WS_ENDPOINT_ACTIONS`    | `https://3y9ayspfp3.execute-api.us-east-1.amazonaws.com/prod/` | Actions WebSocket API Gateway 엔드포인트 URL (stage 포함, 끝에 `/` 포함 권장)           |

---
## 5. 사용 리소스 및 의존성 (Resources & Dependencies) 

### 5.1. AWS 리소스
- Amazon EC2
  - `DVWA_INSTANCE_ID` 로 지정된 인스턴스 조회 및 네트워크 인터페이스 수정
  - `QUARANTINE_SG_ID` 를 ENI 에 적용하여 격리
- Amazon S3
  - `ARCHIVE_BUCKET` 에 이벤트 원문(JSON) 객체 저장
- Amazon DynamoDB
  - `CONNECTIONS_TABLE_ACTIONS` (예: `RemediationWebSocketConnections_v2`)  
    - 파티션 키: `connectionId`  
    - WebSocket 연결/해제 Lambda 가 관리하는 테이블
- Amazon API Gateway (WebSocket)
  - `WS_ENDPOINT_ACTIONS` 로 접근하는 WebSocket Management API  
    - `post_to_connection` 호출로 Actions 채널 클라이언트에 메시지 전송
- Amazon EventBridge
  - CloudWatch Alarm State Change 이벤트를 이 Lambda 로 라우팅하는 Rule
- Amazon CloudWatch Logs
  - Lambda 실행 및 자동대응 결과 로그 기록

### 5.2. 런타임 및 라이브러리
  - Python 3.x (Lambda 런타임)
  - 표준 라이브러리: `os`, `json`, `time`, `uuid`, `re`
  - AWS SDK: `boto3`, `botocore.exceptions`

---
## 6. IAM 권한 (IAM Permissions)
### 6.1. EC2 / S3 / WAF / CloudWatch Logs 관련 관리형 정책
- `AWSWAFConsoleFullAccess`  
  - 현재 코드에서는 직접 WAF API를 호출하지 않지만, 향후 WAF 기반 자동대응 확장을 위해 부여
- `CloudWatchLogsReadOnlyAccess`  
  - CloudWatch Logs 조회용. (실제로는 Lambda 실행 로그 작성을 위해 `AWSLambdaBasicExecutionRole` 도 함께 필요)

### 6.2. DynamoDB & WebSocket 전송용 커스텀 정책
- DynamoDB (`RemediationWebSocketConnections_v2`)
  - `dynamodb:Scan`, `dynamodb:DeleteItem`  
  - 리소스: `arn:aws:dynamodb:us-east-1:021417007719:table/RemediationWebSocketConnections_v2`  
    → Actions WebSocket 연결 목록 조회 및 끊어진 연결 삭제 용도
- API Gateway WebSocket Management API
  - `execute-api:ManageConnections`  
  - 리소스: `arn:aws:execute-api:us-east-1:021417007719:egtwu3mkhb/prod/POST/@connections/*`  
    → WebSocket 클라이언트로 메시지 전송 및 연결 관리

### 6.3. 기본 Lambda 실행 역할
- CloudWatch Logs 로그 생성을 위한 `AWSLambdaBasicExecutionRole` (또는 동등한 권한) 필요

---
## 7. 한계 및 향후 과제 (Limitations & TODO)

| 한계                                                                                             | 향후 과제                                                                                                     |
| ------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------- |
| CloudWatch Alarm 이 `ALARM` 상태일 때에만 동작하며, 다른 보안 이벤트(GuardDuty, Security Hub 등)는 처리하지 않음 | GuardDuty / Security Hub / AWS Config 등 다양한 탐지 소스와 연동하여 자동대응 범위 확장                      |
| EC2/S3 에 **FullAccess 관리형 정책**을 사용하여 최소 권한 원칙(Least Privilege)에 부합하지 않음     | 실제 사용 API만 포함하는 커스텀 IAM 정책으로 교체하여 권한을 최소화                                         |
| DynamoDB 테이블을 **Scan** 으로 전체 조회하므로 WebSocket 연결 수가 많아질수록 비용·지연이 증가할 수 있음 | 파티션키 설계 개선, `Query` 기반 조회 또는 Connection 수가 많을 때는 배치/스트림 기반 브로드캐스트 구조 도입 |
| STATE_TABLE 환경변수는 정의되어 있으나 이 함수에서는 사용하지 않아 상태 관리 기능이 부족함         | remediation 상태(성공/실패, 재시도 정보 등)를 STATE_TABLE 에 기록하는 로직 추가                              |
| 실패한 WebSocket 전송, EC2/ S3 작업에 대한 재시도/보상 처리 로직이 단순 로그 출력에 그침          | Dead Letter Queue(SQS) 및 재처리 Lambda를 도입해 안정적인 실패 처리 및 모니터링 강화                        |
| 현재는 단일 인스턴스(DVWA)와 단일 격리 SG 만 고려하고 있어 멀티 인스턴스/멀티 테넌트 환경 대응이 어려움 | 인스턴스·알람 매핑 정보를 DynamoDB 등에 정의하여 리소스별로 다른 격리 정책을 적용할 수 있도록 구조 확장      |
