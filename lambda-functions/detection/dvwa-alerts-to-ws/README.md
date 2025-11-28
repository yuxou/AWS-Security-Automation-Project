## 1. 함수 개요 (Overview)
이 Lambda 함수는 CloudWatch Alarm / IAM 이벤트를 대시보드 WebSocket으로 중계해 주는 역할을 한다. 

- CloudWatch Alarm(State Change) 이벤트 수신 → 대시보드용 JSON 스키마로 변환 → WebSocket으로 실시간 전송
  - (예시) IAM `CreateAccessKey` 이벤트도 동일 방식으로 대시보드에 전송
- DynamoDB(`WebSocketConnections_v2`)에 저장된 connectionId 전체에 메시지 브로드캐스트
- 끊긴 WebSocket 연결은 자동 삭제하여 테이블 정리

---
## 2. 동작 조건 & 트리거 (Conditions & Trigger)
### 2.1.이벤트 소스
  - `source = "aws.cloudwatch"`  
    - `detail-type = "CloudWatch Alarm State Change"`
    - 예: dvwa 외부 스캐너 탐지용 CloudWatch Alarm
  - `source = "aws.iam"`  
    - `detail-type = "AWS API Call via CloudTrail"`
    - `detail.eventName = "CreateAccessKey"` 인 경우만 처리 (예시 핸들러)

### 2.2. EventBridge 규칙
  - 위 조건에 해당하는 이벤트가 발생하면 이 Lambda 함수로 라우팅되도록 EventBridge Rule 이 설정되어 있어야 한다.

### 2.3. WebSocket 연결 선행 조건
  - 사용자가 대시보드 페이지에 접속하면, 별도 WebSocket 핸들러 Lambda가 `WebSocketConnections_v2` 테이블에 `connectionId` 를 저장하고 필수
  - 이 함수는 해당 테이블을 스캔하여 저장된 connectionId 에만 메시지 전송
---
## 3. 처리 로직 (Logic)
### 3.1. 이벤트 유형 판별
- CloudWatch Alarm → `handle_cloudwatch_alarm`
- IAM CreateAccessKey → `handle_access_key_created`
- 그 외 → `noop`

### 3.2. CloudWatch Alarm 처리
- 알람 이름·상태·메트릭 정보 추출
- 계정/리전 정보 파싱
- 대시보드 스키마(JSON)으로 변환
- WebSocket 브로드캐스트

### 3.3. IAM AccessKey 처리(예시)
- AccessKey 생성 이벤트 감지
- 사용자 ARN 등 정보 추출 후 WebSocket 전송

### 3.4. WebSocket 전송
- DynamoDB에서 모든 `connectionId` 조회
- API Gateway WebSocket Management API로 전송
- 끊긴 연결은 DynamoDB에서 삭제하여 정리

### 3.5. 에러 처리
- DynamoDB 스캔 실패, API 호출 실패 시 에러 로그 출력 후 브로드캐스트 루프 종료
- Lambda 전체 에러는 `handler error` 로 로그에 남기고 예외를 다시 던져 CloudWatch Logs에서 확인 가능

---
## 4. 환경 변수 (Environment Variables) 

| Key                      | Value 예시                                                       | 설명                                                                       |
| ------------------------ |----------------------------------------------------------------| -------------------------------------------------------------------------- |
| `CONNECTIONS_TABLE_ACTIONS` | `RemediationWebSocketConnections`                              | 자동대응(Actions)용 WebSocket 연결 테이블 이름**. 이 함수에서는 사용하지 않음(예약). |
| `CONNECTIONS_TABLE_EVENTS` | `WebSocketConnections_v2`                                      | 이벤트 알림용 WebSocket 연결 정보가 저장된 DynamoDB 테이블 이름**. `connectionId` 컬럼 필요. |
| `STATE_TABLE`            | `security-alerts-state-v2`                                     | 보안 알림 상태를 저장하는 테이블 이름. 본 함수에서는 직접 접근하지 않지만, 아키텍처 상 통일을 위해 존재. |
| `WINDOW_SECONDS`         | `30`                                                           | 다른 시나리오(윈도우 기반 집계)에 사용하기 위한 값. 이 함수에서는 사용하지 않음(예약). |
| `WS_ENDPOINT_ACTIONS`    | `https://egtwu3mkhb.execute-api.us-east-1.amazonaws.com/prod/` | 자동대응용 WebSocket API 엔드포인트. 이 함수에서는 사용하지 않음(예약).      |
| `WS_ENDPOINT_EVENTS`     | `https://egtwu3mkhb.execute-api.us-east-1.amazonaws.com/prod/` | 이벤트 알림용 WebSocket API 엔드포인트. 이 함수에서 실제로 사용하는 주요 엔드포인트. |
| `ACCOUNT_ID_OVERRIDE`    | (옵션) `123456789012`                                            | 설정된 경우, 이벤트에서 추출한 계정 대신 항상 이 계정 ID를 사용. (테스트 / 멀티계정 표시용) |
| `AWS_REGION`             | (Lambda 기본) `us-east-1`                                        | Lambda 실행 리전. 명시적으로 지정하지 않으면 기본 환경변수에서 사용됨.          |

---
## 5. 사용 리소스 및 의존성 (Resources & Dependencies) 

### 5.1. AWS 리소스
  - API Gateway WebSocket (Events 채널)
    - 엔드포인트: `WS_ENDPOINT_EVENTS` 환경변수 값  
      (예: `https://{apiId}.execute-api.us-east-1.amazonaws.com/prod/`)
    - 이 Lambda는 `apigatewaymanagementapi.post_to_connection` 으로 메시지를 전송
  - DynamoDB 테이블
    - `WebSocketConnections_v2` (환경변수 `CONNECTIONS_TABLE_EVENTS`)  
      - 파티션 키: `connectionId` (String)  
      - WebSocket 접속 Lambda에서 연결/해제 시 이 테이블 업데이트 필요
  - EventBridge
    - CloudWatch Alarm / IAM 이벤트를 이 Lambda 함수로 전달하는 Rule 구성 필요
  - CloudWatch Logs
    - Lambda 실행 로그 저장 (에러·브로드캐스트 결과 등 확인)
  - (옵션) STS
    - 계정 ID를 추출하기 위해 `sts:GetCallerIdentity` 를 호출  
      (실제로는 ACCOUNT_ID_OVERRIDE 또는 이벤트 본문에서 대부분 해결 가능)

### 5.2. 라이브러리 / 런타임
  - Python 3.x (Lambda 런타임)
  - 표준 라이브러리: `os`, `json`, `time`, `re`, `urllib.request`
  - AWS SDK: `boto3`, `botocore.exceptions.ClientError`(Lambda 기본 제공)
  - 
---
## 6. IAM 권한 (IAM Permissions)
### 6.1. 기본 Lambda 실행 권한
   - CloudWatch Logs에 로그를 남기기 위한 `AWSLambdaBasicExecutionRole`  
     (로그 그룹 및 로그 스트림 생성/쓰기)

### 6.2. DynamoDB 접근 권한
   - `WebSocketConnections_v2` 테이블에서 활성 WebSocket 연결 목록을 조회하기 위한 권한
     - `dynamodb:Scan`  
   - 끊어진 WebSocket 연결을 정리하기 위해 `connectionId` 항목을 삭제하는 권한
     - `dynamodb:DeleteItem`  
   - 리소스 범위:  
     - `arn:aws:dynamodb:us-east-1:*:table/WebSocketConnections_v2`

### 6.3. API Gateway WebSocket 관리 권한
   - WebSocket 연결로 메시지를 전송하고, 연결 상태를 관리하기 위한 권한
     - `execute-api:ManageConnections`
     - (일부 환경에서) `execute-api:Invoke`  
   - 리소스 범위:  
     - `arn:aws:execute-api:us-east-1:*:*/@connections/*`

### 6.4. (옵션) STS 권한
   - `sts:GetCallerIdentity` (계정 ID 추출을 위해 필요할 수 있음)  
   - ACCOUNT_ID_OVERRIDE 또는 이벤트에서 계정 정보를 충분히 얻을 수 있다면 필수는 아님.

---
## 7. 한계 및 향후 과제 (Limitations & TODO)

| 한계                                                                               | 향후 과제                                                                                                  |
|----------------------------------------------------------------------------------| ---------------------------------------------------------------------------------------------------------- |
| 현재는 CloudWatch Alarm State Change 이벤트와 IAM `CreateAccessKey` 이벤트만 처리하도록 구현되어 있음. | GuardDuty, Security Hub, AWS Config 등 다른 보안 이벤트 소스도 공통 스키마로 수용하도록 핸들러 확장.      |
| WebSocketConnections_v2 테이블을 Scan 으로 전체 조회하기 때문에 연결 수가 많아지면 성능/비용 이슈 가능.         | 파티션 설계 개선 또는 `Query` 기반 구조로 변경, Connection 수에 따라 배치/스트림 방식 브로드캐스트 검토. |
| `STATE_TABLE`, `WINDOW_SECONDS`, `*_ACTIONS` 환경변수는 현재 이 함수에서 사용하지 않아 설정 의미가 불분명. | 다른 시나리오(Actions, 윈도우 기반 집계)와 통합 문서화 및 코드 재사용 구조로 리팩터링.                    |
| 알람 `severity` 로직이 단순히 `ALARM → HIGH, 그 외 → LOW` 로만 분기함.                          | 메트릭 이름/Threshold/태그에 따라 `MEDIUM`, `CRITICAL` 등 더 세밀한 severity 매핑 규칙 도입.              |
| 브로드캐스트 실패 시 단순 로그만 남기고, 재시도/Dead Letter Queue(DLQ) 처리 로직은 없음.                    | 실패 이벤트를 SQS/DLQ에 적재하고, 별도 재처리 Lambda를 두어 안정적인 재전송 메커니즘 구현.               |
| WebSocket 엔드포인트와 테이블 이름이 환경변수로만 관리되어, 스테이지/계정이 늘어나면 설정 실수가 발생할 수 있음.             | IaC(CloudFormation/Terraform)로 환경변수와 리소스 이름을 일괄 관리하고, 스테이지별 설정을 명확하게 분리. |
