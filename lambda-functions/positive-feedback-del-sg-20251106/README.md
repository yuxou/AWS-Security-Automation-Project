## 1. 함수 개요 (Overview)

이 Lambda 함수는 보안그룹 관련 “위험 해소(Positive Feedback)” 이벤트를 감지해서 대시보드와 Incident 히스토리에 기록하는 역할을 한다.
- CloudTrail 이벤트에서  
  - `RevokeSecurityGroupIngress` 로 SSH 22번 포트(0.0.0.0/0) 규칙이 제거된 경우  
  - `DeleteSecurityGroup` 으로 위험했던 SG 자체가 삭제된 경우  
  → “위험 해소” 이벤트로 인식하여 대시보드/Incident로 전송
- AWS Config 이벤트에서
  - `SG_OPEN_TO_WORLD` 계열 규칙이 NON_COMPLIANT → COMPLIANT 로 바뀐 경우  
  → “규정 준수로 위험 해소” 인시던트로 기록
- 동시에 DynamoDB Incident 테이블에 인시던트 히스토리 1건 저장
- 감지된 이벤트를 WebSocket API → 대시보드로 실시간 브로드캐스트


---
## 2. 동작 조건 & 트리거 (Conditions & Trigger)

| 구분 | 로그 소스 / 서비스 | EventBridge 매칭 조건(요약) | 의미 |
|------|--------------------|-----------------------------|------|
| EC2 – Revoke | CloudTrail 관리 이벤트 (`source=aws.ec2`, `detail-type=AWS API Call via CloudTrail`) | `eventName = RevokeSecurityGroupIngress` 이고, `ipPermissions` 안에 `tcp / 22-22 / 0.0.0.0/0` 규칙이 포함된 경우 | SSH 22번을 0.0.0.0/0 으로 열었던 **World Open 규칙이 제거**됨 |
| EC2 – Delete SG | CloudTrail 관리 이벤트 (`source=aws.ec2`) | `eventName = DeleteSecurityGroup` | 위험 SG 자체가 삭제됨 (정보성 Positive 이벤트) |
| Config – Compliance | AWS Config 규칙 컴플라이언스 변경 (`source=aws.config`, detail-type에 `"Compliance Change"` 포함) | `configRuleName` 이 `SG_OPEN_TO_WORLD`, `SecurityGroupOpenToWorld`, `sg_open_to_world` 중 하나이고, `newEvaluationResult.complianceType = COMPLIANT` | “보안그룹이 더 이상 World Open이 아님”을 Config가 **규정 준수 상태로 판정** |

---
## 3. 처리 로직 (Logic)
### 3.1. 이벤트 분기

- `aws.ec2` + `AWS API Call via CloudTrail`
  → **handle_ec2_positive_feedback()**
- `aws.config` + `detail-type`에 `"Compliance Change"` 포함
  → **handle_config_compliant()**
- 그 외는 `"noop"` 처리

### 3.2. EC2 Positive 이벤트 처리
1. 대상 이벤트 판별
   - `RevokeSecurityGroupIngress` → SSH(22) + 0.0.0.0/0 규칙 제거된 경우만 처리
   - `DeleteSecurityGroup` → SG 자체 삭제 시 처리
2. 대시보드용 payload 생성
   - sg-id, region, account, arn, severity 포함
3. Incident 기록
   - Incident 테이블에 NEW 상태로 1건 저장
   - 생성된 `incident_id` 를 payload에 추가
4. WebSocket 브로드캐스트
   - 실시간 대시보드로 이벤트 전송

### 3.3. Config Positive 이벤트 처리

- 규칙이 SG_OPEN_TO_WORLD 계열인지 확인
- COMPLIANT 로 변경된 경우만 처리
- 대시보드 payload + Incident 레코드 생성
- WebSocket 브로드캐스트

### 3.4. WebSocket 전송

- `CONNECTIONS_TABLE` 전체 Scan
- 모든 connectionId 에 메시지 전송
- 끊긴 연결(GoneException)은 자동 삭제
- 성공/삭제/오류 개수 로그 출력

---
## 4. 환경 변수 (Environment Variables)
| Key                | Value                                      | 설명 |
|--------------------|--------------------------------------------|------|
| `WS_ENDPOINT`      | `https://egtwu3mkhb.execute-api.us-east-1.amazonaws.com/prod/` | API Gateway **WebSocket 엔드포인트** URL. 브로드캐스트 시 사용 |
| `CONNECTIONS_TABLE`| `WebSocketConnections_v2`                  | 현재 접속 중인 WebSocket 클라이언트 목록을 저장하는 DynamoDB 테이블 이름 |
| `STATE_TABLE`      | `security-alerts-state-v2`                 | (현재 코드에서는 직접 사용하지 않지만) 탐지 상태/카운트 등을 저장하는 공용 상태 테이블 이름 |
| `INCIDENT_TABLE`   | `Incident`                                 | 보안 이벤트를 인시던트 형태로 적재하는 DynamoDB 테이블 이름 |
| `SEVERITY_ON_POSITIVE` | `LOW`                                  | Positive 이벤트 발생 시 대시보드/Incident에 기록될 **기본 심각도** 값 |

---
## 5. 사용 리소스 및 의존성 (Resources & Dependencies) 

- AWS Lambda
  - 본 함수가 배포되는 실행 환경
  - Python 런타임, `boto3` 기본 제공

- Amazon DynamoDB
  - `WebSocketConnections_v2`  
    - 파티션 키: `connectionId`  
    - 현재 대시보드 WebSocket 연결 관리용
  - `Incident`  
    - 파티션 키: `incident_id`  
    - 인시던트 히스토리 저장용

- Amazon API Gateway (WebSocket API)
  - 엔드포인트: `wss://egtwu3mkhb.execute-api.us-east-1.amazonaws.com/prod`
  - Lambda에서 `post_to_connection` 으로 대시보드에 실시간 알림 전송

- AWS CloudTrail
  - EC2 보안그룹 관련 관리 이벤트 수집
  - EventBridge 규칙이 CloudTrail 이벤트를 이 Lambda의 트리거로 사용

- AWS Config
  - `SG_OPEN_TO_WORLD` 등 보안그룹 공개 여부 규칙 평가
  - Compliance Change 이벤트를 EventBridge를 통해 Lambda로 전달

- EventBridge Rule
  - 위에서 설명한 CloudTrail / Config 이벤트를 필터 후 이 Lambda를 호출

---
## 6. IAM 권한 (IAM Permissions)

### 6.1. CloudWatch Logs 기본 권한 (AWSLambdaBasicExecutionRole)
   - 로그 그룹/스트림 생성 및 로그 기록  
   - `logs:CreateLogGroup`, `logs:CreateLogStream`, `logs:PutLogEvents`

### 6.2. WebSocketConnections_v2 DynamoDB 접근
   - `dynamodb:Scan` : 현재 연결된 WebSocket connectionId 목록 조회  
   - `dynamodb:UpdateItem`, `dynamodb:DeleteItem` : 끊어진 연결 정리 등

### 6.3. API Gateway WebSocket 연결 관리
   - `execute-api:ManageConnections`  
   - `@connections/*` 엔드포인트에 데이터 전송 및 종료 처리

### 6.4. STS GetCallerIdentity
   - `sts:GetCallerIdentity`  
   - 이벤트에 계정 ID가 없는 경우, 현재 Lambda 실행 계정 ID 조회용

### 6.5. Incident 테이블 쓰기 권한
   - `dynamodb:PutItem` on `arn:aws:dynamodb:us-east-1:021417007719:table/Incident`  
   - Positive 이벤트를 인시던트 히스토리를 위해 저장할 때 사용

---
## 7. 한계 및 향후 과제 (Limitations & TODO)

| 한계 | 향후 과제 |
|------|-----------|
| 현재는 **SSH 22번 포트(0.0.0.0/0)** 에 대한 World Open 규칙 해소만 Positive로 인식 | 규칙 확장: RDP(3389), 기타 포트, 특정 CIDR 블록(예: /8, /16) 해소 등도 Positive 이벤트로 지원 |
| AWS Config 규칙 이름이 `SG_OPEN_TO_WORLD`, `SecurityGroupOpenToWorld`, `sg_open_to_world` 중 하나일 때만 동작 | 환경 변수나 설정 테이블을 통해 **지원 rule 목록을 동적으로 관리**하도록 개선 |
| Incident 테이블에 저장만 하고, 후속 상태 변경(Processing, Mitigated, Closed)을 이 함수에서 관리하지 않음 | 운영 단계에서 **대시보드/운영자 조치에 따라 Incident 상태 갱신 API** 또는 별도 Lambda 설계 |
| WebSocket 브로드캐스트 실패 시, 일부 에러 케이스는 단순 로그만 남기고 재시도/알람이 없음 | 전송 실패 건에 대해 **재시도 메커니즘 또는 Dead-letter Queue(SQS)** 연동 검토 |
| STATE_TABLE(`security-alerts-state-v2`) 은 현재 코드에서 직접 사용되지 않음 | 추후 다른 탐지 Lambda와 공통으로 사용할 **상태/카운트 재사용 로직**으로 통합하거나, 미사용 시 정리 |


