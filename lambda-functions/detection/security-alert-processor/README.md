## 1. 함수 개요 (Overview)
이 Lambda 함수는 AWS 환경 내에서 발생하는 보안 그룹(Security Group) 변경 이벤트를 실시간으로 분석하여 위험 요소를 탐지하는 **보안 이벤트 분석 및 전파 엔진**임
* **주요 기능:** 22번 포트 개방, PROD 정책 위반 등 고위험 변경 사항을 즉시 탐지함
* **결과 처리:** 탐지된 위험을 WebSocket 대시보드로 브로드캐스팅하고, 인시던트 DB에 기록하며, 필요한 경우 자동 조치(Remediation)를 위해 SQS 메시지를 발행함
* **상관 분석:** 보안 그룹 개방 직후 발생하는 외부 접속 시도(CloudTrail/GuardDuty)와의 연관성을 분석함

---

## 2. 동작 조건 및 트리거 (Conditions & Trigger)
* **이벤트 소스:** AWS EventBridge (CloudTrail API Calls)
* **트리거 조건:** `event['detail']['eventName']`이 다음 중 하나일 때 동작함
    * **위험 분석 대상:** `AuthorizeSecurityGroupIngress`, `ModifySecurityGroupRules`, `CreateSecurityGroup`
    * **상태 해제 대상:** `RevokeSecurityGroupIngress`
    * **상관 분석 대상:** `ExternalAccessDetected`, `AcceptConnection`, `RemoteLoginAttempt`

---

## 3. 처리 로직 (Logic)
1. **위험 탐지 (Risk Detection):** 수신된 이벤트의 `ipPermissions`를 분석하여 등급을 산정함
    * **CRITICAL:** `0.0.0.0/0`으로 SSH(22) 개방 또는 PROD 환경에서의 전체 개방
    * **HIGH:** 고위험 포트(`21`, `23`, `3306`, `5432`, `3389`) 전체 개방
    * **WARNING:** 설명(Description)에 `test`, `temp`, `open` 등 임시 허용 키워드 포함
2. **데이터 처리 및 전파:**
    * **DB 기록:** `Incident` 테이블에 사건 생성 및 `RecentOpenSGs`에 최근 개방 기록 저장(TTL 적용)
    * **알림 전송:** `WebSocketConnections_v2` 테이블을 스캔하여 연결된 클라이언트에 알림 발송
    * **조치 요청:** 위험 규칙 식별 시 `SecurityRemediationQueue` SQS로 조치 메시지 발행
3. **상관 관계 분석 (Correlation):**
    * 보안 그룹이 개방된 직후(5분 내) 외부 접속 이벤트가 발생하면 `RecentOpenSGs` 테이블을 조회하여 **"개방 직후 접속 시도"** 패턴을 탐지하고 CRITICAL 알림을 생성함

---

## 4. 환경 변수 (Environment Variables)

| 변수명 | 값 | 설명 |
| :--- | :--- | :--- |
| TARGET_REGION | us-east-1 | 리소스가 위치한 대상 리전 |
| WS_ENDPOINT | egtwu3mkhb.execute-api.us-east-1.amazonaws.com/prod | 웹소켓 API 게이트웨이 엔드포인트 |
| CONNECTIONS_TABLE | WebSocketConnections_v2 | 활성 웹소켓 세션 관리 테이블 |
| INCIDENT_TABLE_NAME | Incident | 보안 인시던트 이력 저장 테이블 |
| REMEDIATION_LAMBDA_NAME | SecurityGroupRemediationProcessor | (참조용) 복구 담당 람다 이름 |

---

## 5. 사용 리소스 및 의존성 (Resources & Dependencies)
**AWS Resources**
* **DynamoDB:**
    * `Incident`: 인시던트 상세 정보 저장
    * `WebSocketConnections_v2`: 웹소켓 연결 ID 관리
    * `RecentOpenSGs`: 최근 개방된 SG 추적 (TTL 적용)
* **SQS:** `SecurityRemediationQueue` (자동 조치 요청용)
* **API Gateway:** WebSocket 메시지 전송 (`PostToConnection`)

**Python Libraries**
* `boto3`, `botocore`
* `json`, `os`, `datetime`, `uuid`, `random`, `time`

---

## 6. 필요한 IAM 권한 (Required IAM Permissions)

### 6.1. Logging (CloudWatch)
* `logs:CreateLogGroup`, `logs:CreateLogStream`, `logs:PutLogEvents`: Lambda 실행 로그 기록

### 6.2. EC2 (Security Group)
* `ec2:DescribeSecurityGroups`: 보안 그룹의 태그 및 설명(Description) 정보 조회
* `ec2:RevokeSecurityGroupIngress`: (참조) 직접적인 제어 권한(실제 로직은 SQS로 위임)

### 6.3. DynamoDB
* `dynamodb:PutItem`, `GetItem`, `UpdateItem`, `DeleteItem`, `Scan`, `Query`: 인시던트 기록, 최근 개방 목록 관리, 웹소켓 연결자 조회
* **대상 테이블:** `Incident`, `RecentOpenSGs`, `WebSocketConnections_v2`, `ProcessedEvents`

### 6.4. SQS & API Gateway
* `sqs:SendMessage`: `SecurityRemediationQueue`로 조치 요청 메시지 발송
* `execute-api:ManageConnections`: 연결된 클라이언트에 데이터 전송

---

## 7. 한계 및 향후 과제 (Limitations & TODO)
* **[Limit] SQS URL 하드코딩:** 코드 내 큐 URL이 고정되어 있어 환경 변수 기반으로 동적 할당하도록 수정 필요함
* **[Limit] 동시성 처리:** 대량의 이벤트 발생 시 `scan`을 사용하는 웹소켓 브로드캐스팅 로직이 성능 병목이 될 수 있음
* **[TODO]** 조치 결과 피드백 루프 구현 (SQS 단방향 요청 후 조치 성공 여부를 수신하는 로직 추가)
* **[TODO]** 사용되지 않거나 혼재된 DynamoDB 테이블(`AlertStateTable` 등) 정리 및 IAM 정책 최적화
