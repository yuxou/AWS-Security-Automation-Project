## 1. 함수 개요 (Overview)
이 Lambda 함수는 탐지된 고위험 보안 그룹 변경 사항에 대해 **자동 대응(Auto-Remediation)** 을 수행하는 실행 엔진임

`SecurityAlertProcessor`가 위험을 감지하여 SQS에 메시지를 넣으면, 이 함수가 트리거되어 다음 작업을 수행함
1.  **자동 차단:** EC2 API를 호출하여 위험한 인바운드 규칙(예: SSH 전체 개방)을 즉시 제거(Revoke)
2.  **진행 상황 전파:** 대응 시작(TRIGGERED) 및 완료(SUCCEEDED/FAILED) 상태를 WebSocket을 통해 대시보드에 실시간 전송함
3.  **이력 업데이트:** `Incident` DynamoDB 테이블의 인시던트 상태를 `PROCESSING` -> `MITIGATED`로 갱신함

---
## 2. 동작 조건 & 트리거 (Conditions & Trigger)

### 2.1. 트리거 소스 (Event Source)
* **AWS SQS (Simple Queue Service):** `SecurityRemediationQueue`
* **배치 크기:** 코드 로직상 1회 실행 시 `Records[0]`만 처리하므로, 배치 크기(Batch Size)를 1로 설정하는 것이 권장됨

### 2.2. 메시지 페이로드 (Input Format)
SQS 메시지 본문(Body)은 다음 JSON 형식을 따름
```json
{
    "groupId": "sg-xxxxxx",
    "remediationRules": [
        { "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIp": "0.0.0.0/0" }
    ],
    "incidentId": "inc-20251124-xxxx"
}
```

---
## 3. 처리 로직 (Logic) 

본 함수는 SQS로부터 트리거되어 다음과 같은 순서로 자동 대응을 수행함

1.  **초기화 및 파싱:** `SecurityRemediationQueue`에서 수신된 메시지를 파싱하여 `groupId`, `remediationRules`, `incidentId`를 추출함
2.  **대응 시작 알림 (TRIGGERED):**
    * WebSocket을 통해 대시보드에 대응 시작 상태(`TRIGGERED`)를 전송함
    * `Incident` 테이블의 상태를 `PROCESSING`으로 업데이트
3.  **보안 그룹 규칙 제거 (Revoke):**
    * `ec2:RevokeSecurityGroupIngress` API를 사용하여 위험으로 식별된 인바운드 규칙을 즉시 삭제함
4.  **결과 처리 및 종료:**
    * **성공 시:** WebSocket 상태 `SUCCEEDED`, DB 상태 `MITIGATED`로 업데이트함
    * **실패 시:** WebSocket 상태 `FAILED`를 전송하고 로그를 남김

### 3.2. 메시지 브로드캐스팅
* `RemediationWebSocketConnections` 테이블을 스캔하여 현재 접속 중인 관리자 세션을 식별하고, 모든 세션에 조치 진행 상황을 실시간 JSON으로 전송함

---
## 4. 환경 변수 (Environment Variables) 

| 변수명 | 값 | 설명 |
| :--- | :--- | :--- |
| REGION_WS | us-east-1 | WebSocket API가 배포된 리전 |
| REMEDIATION_WS_ENDPOINT | 3y9ayspfp3.execute-api.us-east-1.amazonaws.com/prod/ | 대응 현황 중계용 WebSocket 엔드포인트 |
| REMEDIATION_CONNECTIONS_TABLE | RemediationWebSocketConnections | 대응 채널 활성 세션 관리 테이블 |
| INCIDENT_TABLE_NAME | Incident | 인시던트 상태 관리를 위한 테이블 |

---
## 5. 사용 리소스 및 의존성 (Resources & Dependencies) 

### 5.1. AWS 리소스
* **SQS:** `SecurityRemediationQueue` (Trigger Source)
* **EC2:** `RevokeSecurityGroupIngress`, `DescribeSecurityGroups`
* **DynamoDB:** `Incident`, `RemediationWebSocketConnections`
* **API Gateway:** WebSocket Management API (`PostToConnection`)

### 5.2. 외부 라이브러리
* `boto3`, `botocore`: AWS SDK for Python (기본 런타임 포함)

---
## 6. IAM 권한 (IAM Permissions)

* **SQS:** 메시지 수신(`ReceiveMessage`) 및 처리 완료 후 삭제(`DeleteMessage`)
* **EC2:** 보안 그룹 인바운드 규칙 제거(`RevokeSecurityGroupIngress`)
* **DynamoDB:** 인시던트 상태 갱신(`UpdateItem`) 및 웹소켓 연결 조회(`Scan`)
* **API Gateway:** 웹소켓 클라이언트로 상태 메시지 전송(`ManageConnections`)
* **CloudWatch Logs:** 로그 그룹 생성 및 로그 스트림 기록

---
## 7. 한계 및 향후 과제 (Limitations & TODO)

* **[Limit] SQS 배치 처리:** 현재 로직은 단일 레코드(`Records[0]`)만 처리하도록 되어 있어, SQS 배치 사이즈가 2 이상일 경우 나머지 메시지가 누락될 수 있음 (Loop 처리 필요)
* **[Limit] 예외 처리 강화:** `revoke` 실패 시 단순 로그 기록 외에, 실패 상태를 DB에 명시적으로 기록하거나 운영자에게 알림(SNS)을 보내는 로직 추가 필요함
* **[TODO] 환경 변수 검증:** `REMEDIATION_WS_ENDPOINT` 프로토콜(`https://`) 하드코딩 제거 및 유연한 처리 개선 필요함

---
