## 1. 함수 개요 (Overview)
이 Lambda 함수는 **DVWA 인스턴스에 대한 외부 취약점 스캐너 탐지 알람(CloudWatch Alarm)** 이 발생했을 때
아래의 자동대응을 수행하는 역할을 한다.

1. CloudWatch Alarm(스캐너 탐지) 이벤트 수신
2. 이벤트 원문을 S3 버킷에 아카이브 (로그/증적 보관)
3. 대상 DVWA EC2 인스턴스를 **격리용 SG 하나만 적용된 상태로 변경(인스턴스 격리/HTTP 차단 효과)**
4. 자동대응 결과를 **Actions WebSocket 대시보드**로 브로드캐스트

- 추가 특징
  - ALARM 상태가 아닐 경우(`OK`, `INSUFFICIENT_DATA`)에는 자동대응을 수행하지 않고 `skip` 처리
  - CloudWatch Alarm ARN에서 `...:alarm` 부분까지만 잘라서 대시보드에 전달 (시각화 단순화)
  - 아카이브/격리/HTTP 차단 결과를 모두 `details` 필드에 포함하여 대시보드에서 상세 확인 가능

---

## 2. 동작 조건 & 트리거 (Conditions & Trigger)

| 구분                            | 조건                                                                                 | 트리거되는 이벤트(detail-type / state)                              | 설명                                                                 |
| ----------------------------- | ---------------------------------------------------------------------------------- | -------------------------------------------------------------------- | -------------------------------------------------------------------- |
| **스캐너 탐지 자동대응 수행**          | `source = aws.cloudwatch`<br>`detail-type = CloudWatch Alarm State Change`       | • `state.value = "ALARM"`                                           | DVWA 스캐너 탐지용 CloudWatch Alarm 이 ALARM 상태가 되었을 때 자동대응 실행 |
| **스캐너 탐지 알람이지만 ALARM 아님** | `source = aws.cloudwatch`<br>`detail-type = CloudWatch Alarm State Change`       | • `state.value = "OK"` or `"INSUFFICIENT_DATA"` 등 ALARM 이외 상태 | 자동대응을 수행하지 않고 `state_is_xxx` 로그만 남기고 종료                         |
| **기타 이벤트 (noop)**            | 그 외 모든 이벤트                                                                         | 해당 없음                                                               | 이 Lambda 가 담당하지 않는 이벤트는 `skip` 으로 처리                                  |

---

## 3. 처리 로직 (Logic)

### 3.1 CloudWatch Alarm 필터링 및 상태 체크 (`lambda_handler`)
- 이벤트 소스/타입 확인  
  - `event["source"] != "aws.cloudwatch"` 이면 즉시 `skip` 처리  
  - `event["detail-type"] != "CloudWatch Alarm State Change"` 이면 `skip` 처리
- 새 상태 추출  
  - `detail.state.value` 값을 읽어서 `new_state` 로 저장
- `new_state != "ALARM"` 인 경우  
  - 자동대응 수행 없이 `{"status": "skip", "reason": f"state_is_{new_state}"}` 로그 후 종료
- `ALARM` 인 경우에만 아래 3단계 자동대응 + WebSocket 알림 수행

### 3.2 CloudWatch 이벤트 S3 아카이브 (`archive_event_to_s3`)
- 목적: 스캐너 탐지 알람 발생 시 **이벤트 원문을 S3 에 JSON 파일로 보존**
- 동작
  - `ARCHIVE_BUCKET` 환경변수가 없으면  
    - `{"warn": "ARCHIVE_BUCKET not set, skip archive"}` 로그 후 skip
  - 키 형식:  
    - `scanner/{unix_timestamp}-{uuid}.json`
  - S3 `put_object` 호출로 이벤트 전체를 pretty JSON 형태로 저장
- 리턴 구조 예시
  - 성공: `{"status": "ok", "bucket": "...", "key": "scanner/..."}`  
  - 실패: `{"status": "error", "error": "..."}`

### 3.3 인스턴스 격리 (`quarantine_instance`)
- 목적: DVWA 인스턴스를 **격리 SG 하나만 연결된 상태**로 변경하여 외부 접근 차단
- 입력
  - `instance_id`: `DVWA_INSTANCE_ID` 환경변수에서 주입된 대상 인스턴스 ID
  - `quarantine_sg_id`: `QUARANTINE_SG_ID` (격리용 SG)
- 처리 순서
  - 필수 값 확인: 둘 중 하나라도 없으면 `skip` 하고 로그 남김
  - `ec2.describe_instances(InstanceIds=[instance_id])` 로 인스턴스 정보 조회
  - 첫 번째 네트워크 인터페이스(ENI)를 가져와 `NetworkInterfaceId` 추출
  - `modify_network_interface_attribute` 호출로 `Groups=[quarantine_sg_id]` 로 교체
- 결과
  - 성공 시:  
    ```jsonc
    {
      "status": "ok",
      "instance_id": "i-xxxx",
      "eni_id": "eni-xxxx",
      "applied_sg": "sg-xxxx"
    }
    ```
  - 실패 시: `{"status": "error", "error": "..."}`

### 3.4 HTTP 차단 처리 (`block_world_http`)
- 현재 구조에서는 **별도의 SG 규칙 변경 작업 없이**  
  “격리 SG 하나만 적용”되는 것 자체가 HTTP 차단 효과를 냄
- 따라서 함수 내부에서는
  - 추가 API 호출 없이  
    `{"status": "blocked_by_quarantine_sg", "instance_id": ...}` 형태로 상태만 기록
- 향후 필요 시, 80/443 포트만 특정 규칙으로 조정하거나 WAF 연동 등으로 확장 가능

### 3.5 Actions WebSocket 브로드캐스트 (`post_to_ws_actions`)
- 목적: 자동대응 결과를 **Remediation WebSocket 대시보드**에 실시간 전송
- 환경변수 확인
  - `WS_ENDPOINT_ACTIONS` 가 없으면 `ws_actions: skip` 후 종료
  - `CONNECTIONS_TABLE_ACTIONS` 가 없으면 역시 `skip`
- 엔드포인트/리전 계산
  - `endpoint_url = WS_ENDPOINT_ACTIONS.rstrip("/")`
  - URL 에서 `.execute-api.{region}.amazonaws.com` 패턴을 파싱해 리전 추출  
    (실패 시 `REGION` 기본값 사용)
- DynamoDB 스캔 + API Gateway 관리 API 호출
  - `CONNECTIONS_TABLE_ACTIONS` 테이블에서 `connectionId` 만 Projection 으로 `scan`
  - 각 connectionId 에 대해  
    `apigatewaymanagementapi.post_to_connection(ConnectionId=..., Data=payload)`
  - `GoneException` 발생 시 해당 connectionId 를 테이블에서 삭제
  - 기타 오류는 로그(`send_error`)로만 남기고 카운터 증가
- 최종 로그 예시
  ```jsonc
  {
    "ws_actions": "done",
    "ok": 3,
    "gone": 1,
    "err": 0
  }

---
## 4. 환경 변수 (Environment Variables)
| Key                         | Value                                                       | 설명                                                                                    |
| --------------------------- | -------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| `ARCHIVE_BUCKET`            | `layer3-security-archive`                                      | 스캐너 탐지 CloudWatch 이벤트 원문을 아카이브할 S3 버킷 이름                                              |
| `CONNECTIONS_TABLE_ACTIONS` | `RemediationWebSocketConnections`                              | **자동대응(액션) WebSocket** 연결 ID 를 저장하는 DynamoDB 테이블명                                     |
| `DVWA_INSTANCE_ID`          | `i-0ac2cbc9d6a8afc46`                                          | 격리 대상인 DVWA EC2 인스턴스 ID                                                               |
| `QUARANTINE_SG_ID`          | `sg-08af46f4a407ece7b`                                         | 격리용 Security Group ID (외부 접근이 차단된 SG)                                                 |
| `REGION`                    | `us-east-1`                                                    | (선택) 강제로 사용할 리전. 없으면 `AWS_REGION` 사용, 둘 다 없으면 기본값 `us-east-1`                         |
| `WS_ENDPOINT_ACTIONS`       | `https://egtwu3mkhb.execute-api.us-east-1.amazonaws.com/prod/` | Remediation WebSocket API 의 관리 엔드포인트 (`/prod` 까지 포함, `apigatewaymanagementapi` 에서 사용) |
| `STATE_TABLE`               | `security-alerts-state-v2`                                     | **현재 이 코드에서는 직접 사용하지 않음.** 향후 자동대응 상태 관리용으로 확장 예정인 예약 변수                              |

---
## 5. 사용 리소스 및 의존성 (Resources & Dependencies)

### 5.1 AWS 리소스

#### **EC2**
- `DescribeInstances`, `ModifyNetworkInterfaceAttribute`  
  → 대상 인스턴스/ENI 조회 및 SG 교체에 사용됨

#### **S3**
- `ARCHIVE_BUCKET` 에 CloudWatch Alarm 이벤트(JSON)를 저장

#### **DynamoDB**
- `CONNECTIONS_TABLE_ACTIONS`  
  → WebSocket connectionId 목록 관리 및 Scan

#### **API Gateway WebSocket**
- `WS_ENDPOINT_ACTIONS`  
  → WebSocket API의 `@connections/*` 엔드포인트로 알림 전송

#### **CloudWatch Logs**
- Lambda 실행 로그 및 디버깅 정보 기록


### 5.2 코드/라이브러리 의존성

#### **Python 표준 라이브러리**
- os  
- json  
- time  
- uuid  
- re  

#### **외부 라이브러리**
- boto3  
- botocore.exceptions.ClientError  
- botocore.exceptions.BotoCoreError  

---

## 6. IAM 권한 (IAM Permissions)

### 6.1 EC2 권한
대상 인스턴스 ENI 조회 및 SG 변경에 필요:

- `ec2:DescribeInstances`
- `ec2:ModifyNetworkInterfaceAttribute`

### 6.2 S3 권한
CloudWatch 이벤트 JSON 저장:

- 리소스:  
  `arn:aws:s3:::<ARCHIVE_BUCKET>/*`
- 필요한 액션:
  - `s3:PutObject`

### 6.3 DynamoDB 권한
`CONNECTIONS_TABLE_ACTIONS` 접근:

- `dynamodb:Scan`
- `dynamodb:DeleteItem`
- (선택) `dynamodb:DescribeTable`  
  → 운영/디버그 편의성

### 6.4 API Gateway WebSocket 권한
WebSocket connectionId 로 메시지를 전송하기 위해 필요:

- 리소스 예시  
  `arn:aws:execute-api:us-east-1:<ACCOUNT_ID>:<API_ID>/prod/POST/@connections/*`
- 권장 액션
  - `execute-api:ManageConnections`

### 6.5 CloudWatch Logs (Lambda 기본 실행 역할)
Lambda 실행 로그 기록용:

- `logs:CreateLogGroup`
- `logs:CreateLogStream`
- `logs:PutLogEvents`
- 
---
## 7. 한계 및 향후 과제 (Limitations & TODO)
| 한계                                                                 | 향후 과제                                                                 |
| ------------------------------------------------------------------ | --------------------------------------------------------------------- |
| 현재는 **고정된 하나의 DVWA 인스턴스 ID(DVWA_INSTANCE_ID)** 에 대해서만 자동대응 수행      | CloudWatch Alarm 메트릭/Tag 를 기반으로 여러 인스턴스를 동적으로 찾아 격리할 수 있도록 확장         |
| 인스턴스에 ENI 가 여러 개 있는 경우, **첫 번째 ENI 에만 격리 SG 적용**                   | 모든 ENI 를 순회하며 동일한 격리 SG 를 적용하거나, 특정 서브넷/ENI 패턴에 따라 선택적으로 격리하도록 개선     |
| 격리 이후 **롤백(원래 SG 복구)** 로직이 없다                                      | 수동/자동 롤백을 위한 원래 SG 스냅샷 저장 및 복구 API 설계                                 |
| `STATE_TABLE` 환경변수가 있지만, **현재 실제 코드에서는 사용되지 않음**                   | 자동대응 이력/상태(이미 격리된 인스턴스 여부, 최근 N분 간 대응 여부 등)를 STATE_TABLE 에 기록하는 로직 추가 |
| WebSocket 브로드캐스트 시 단순 `scan + 전송` 만 수행, **재시도/지수 백오프/배치 전송 전략 부재** | 대량 연결 환경에서도 안정적인 전송을 위해 실패 재시도, 배치 처리, 전송 실패 지표 수집 추가                 |
| CloudWatch Alarm 의 **정확한 조건/임계치** 에 따라 오탐/미탐 가능성이 존재               | 스캐너 트래픽 패턴을 기반으로 메트릭/임계치를 지속적으로 튜닝하고, GuardDuty 등 다른 탐지 소스와 연계하여 보완   |
| S3 아카이브 파일이 증가해도 별도 LifeCycle/만료 정책이 없어 **장기적으로 스토리지 비용 증가 가능성**   | S3 Lifecycle Rule 로 `scanner/` prefix 에 대해 일정 기간 후 Glacier/삭제 정책 설정   |
