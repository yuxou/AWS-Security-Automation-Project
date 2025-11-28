## 1. 함수 개요 (Overview)
이 Lambda 함수는 동일 사용자가 여러 보안 그룹(SG)에 대해 SSH(22/TCP)를 0.0.0.0/0 또는 ::/0 으로 반복 오픈하는 위험 패턴을 탐지하여, 임계치(THRESHOLD) 이상이면 WebSocket 대시보드로 알림을 보내는 보안 탐지 함수이다.

- CloudTrail 이벤트 `AuthorizeSecurityGroupIngress`, `RunInstances`, `ModifyInstanceAttribute`, `CreateAccessKey` 감지
- 5~10분 윈도우(WINDOW_SECONDS) 내부에서 동일 사용자(ARN)가 서로 다른 SG에서 SSH 월드 오픈을 3회 이상 수행하면 즉시 알림 전송
- 중복 이벤트(eventID)는 1번만 처리 (멱등성 보장)
- Access Key 생성(CreateAccessKey) 이벤트 발생 시 AccessKeyCreated 보안 이벤트를 대시보드로 전달
- WebSocket API + DynamoDB(WebSocketConnections)를 이용해 대시보드로 실시간 브로드캐스트

---
## 2. 동작 조건 & 트리거 (Conditions & Trigger)
### 2.1. EventBridge / CloudTrail 트리거 조건
| source | detail-type                   | eventName                                 | 설명                                             |
| ---- | ----------------------------- | ----------------------------------------- | ---------------------------------------------- |
| `aws.ec2` | `AWS API Call via CloudTrail` | `AuthorizeSecurityGroupIngress`           | SG 인바운드 규칙 추가 시 호출. 이 함수의 **메인 트리거**로 사용됨.     |
| `aws.ec2` | `AWS API Call via CloudTrail` | `RunInstances`, `ModifyInstanceAttribute` | 인스턴스에 SG가 연결되거나 변경될 때 참조용 보조 알림(필요 시 비활성화 가능). |
| `aws.iam` | `AWS API Call via CloudTrail` | `CreateAccessKey`                         | IAM Access Key 생성 이벤트 수신 및 대시보드 알림.            |

### 2.2. SSH 월드 오픈 카운트 조건
- CloudTrail detail 의 eventName == "AuthorizeSecurityGroupIngress" 인 경우만 처리
- requestParameters.ipPermissions.items[] 중 아래 조건을 모두 만족하는 항목이 있을 때만 “SSH 월드 오픈”으로 판단
  - ipProtocol ∈ { "tcp", "6", "-1", "all" }
  - fromPort == 22 AND toPort == 22
  - 아래 둘 중 하나라도 존재
    - ipRanges.items[].cidrIp == "0.0.0.0/0"
    - ipv6Ranges.items[].cidrIpv6 == "::/0"

### 2.3. 임계치 및 윈도우 조건
- 윈도우 길이 : WINDOW_SECONDS (예: 600초 = 10분)
- 임계치 : THRESHOLD (예: 3)
- 같은 userIdentity.arn(행위자) 기준으로
  - 서로 다른 SG 에서 SSH 월드 오픈이 발생할 때마다 1회씩 카운트
  - 같은 SG 에 대해 윈도우 내에서 여러 번 다시 열어도 1회만 카운트
- 카운트 방식 (DynamoDB 키)
  - actor-sg#{actor_arn}#{sg_id} : 해당 윈도우에서 이 조합을 이미 센 적 있는지 여부
  - actor-count#{actor_arn} : 윈도우 내에서 서로 다른 SG 에서 월드 SSH 오픈한 개수
- 조건 충족 시점
  - actor-count#{actor_arn}.count >= THRESHOLD 가 되는 바로 그 AuthorizeSecurityGroupIngress 이벤트에서 알림 전송

### 2.4. 알림 래치(윈도우당 1회)
- 같은 행위자가 같은 윈도우 동안 반복적으로 조건을 충족하더라도
  - actor-alerted#{actor_arn} 키로 플래그를 저장
  - 해당 TTL (WINDOW_SECONDS) 동안은 추가 알림을 보내지 않고 already_alerted_in_window 상태로 종료
---
## 3. 처리 로직 (Logic) 

### 3.1. 이벤트 수신 & 필터링
- EventBridge/CloudTrail 관리 이벤트(AuthorizeSecurityGroupIngress, RunInstances, ModifyInstanceAttribute, CreateAccessKey)를 수신하고, CloudWatch Logs 형식(awslogs)은 바로 스킵한다.

### 3.2. 멱등성 & SSH 월드 오픈 판별

- CloudTrail `eventID` 기준으로 중복 이벤트를 제거하고, `AuthorizeSecurityGroupIngress` 중에서 **22/TCP + 0.0.0.0/0 또는 ::/0** 인 경우에만 “SSH 월드 오픈”으로 인식한다.

### 3.3. 사용자별 SG 오픈 카운팅

- SG별 마커(`sg-open#*`)와 사용자·SG 조합(`actor-sg#actor#sg`)을 DynamoDB에 저장하고, 같은 사용자(ARN)가 **윈도우 시간(WINDOW_SECONDS)** 안에서 서로 다른 SG를 열 때마다 `actor-count#actor` 카운트를 증가시킨다.

### 3.4. 임계치 도달 & 윈도우당 1회 알림
- 카운트가 `THRESHOLD` 이상이면, 윈도우 내에서 이미 알림을 보낸 적이 있는지(`actor-alerted#actor`) 확인하고, 처음일 때만 “동일 계정 내 여러 SG에서 반복 SSH 오픈” 이벤트를 생성한다.

### 3.5. 대시보드 전송 (WebSocket 브로드캐스트)
- 대시보드 스키마로 변환한 후 WebSocket API(Connections 테이블 기반)로 모든 활성 connectionId에 전송하고, 필요 시 Access Key 생성(CreateAccessKey) 이벤트도 별도의 보안 이벤트로 동일 방식으로 브로드캐스트한다.

---
## 4. 환경 변수 (Environment Variables) 
| Key                   | 예시 Value                                                       | 설명                                                                               |
| --------------------- | -------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| `CONNECTIONS_TABLE`   | `WebSocketConnections`                                         | WebSocket 연결 정보를 보관하는 DynamoDB 테이블 이름. connectionId 리스트를 조회해 대시보드로 브로드캐스트할 때 사용. |
| `STATE_TABLE`         | `security-alerts-state-v2`                                     | 각종 상태(멱등성 플래그, SG 오픈 마커, actor 카운트, 알림 래치 등)를 저장하는 DynamoDB 테이블 이름.              |
| `THRESHOLD`           | `3`                                                            | 임계치 값. 동일한 사용자(ARN)가 **서로 다른 SG에서 SSH 월드 오픈을 몇 번 하면** 알림을 보낼지 결정.                |
| `USE_EVENT_TIME`      | `0`                                                            | 대시보드 표시 시간 기준. `0`이면 Lambda 실행 시점을 사용(실시간 느낌), `1`이면 CloudTrail `eventTime` 사용.  |
| `WINDOW_SECONDS`      | `300` 또는 `600`                                                 | 윈도우 길이(초). 이 시간 동안의 이벤트만 누적 카운트에 포함되며, TTL 이 지나면 자동으로 초기화.                       |
| `WS_ENDPOINT`         | `https://egtwu3mkhb.execute-api.us-east-1.amazonaws.com/prod/` | WebSocket API Gateway 엔드포인트 URL. 이 주소로 대시보드 메시지가 전송됨.                            |
| `STATE_PK`            | `id`                                                      | `STATE_TABLE` 에서 파티션 키로 사용할 속성 이름. 기본은 `id`.                                     |

---
## 5. 사용 리소스 및 의존성 (Resources & Dependencies) 
### 5.1. AWS DynamoDB
- security-alerts-state-v2
  - CloudTrail eventID 멱등성(seen::*)
  - SG 오픈 마커(sg-open#*)
  - 행위자-보안그룹 조합 상태(actor-sg#*)
  - 행위자별 카운트(actor-count#*)
  - 알림 래치 플래그(actor-alerted#*)
- WebSocketConnections
  - WebSocket API Gateway 에 연결된 모든 클라이언트의 connectionId 저장
### 5.2. AWS API Gateway (WebSocket)
- WS_ENDPOINT 로 지정된 WebSocket API
- Lambda 가 apigatewaymanagementapi:post_to_connection 을 통해 대시보드로 실시간 이벤트 전송
### 5.3. AWS CloudTrail + EventBridge
- AuthorizeSecurityGroupIngress, RunInstances, ModifyInstanceAttribute, CreateAccessKey 등의 관리 이벤트를 EventBridge 규칙을 통해 Lambda 타겟으로 전달
### 5.4. AWS STS 
- 이벤트에서 accountId 를 찾지 못할 경우 sts:GetCallerIdentity 를 통해 보완
### 5.5. Python 라이브러리
- boto3, botocore.exceptions.ClientError, decimal.Decimal, datetime, urllib.request, re, json, time, os

---
## 6. IAM 권한 (IAM Permissions)
### 6.1. 기본 Lambda 실행권한 (AWSLambdaBasicExecutionRole)
- CloudWatch Logs 로그 그룹 생성 및 로그 전송
- logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents 등 포함
### 6.2. 상태 테이블 접근 권한 (STATE_TABLE: security-alerts-state-v2)
- SG 오픈 상태, 카운트, 멱등성 플래그 저장/조회
- 허용 액션
  - dynamodb:PutItem
  - dynamodb:UpdateItem
  - dynamodb:GetItem
- 리소스 : arn:aws:dynamodb:us-east-1:*:table/security-alerts-state-v2
### 6.3. WebSocket 연결 테이블 접근 권한 (CONNECTIONS_TABLE: WebSocketConnections)
- 활성화된 WebSocket connectionId 목록 조회 및, 끊어진 연결 삭제
- 허용 액션
  - dynamodb:Scan
    - dynamodb:DeleteItem
- 리소스 : arn:aws:dynamodb:us-east-1:*:table/WebSocketConnections
### 6.4. WebSocket API Gateway 연결 관리 권한
- 대시보드 클라이언트로 메시지를 push 하기 위해 필요
- 허용 액션
  - execute-api:ManageConnections
- 리소스 : arn:aws:execute-api:us-east-1:*:*/*/@connections/*
---
## 7. 한계 및 향후 과제 (Limitations & TODO)
| 한계                                                                                                     | 향후 과제                                                                                               |
| ------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------- |
| 현재는 **SSH(22/TCP) + 0.0.0.0/0, ::/0** 만 감지하며, 다른 포트(3389/RDP 등)나 넓은 CIDR(예: /8, /16)은 탐지하지 않음          | 감지 대상을 포트/프로토콜/네트워크 대역별로 설정 가능하게 확장 (예: 환경변수로 포트 리스트, 허용 CIDR 범위 지정)                                |
| 카운트 기준이 **행위자 ARN 단위**라서, 여러 사용자가 같은 계정에서 조금씩 나눠서 오픈하는 경우는 임계치에 도달하지 않을 수 있음                           | 계정 전체 기준, IAM Role 기준 등 다양한 집계 단위를 지원하고, 대시보드에서 필터링 가능하도록 메타데이터 확장                                  |
| TTL 기반 윈도우(슬라이딩 방식)에 의존하기 때문에, 테이블 파티션 키(`STATE_PK`)에 이벤트가 많이 몰릴 경우 DynamoDB 핫 파티션 가능성 존재              | 파티션 설계를 개선하고, CloudWatch 지표 기반으로 읽기/쓰기 용량 및 파티션 키 설계 튜닝                                             |
| WebSocket 대시보드에 의존하므로, 대시보드가 연결되어 있지 않거나 WebSocket 에러가 발생하면 알림이 사용자에게 보이지 않을 수 있음                      | SNS, 이메일, Slack Webhook 등 다른 채널과 연동하여 **다중 채널 알림** 지원. HTTP 폴백 엔드포인트 고도화                            |
| RunInstances / ModifyInstanceAttribute 보조 로직은 인스턴스와 SG 매칭만 수행하며, 실제로 트래픽이 발생했는지(실제 SSH 접속 시도)는 확인하지 않음 | VPC Flow Logs, GuardDuty, CloudWatch Metric Filter 등과 연계하여 “실제 접속 시도 + 월드 오픈”을 함께 볼 수 있는 상관분석 로직 추가 |
| 현재 Access Key 생성 이벤트에 대해서는 단순 발생 알림만 제공하며, 키 회전 정책, MFA 여부 등은 고려하지 않음                                  | IAM 보안 베스트 프랙티스(키 회전 주기, 루트 계정 사용 여부, MFA 활성화 여부 등)를 함께 점검하여 보안 점수 형태로 대시보드에 추가 표시                  |

