## 1. 함수 개요 (Overview)
이 Lambda 함수는 AWS IAM의 CreateAccessKey 이벤트를 실시간으로 탐지하여 다음 기능을 수행하는 보안 관제용 이벤트 수집 Lambda이다.
- IAM Access Key 생성(CreateAccessKey) 이벤트 감지 
- CloudTrail 이벤트 분석 후 보안 알림 생성 
- WebSocket API 대시보드로 알림 전송 
- Incident 테이블에 이벤트 이력 저장 
- SG/ARN/Region 등 상세 데이터 자동 파싱 및 스키마에 맞게 변환

---
## 2. 동작 조건 & 트리거 (Conditions & Trigger)
| 항목           | 값                             |
| ------------ | ----------------------------- |
| Event Source | `aws.iam`                     |
| detail-type  | `AWS API Call via CloudTrail` |
| 적용되는 이벤트 이름  | `CreateAccessKey`             |
| 트리거 방식       | EventBridge Rule → Lambda     |

---
## 3. 처리 로직 (Logic) 
### 3.1. EventBridge에서 CreateAccessKey 이벤트를 수신
### 3.2. Lambda가 detail 을 파싱하여 다음 정보를 추출
- userArn 
- accessKey ID 
- source IP 
- region 
- userAgent

### 3.3. 스키마대로 payload 생성

### 3.4. Incident Table(DynamoDB) 에 기록

### 3.5. payload를 WebSocket 연결 전체에 브로드캐스트

### 3.6. 대시보드에서 실시간 표시

---
## 4. 환경 변수 (Environment Variables) 
| Key                   | Value                                                                                                                      | 설명                                     |
| --------------------- | -------------------------------------------------------------------------------------------------------------------------- | -------------------------------------- |
| **CONNECTIONS_TABLE** | WebSocketConnections_v2                                                                                                    | 현재 WebSocket에 접속중인 connectionId 목록 테이블 |
| **INCIDENT_TABLE**    | Incident                                                                                                                   | 보안 이벤트 이력을 저장하는 DynamoDB 테이블           |
| **REGION**            | us-east-1                                                                                                                  | Lambda 기본 실행 리전                        |
| **STATE_TABLE**       | security-alerts-state                                                                                                      | 상태 데이터 저장하는 DynamoDB 테이블               |
| **WS_ENDPOINT**       | [https://egtwu3mkhb.execute-api.us-east-1.amazonaws.com/prod](https://egtwu3mkhb.execute-api.us-east-1.amazonaws.com/prod) | WebSocket API 엔드포인트                    |

---
## 5. 사용 리소스 및 의존성 (Resources & Dependencies) 
### 5.1. AWS 리소스
- EventBridge Rule 
- Lambda Function 
- DynamoDB 
  - WebSocketConnections_v2 
  - Incident 
  - security-alerts-state 
- API Gateway WebSocket 
- CloudTrail

### 5.2. Python dependency
- boto3 
- botocore 
- urllib 
- json, re, time, datetime

---
## 6. IAM 권한 (IAM Permissions)
### 6.1. WebSocket 연결 전송 권한
- execute-api:ManageConnections
- WebSocket으로 메시지를 보내기 위해 필요함

### 6.2. WebSocketConnections_v2 테이블 권한
- dynamodb:Scan, dynamodb:GetItem, dynamodb:DeleteItem
- 끊긴 stale connection 삭제 및 connectionId 조회

### 6.3. Incident 테이블 권한
- dynamodb:PutItem, dynamodb:UpdateItem, dynamodb:GetItem
- Incident 기록 저장 및 업데이트

### 6.4. Lambda 기본 로그 권한
- logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents

### 6.5. DynamoDB Full Access (필요한 경우)
- AmazonDynamoDBFullAccess_v2
---
## 7. 한계 및 향후 과제 (Limitations & TODO)
| 한계                                 | 향후 과제                                        |
| ---------------------------------- | -------------------------------------------- |
| WebSocket 연결이 많아지면 Broadcast 비용 증가 | SQS 또는 EventBridge Pipe 기반 비동기 처리로 개선        |
| Access Key 생성만 탐지                  | DeleteAccessKey, IAM Policy 변경 등 추가 이벤트 확장   |
| Incident 테이블 구조 단순                 | Incident → Events 관계형 스키마(Timeseries 구조)로 확장 |
| geoip 외부 API 의존                    | VPC 엔드포인트 기반 GeoIP DB 로컬 캐싱 고려               |


