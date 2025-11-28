## 1. 함수 개요 (Overview)
이 Lambda 함수는 사용자가 평소 사용하지 않던 AWS 리전에서 중요한 리소스(Ec2/S3/IAM 등)에 접근하는 경우 이를 감지하여 알림을 보내는 역할을 한다.
- CloudTrail API 이벤트 감지 
- 사용자별 baseline 리전 목록 관리 
- 새 리전 접근 시 DynamoDB 업데이트 
- WebSocket 클라이언트 전체에 브로드캐스트

---
## 2. 동작 조건 & 트리거 (Conditions & Trigger)
| 조건                                                  | 설명                                       |
| --------------------------------------------------- | ---------------------------------------- |
| **source = aws.ec2, aws.s3, aws.iam, aws.lambda 등** | 중요한 AWS 서비스에서 발생한 API 호출                 |
| **detail-type = AWS API Call via CloudTrail**       | CloudTrail 관리 이벤트                        |
| **eventName = StartInstances, CreateBucket 등**      | 중요 API 호출일 때만 감지 (코드 내 IMPORTANT 리스트 기준) |

---
## 3. 처리 로직 (Logic) 
### 1. CloudTrail 이벤트 수신 : eventSource, eventName, 사용자 ARN(principal), region 추출
### 2. 중요 서비스인지 확인 : EC2/S3/IAM/Lambda/RDS/EKS 만 대상으로 함
### 3. 사용자별 baseline 리전 목록 조회 : DynamoDB에서 baseline_regions#{사용자ARN} 키 조회
### 4. 처음 보는 리전이면 baseline 업데이트 
- 새 리전 baseline에 추가
- TTL 30일 설정
### 5. 대시보드(WebSocket)에 알림 브로드캐스트
    ```{
    "alert_type": "unusual_region_access",
    "principal": "<사용자 ARN>",
    "region": "ap-south-1",
    "event": "StartInstances",
    "source": "ec2.amazonaws.com",
    "baseline_regions": ["us-east-1", "ap-south-1"],
    "time": "UTC timestamp"
    }
    ```
---
## 4. 환경 변수 (Environment Variables) 
| Key             | 예시 값                                                        | 설명                                 |
| --------------- |-------------------------------------------------------------| ---------------------------------- |
| **AWS_REGION**  | us-east-1                                                   | Lambda 실행 리전 (기본값 us-east-1)       |
| **WS_ENDPOINT** | http://egtwu3mkhb.execute-api.us-east-1.amazonaws.com/prod/ | WebSocket API Gateway Endpoint     |
| **TABLE_NAME**  | WebSocketConnections_v2                                     | WebSocket 연결 목록 저장 DynamoDB 테이블 이름 |

---
## 5. 사용 리소스 및 의존성 (Resources & Dependencies) 
| 리소스                                        | 용도                                                      |
| ------------------------------------------ | ------------------------------------------------------- |
| **DynamoDB — WebSocketConnections**        | 현재 연결된 WebSocket 클라이언트 목록 관리                            |
| **DynamoDB — same table 사용하여 baseline 저장** | 사용자별 baseline 리전 목록 저장 (키: connectionId → baseline key) |
| **API Gateway WebSocket**                  | Dashboard 알림 실시간 전송                                     |
| **CloudTrail**                             | API 호출 감지                                               |

---
## 6. IAM 권한 (IAM Permissions)
### 1. DynamoDB 접근
- GetItem 
- PutItem 
- UpdateItem 
- DeleteItem 
- Scan

### 2. WebSocket 연결 관리 
- execute-api:ManageConnections arn:aws:execute-api:us-east-1:*:*/prod/POST/@connections/*

### 3. CloudWatch Logs
- logs:CreateLogGroup 
- logs:CreateLogStream 
- logs:PutLogEvents

---
## 7. 한계 및 향후 과제 (Limitations & TODO)
| 한계                                             | 향후 과제                               |
| ---------------------------------------------- | ----------------------------------- |
| baseline을 WebSocketConnections 테이블에 저장 (이름 혼용) | baseline용 별도 테이블 분리 필요              |
| 중요 서비스 리스트가 코드 내부에 고정                          | 환경 변수 또는 외부 설정파일로 확장 가능             |
| 첫 탐지 시마다 알림 1회만 발송                             | 지속적/반복된 비정상 리전 접근 탐지 기능 추가          |
| IAM ARN 외 추가 정보 없음                             | IP, Device, MFA 여부 등 추가 메타데이터 포함 가능 |



