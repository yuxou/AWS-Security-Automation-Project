## 1. 함수 개요 (Overview)
이 Lambda 함수는 AWS ConsoleLogin 및 GuardDuty 보안 이벤트를 실시간 감지하여,
다음 작업을 자동으로 수행한다.
1. 새로운 디바이스 접근 탐지 (디바이스 지문 기반)
2. WebSocket 브로드캐스트 전송
3. Incident 테이블에 보안 이벤트 저장
4. KnownDevices 테이블에 fingerprint 누적

주요 기능:
- User-Agent + IP 조합을 기반으로 한 기기 지문(fingerprint) 생성
- CloudTrail detail 기반 principal 표시 정규화
- 프런트엔드가 즉시 사용할 수 있는 meta 구조(JSON 객체)
- GuardDuty 이벤트 별도 처리 (severity 포함)
- handler.py 와 동일한 리소스 표기 규칙 적용

---
## 2. 동작 조건 & 트리거 (Conditions & Trigger)
### 이벤트 소스
EventBridge(CloudTrail 기반)

### 처리 대상 이벤트
| 구분                | 이벤트             | 설명              |
| ----------------- | --------------- | --------------- |
| ConsoleLogin      | AWS SignIn/STS  | 새로운 디바이스 접근 탐지  |
| GuardDuty Finding | aws.guardduty.* | GuardDuty 위협 탐지 |

### 동작 조건
- UA_ONLY
- UA_IP_PREFIX24
- UA_IP 지문은 FINGERPRINT_MODE 환경변수로 결정됨.
지문이 KnownDevices 테이블에 없으면 → 새로운 디바이스로 판정.

---
## 3. 처리 로직 요약 (Logic Flow)
### 1. EventBridge → Lambda로 CloudTrail 이벤트 수신
### 2. event.detail에서 다음 항목 추출
   - userIdentity(type/principal/user)
   - userAgent → 디바이스 정규화
   - sourceIPAddress → IP / prefix24
### 3. fingerprint(userAgent, IP) 생성
### 4. KnownDevices 테이블 조회
   - Fingerprint 존재 → known device → 종료
   - Fingerprint 없음 → 신규 디바이스
### 5. 신규 디바이스 시
   - payload 생성
   - Incident 테이블에 저장
   - WebSocket broadcast
   - Fingerprint KnownDevices 테이블에 저장
### 6. GuardDuty 이벤트 발생 시
   - GuardDuty용 payload 생성
   - Incident 테이블 저장
   - WebSocket 브로드캐스트

---
## 4. 환경 변수 (Environment Variables)
| 이름                | 예시                                                                                                                     | 설명                        |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------- | ------------------------- |
| CONNECTIONS_TABLE | `WebSocketConnections_V2`                                                                                                   | WebSocket 연결 목록 저장        |
| KNOWN_DEV_TABLE   | `KnownDevices`                                                                                                           | 디바이스 fingerprint 저장       |
| WS_ENDPOINT       | `https://egtwu3mkhb.execute-api.us-east-1.amazonaws.com/prod` | WebSocket API Gateway URL |
| INCIDENT_TABLE    | `Incident `                                                                                                              | 인시던트 저장 DynamoDB          |
| FINGERPRINT_MODE  | `UA_ONLY / UA_IP / UA_IP_PREFIX24`                                                                                       | 디바이스 지문 생성 모드             |


---
## 5. 사용 리소스 / 의존성 (Dependencies)
### AWS 리소스
   - DynamoDB
     - KNOWN_DEV_TABLE (디바이스 fingerprint 저장)
     - CONNECTIONS_TABLE (WebSocket 연결 ID 저장)
     - INCIDENT_TABLE (Incident 저장)
   - API Gateway WebSocket
     - post_to_connection() 사용
   - CloudTrail + EventBridge
### Python 패키지
   - boto3
   - botocore
   - ipaddress
   - hashlib
   - datetime, time, random
   - os, json

---
## 6. 필요한 IAM 권한 (Required IAM Permissions)
### 1. DynamoDB 권한
#### 1.1 `KnownDevices`
   - "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Scan", "dynamodb:DeleteItem"
#### 1.2 `WebSocketConnections_V2`
   - "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Scan", "dynamodb:DeleteItem"
#### 1.3 `Incident`
   - "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Scan", "dynamodb:DeleteItem"
### 2. API Gateway WebSocket 연결 관리 권한
   - execute-api:ManageConnections
   - Resource : arn:aws:execute-api:us-east-1:*:egtwu3mkhb/prod/POST/@connections/*
   - WebSocket 대시보드에 실시간 이벤트 push, 연결이 죽은 클라이언트 자동 삭제

---
## 7. 한계 & TODO (Limitations / TODO)
   - User-Agent 기반 fingerprint는 100% 정확하지 않음
   - Private IP, VPN 환경에서는 신규 탐지가 제한적
   - GuardDuty event meta는 원본 service 객체이므로 크기가 클 수 있음
   - TODO
     - GeoIP 확장
     - Device session 관리 기능
     - Web Dashboard 알림 딥링크 연결
     - Incident 후속조치 자동화
