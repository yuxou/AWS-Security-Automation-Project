## 1. 함수 개요 (Overview)
이 Lambda 함수는 CloudTrail 기반 **MFA 관련 이벤트(등록/비활성화/우회 포함)**를 실시간으로 분석하여 아래 작업을 수행한다.
1. MFA 등록/비활성화/우회 시도/완료/실패 감지
2. 중복 알림 자동 억제 (DeactivateMFADevice → suppress)
3. 정규화된 payload 생성
4. WebSocket 대시보드에 실시간 알림 전송
5. Incident 테이블에 인시던트 생성(meta 기반 저장)

주요 기능:
- 본 모듈은 보안 계정의 MFA 설정 변경을 고도화하여 감지하며,
actor / target 사용자 정보, IP, userAgent(디바이스 정보), ConsoleLogin 결과 등 모든 MFA 관련 메타데이터를 incident.meta에 저장한다.

---
## 2. 동작 조건 & 트리거 (Conditions & Trigger)
### 이벤트 소스
EventBridge(CloudTrail 기반)

### 처리 대상 이벤트
| 구분              | 이벤트(eventName)         | 설명                                        |
| --------------- | ---------------------- | ----------------------------------------- |
| **MFA 등록**      | CreateVirtualMFADevice | 새로운 Virtual MFA 장치 생성 (등록 시도)             |
| **MFA 등록**      | AssociateSoftwareToken | MFA 소프트웨어 토큰 연결(등록 시도)                    |
| **MFA 등록 완료**   | EnableMFADevice        | MFA 장치 활성화 완료                             |
| **MFA 비활성화 억제** | DeactivateMFADevice    | MFA 비활성화 시도(전송 억제: 중복 오탐 방지)              |
| **MFA 비활성화**    | DeleteVirtualMFADevice | MFA 장치 삭제(비활성화 완료로 판단)                    |
| **MFA 우회/로그인**  | ConsoleLogin           | ConsoleLogin 성공 + MFAUsed=No → MFA 우회로 처리 |

### 특수 정책
- DeactivateMFADevice는 중복/오탐 방지를 위해 전송 억제(suppress)
- DeleteVirtualMFADevice만 실제 비활성화 이벤트로 처리
- ConsoleLogin + MFAUsed = “No” → MFA 우회로 처리

---
## 3. 처리 로직 요약 (Logic Flow)
### 1. EventBridge → Lambda로 CloudTrail 이벤트 수신
### 2. 이벤트 분석
   - eventName, eventSource
   - userIdentity
   - additionalEventData.MFAUsed
   - errorCode
   - responseElements.ConsoleLogin
   - userAgent → 디바이스 정보 생성
   - sourceIPAddress → meta.ip 저장
### 3. MFA 이벤트 유형/상태 자동 분류
   - “시도/완료/실패”
   - “MFA 새로운 등록”, “MFA 비활성화”, “MFA 우회”
   - severity 자동 계산
### 4. Payload 생성
   - resource 통일 규칙 적용
   - arn 규칙 적용
   - meta에 actor / target / status / api / mfaUsed / consoleOutcome / device / ip 저장
### 5. Incident 테이블 저장
   - incident.details 대신 meta에만 저장(요구사항 동일)
   - timestamp 기반 incident_id 생성 (inc-YYYYMMDD-HHMMSS-XYZ)
### 6. WebSocket 브로드캐스트
   - DynamoDB 스캔 → 모든 연결 클라이언트로 push
   - stale connection 자동 삭제

---
## 4. 환경 변수 (Environment Variables)
| 이름                | 예시                                                      | 설명                       |
| ----------------- | ------------------------------------------------------- | ------------------------ |
| CONNECTIONS_TABLE | `WebSocketConnections_V2`                          | WebSocket 연결 ID 저장       |
| WS_ENDPOINT       | `https://egtwu3mkhb.execute-api.us-east-1.amazonaws.com/prod` | WebSocket APIGW endpoint |
| INCIDENT_TABLE    | `Incident`                                              | 인시던트 저장 테이블              |



---
## 5. 사용 리소스 / 의존성 (Dependencies)
### AWS 리소스
   - DynamoDB
     - CONNECTIONS_TABLE (WebSocket 연결 ID 저장)
     - INCIDENT_TABLE (Incident 저장)
   - API Gateway WebSocket
     - post_to_connection() 사용
   - CloudTrail + EventBridge
### Python 패키지
   - boto3
   - botocore
   - 표준 라이브러리: re, os, json, datetime, random 등

---
## 6. 필요한 IAM 권한 (Required IAM Permissions)
### 1. DynamoDB 권한
#### 1.1 `WebSocketConnections_V2`
   - "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Scan", "dynamodb:DeleteItem"
#### 1.2 `Incident`
   - "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Scan", "dynamodb:DeleteItem"
### 2. API Gateway WebSocket 연결 관리 권한
   - execute-api:ManageConnections
   - Resource : arn:aws:execute-api:us-east-1:*:egtwu3mkhb/prod/POST/@connections/*
   - WebSocket 대시보드에 실시간 이벤트 push, 연결이 죽은 클라이언트 자동 삭제

---
## 7. 한계 & TODO (Limitations / TODO)
   - DeactivateMFADevice suppress 정책은 운영 정책에 따라 조정 필요
   - target 계정/사용자의 serialNumber parameter가 누락된 이벤트가 존재할 수 있음
   - Device Fingerprint 고도화 가능
   - MFA 재등록 과정의 연속 이벤트를 세션 단위로 그룹핑하는 기능 추가 가능
