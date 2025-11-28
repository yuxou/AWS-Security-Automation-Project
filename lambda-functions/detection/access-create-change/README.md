## 1. 함수 개요 (Overview)
이 Lambda 함수는 CloudTrail 기반 IAM 이벤트(비밀번호 변경, 액세스 키 조작, MFA 비활성화, 정책 수정 등)를 EventBridge로 전달받아 다음 역할을 수행합니다.

주요 기능:
1. CloudTrail IAM 이벤트 분석 및 정규화
2. Severity 산정 (CRITICAL/HIGH/MEDIUM/LOW)
3. 대상 리소스(유저/키/디바이스 등) 자동 식별
4. 디바이스·IP·액세스 키 상세정보 meta 자동 생성
5. Incident 테이블에 인시던트 자동 생성
6. WebSocket 연결된 모든 대시보드로 실시간 알림 전송 (broadcast)
이 Lambda는 AWS IAM 보안 관련 이벤트의 “감지 → 구조화 → 저장 → 실시간 전송”을 통합 처리하는 핵심 보안 관제 모듈입니다.

---
## 2. 동작 조건 & 트리거 (Conditions & Trigger)
### 이벤트 소스
- AWS EventBridge
- CloudTrail → IAM 관리 이벤트 (Management Events)

### 처리 대상 이벤트
아래와 같은 CloudTrail IAM 이벤트를 처리합니다.
| 구분              | 이벤트                                                                           | 설명                 |
| --------------- | ----------------------------------------------------------------------------- | ------------------ |
| 액세스 키 조작        | CreateAccessKey / UpdateAccessKey / DeleteAccessKey                           | 자격 증명 위험도 높음       |
| MFA 조작          | EnableMFADevice / DeactivateMFADevice / DeleteVirtualMFADevice                | 접근 보안에 직접적 영향      |
| 비밀번호 조작         | CreateLoginProfile / UpdateLoginProfile / ChangePassword                      | 콘솔 계정 보안 관련        |
| SSH/Signing Key | UploadSSHPublicKey / UpdateSSHPublicKey / DeleteSSHPublicKey / SigningCert 관련 | Git/CodeCommit/인증서 |
| IAM 사용자/정책      | CreateUser / DeleteUser / AttachUserPolicy / PutUserPolicy 등                  | 계정 권한 변경           |
### 예외 처리
- CreateAccessKey 이벤트는 이 Lambda에서는 Incident 생성 및 알림을 수행하지 않으며, 단순히 "skipped" 처리합니다.

---
## 3. 처리 로직 요약 (Logic Flow)
### 1. EventBridge → Lambda 호출
CloudTrail IAM 이벤트 detail 을 수신합니다.
### 2. Timestamp 변환
ISO8601 → epoch(ms) 변환
```python
epoch_ms_from_iso(detail.get("eventTime"))
```
### 3. Source, Event Type 정규화
- CloudTrail service → 사람이 읽기 쉬운 서비스명 변환
- eventName → 한글 타입(EX: “액세스 키 생성”) 매핑
### 4. Severity 산정
다음 기준으로 위험도 판단:
- 루트 계정 관련 조작 → HIGH/CRITICAL
- MFA 비활성화, 비밀번호 변경, 액세스 키 조작 → HIGH/CRITICAL
- 정책 변경(Update/Delete) → MEDIUM/HIGH
- 일반 IAM 변경 → MEDIUM
- 그 외 → LOW
### 5. 대상 리소스 파싱
예:
- accessKeyId
- 사용자(userName)
- MFA 디바이스(serialNumber)
- SSH key / signing certificate
- eventID fallback
### 6. meta 데이터 구성
meta에는 다음 구조가 포함됩니다.
| 필드        | 설명                                               |
| --------- | ------------------------------------------------ |
| device    | OS/브라우저 정보 summary + 원본 UA                       |
| ip        | sourceIPAddress                                  |
| api       | CloudTrail eventName                             |
| accessKey | 액세스 키 조작 시 상세 정보(owner, access_key_id, status 등) |
### 7. Incident 자동 생성
Incident 테이블에 다음 정보 저장:
- incident_id (inc-YYYYMMDD-HHMMSS-XYZ)
- event_type
- resource
- severity
- status=NEW
- meta (디바이스 + IP + 액세스키 정보)
- source/account/region
- created_at / updated_at
### 8. WebSocket Broadcast
현재 연결된 모든 WebSocket 클라이언트에 실시간 알림 전송
```python
apigw.post_to_connection(ConnectionId=cid, Data=json.dumps(payload))
```
끊어진 연결은 자동으로 DynamoDB에서 제거합니다.

---
## 4. 환경 변수 (Environment Variables)
| 이름                | 예시                                | 설명                                |
| ----------------- | --------------------------------- | --------------------------------- |
| CONNECTIONS_TABLE | `IamEventWebSocketConnections`    | 실시간 WebSocket 연결 저장 테이블           |
| WS_ENDPOINT       | `https://xxx.execute-api.../prod` | WebSocket Management API endpoint |
| INCIDENT_TABLE    | `Incident`                        | 인시던트 저장 DynamoDB 테이블              |
| (추가 없음)           | -                                 | meta 구성은 CloudTrail detail 기반     |

---
## 5. 사용 리소스 / 의존성 (Dependencies)
### AWS 리소스
   - DynamoDB
      - CONNECTIONS_TABLE
      - INCIDENT_TABLE
   - API Gateway (WebSocket Management API)
   - CloudWatch Logs
### Python 패키지
   - boto3, botocore
   - datetime, time
   - ipaddress
   - random
   - json

---
## 6. 필요한 IAM 권한 (Required IAM Permissions)
이 Lambda가 정상 동작하려면 다음 권한이 반드시 필요합니다.
### 1. DynamoDB 권한
- dynamodb:Scan
- dynamodb:PutItem
- dynamodb:UpdateItem
- dynamodb:DeleteItem
### 2. API Gateway WebSocket 권한
- execute-api:ManageConnections
### 3. CloudWatch Logs 권한
- AWSLambdaBasicExecutionRole

---
## 7. 한계 & TODO (Limitations / TODO)
### 한계
- IAM 이벤트가 매우 많은 경우 Broadcast 비용이 증가할 수 있습니다.
- Severity 규칙은 커스텀 로직이므로 조직 정책에 따라 확장 필요합니다.
- meta 필드는 원본 UA 기반 heuristic이므로 완전 정확하지 않을 수 있습니다.
### TODO
- IAM Role 변경/Trust Policy 변경 감지 로직 추가
- Advanced GeoIP / User Behavior Analytics 연계
- 정책 기반 Severity 가중치 적용
- Incident Playbook 자동 대응 연동 (권한 회수, 키 비활성화 등)
