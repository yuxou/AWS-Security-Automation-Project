## 1. 함수 개요 (Overview)
이 Lambda 함수는 AWS ConsoleLogin / AssumeRole 이벤트 중
**“이 계정·Principal에서 처음 등장한 IP인지”**를 자동으로 탐지하고,
새로운 IP일 경우:
1. 대시보드(WebSocket)에 알림 전송
2. Incident 테이블에 인시던트 생성
3. KnownIp(KNOWN_TABLE)에 해당 IP를 등록 및 lastSeen 갱신
까지 수행하는 보안 이벤트 자동 대응 모듈이다.

주요 기능:
[예: CloudTrail 기반 이벤트 분석]
[예: 새로운 IP 로그인 탐지]
[예: Incident 기록 생성]
[예: WebSocket 브로드캐스트]

---
## 2. 동작 조건 & 트리거 (Conditions & Trigger)
### 이벤트 소스
EventBridge(CloudTrail 기반)

### 처리 대상 이벤트
다음 두 가지 이벤트 외에는 모두 무시한다.
| eventSource          | eventName    | 설명        |
| -------------------- | ------------ | --------- |
| `signin.amazonaws.com` | `ConsoleLogin` | 콘솔 로그인 시도 |
| `sts.amazonaws.com`    | `AssumeRole`   | STS 역할 전환 |

### 동작 조건
- sourceIPAddress가 AllowList에 없고
- 지정된 SCOPE(principal/account/global)에 대해 
KnownIp 테이블에 처음 등장한 IP일 경우
→ “새로운 IP”로 판정 후 WebSocket 및 Incident 처리 수행.

---
## 3. 처리 로직 요약 (Logic Flow)
### 1. EventBridge → Lambda로 CloudTrail 이벤트 수신
### 2. event.detail에서 다음 항목 추출
   - principal 정보
   - eventName / eventSource
   - sourceIPAddress
   - userAgent (디바이스 정보 생성용)
### 3. AllowList 또는 기존 등록된 IP인지 KnownIp 테이블에서 검사
### 4. 새로운 IP일 경우
   - payload 생성 (resource, severity, principal, meta.ip 등 포함)
   - Incident 테이블에 인시던트 저장
     - meta 필드에 device(OS|browser) + userAgent + IP 저장
   - WebSocketConnections 테이블 스캔 후 연결된 클라이언트에 브로드캐스트
### 5. 기존 IP일 경우
   - lastSeen 업데이트 후 종료

---
## 4. 환경 변수 (Environment Variables)
| 이름                | 예시                                                                                                                       | 설명                      |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------ | ----------------------- |
| CONNECTIONS_TABLE | `WebSocketConnections_v2`                                                                                                     | WebSocket 연결 목록 저장      |
| WS_ENDPOINT       | `https://egtwu3mkhb.execute-api.us-east-1.amazonaws.com/prod` | WebSocket APIGW 주소      |
| KNOWN_TABLE       | `KnownIps`                                                                                                                 | 신규 IP 기록 테이블            |
| WINDOW_DAYS       | `30`                                                                                                                       | IP TTL 및 lastSeen 유지 기간 |
| ALLOW_CIDRS       | `10.0.0.0/8, 192.168.0.0/16`                                                                                               | 허용된 IP 대역               |
| SCOPE             | `principal / account / global`                                                                                             | 신규 IP 판단 단위             |
| INCIDENT_TABLE    | `Incident`                                                                                                                 | 인시던트 히스토리 저장            |

---
## 5. 사용 리소스 / 의존성 (Dependencies)
### AWS 리소스
   - DynamoDB
     - KNOWN_TABLE (신규/최근 IP 기록)
     - CONNECTIONS_TABLE (WebSocket 연결 ID 저장)
     - INCIDENT_TABLE (Incident 저장)
   - API Gateway WebSocket
     - post_to_connection 사용
### Python 패키지
   - boto3
   - botocore
   - 표준 라이브러리: os, json, time, datetime, hashlib, random, ipaddress 등

---
## 6. 필요한 IAM 권한 (Required IAM Permissions)
### 1. DynamoDB 권한
#### 1.1 `KnownIps`
   - "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Scan"
#### 1.2 `WebSocketConnections_V2`
   - "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Scan"
#### 1.3 `Incident`
   - "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Scan"
### 2. API Gateway WebSocket 연결 관리 권한
   - execute-api:ManageConnections
   - Resource : arn:aws:execute-api:us-east-1:*:egtwu3mkhb/prod/POST/@connections/*
   - WebSocket 대시보드에 실시간 이벤트 push, 연결이 죽은 클라이언트 자동 삭제

---
## 7. 한계 & TODO (Limitations / TODO)
   - sourceIPAddress가 Private IP·Proxy 기반일 경우 신규 탐지 정확도가 낮아질 수 있음
   - GeoIP 기반 판단은 기능적으로 포함되지 않음
   - Known TABLE의 TTL 메커니즘에 따라 오래된 IP가 자동 삭제됨
   - TODO
     - GeoIP 단위 탐지 확장
     - Device Fingerprint 고도화
     - Web Dashboard 알림 딥링크 연결
     - Incident 후속 조치 자동화 (예: IAM session revoke)
