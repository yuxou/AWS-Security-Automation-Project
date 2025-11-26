## 1. 함수 개요 (Overview)
이 Lambda 함수는 AWS 콘솔 로그인 실패 이벤트를 집계하여 3회 이상 실패 시 10분간 해당 사용자 콘솔 접근을 차단하고, 잠금/해제 진행 상황을 WebSocket으로 브로드캐스트하며, 선택적으로 Incident 테이블에 상태를 기록/갱신합니다. 잠금 해제는 EventBridge Scheduler가 지정 시각에 동일 람다를 호출하여 수행합니다.

주요 기능:
- 실패 횟수 카운팅 및 TTL 관리(집계 윈도우)
- 임계 도달 시 IAM Inline Policy(DenyAll) 부착, 옵션으로 LoginProfile 삭제(콘솔 로그인 자체 봉쇄)
    - IAM Inline Policy(DenyAll) 부착으로 권한 차단
    - 옵션: LoginProfile 삭제로 콘솔 로그인 자체 차단
    - (주석 형태) 액세스 키 비활성화 루틴 포함
- 10분 후 잠금 해제 스케줄 생성
- WebSocket 브로드캐스트 및 Incident 연동(생성/갱신)
- Incident 연동: 인자로 넘어온 incident_id가 있으면 해당 레코드 상태 업데이트, 없으면 자동 생성 가능(플레이북 결과 기반)

---
## 2. 동작 조건 & 트리거 (Conditions & Trigger)
### 이벤트 소스
EventBridge(CloudTrail 기반)

### 처리 대상 이벤트
| eventSource            | eventName      | 조건/설명                                                      |   |
| ---------------------- | -------------- | ---------------------------------------------------------- | - |
| `signin.amazonaws.com` | `ConsoleLogin` | `responseElements.ConsoleLogin == "Failure"` 인 이벤트만 실패로 집계 |   |


### 해제 트리거
- EventBridge Scheduler가 mode=unlock 입력으로 동일 Lambda 호출 → 잠금 해제 수행

---
## 3. 처리 로직 요약 (Logic Flow)
### 1. 실패 이벤트 수신 → parse_console_login_failure()로 account/region/userType/userName/userArn/success 추출
### 2. 성공 이벤트는 스킵(집계 대상 아님)
### 3. 카운터 증가: COUNTER_TABLE에 count 증가 및 TTL(집계 윈도우) 갱신 → inc_failure_and_get_count()
### 4. 기존 잠금 여부 확인: is_locked()가 참이면 플레이북 스킵
### 5. count ≥ 3 → run_playbook_lock_signin_10m() 실행
- Inline Policy 부착(iam:PutUserPolicy)
- 설정에 따라 LoginProfile 삭제(LOCK_CONSOLE_BY_LOGINPROFILE=true)
- 잠금 레코드 저장(put_lock) 및 해제 스케줄 생성(schedule_unlock_once)
- 상태 브로드캐스트: TRIGGERED → RUNNING → SUCCEEDED/FAILED
- Incident 생성/갱신(update_incident_for_action)
### 6. 해제 호출(mode=unlock) → Inline Policy 제거, Incident 갱신, 상태 브로드캐스트 수행

---
## 4. 환경 변수 (Environment Variables)
| 이름                             | 예시                                                                    | 설명                                 |   |
| ------------------------------ | --------------------------------------------------------------------- | ---------------------------------- | - |
| `CONNECTIONS_TABLE`            | `WebSocketConnections`                                                | WebSocket 연결 ID 저장 테이블             |   |
| `WS_ENDPOINT`                  | `https://…execute-api.ap-northeast-2.amazonaws.com/prod/@connections` | API GW Management 엔드포인트            |   |
| `COUNTER_TABLE`                | `FailedLogins`                                                        | 실패 횟수·잠금 정보 저장 테이블                 |   |
| `WINDOW_MIN`                   | `15`                                                                  | 집계 윈도우(분) → 카운터 TTL에 사용            |   |
| `LOCK_MIN`                     | `10`                                                                  | 잠금 유지 시간(분)                        |   |
| `POLICY_NAME`                  | `auto-temp-total-deny`                                                | 임시 차단용 사용자 인라인 정책명                 |   |
| `LOCK_CONSOLE_BY_LOGINPROFILE` | `true/false`                                                          | `true`면 LoginProfile 삭제(콘솔 로그인 봉쇄) |   |
| `INCIDENT_TABLE`               | `Incident`                                                            | 인시던트 기록 테이블(선택)                    |   |
| `SCHEDULER_REGION`             | `us-east-1`                                                           | EventBridge Scheduler 리전           |   |
| `SCHEDULER_ROLE_ARN`           | `arn:aws:iam::…:role/...`                                             | Scheduler가 Lambda 호출 시 사용할 역할      |   |
| `THIS_LAMBDA_ARN`              | `arn:aws:lambda:…:function:FailedLogins`                              | 스케줄 타깃 Lambda ARN                  |   |

---
## 5. 사용 리소스 / 의존성 (Dependencies)
### AWS 리소스
   - DynamoDB
     - CONNECTIONS_TABLE (WebSocket 연결 ID 저장)
     - INCIDENT_TABLE (Incident 저장)
     - COUNTER_TABLE (count/lastSeen/ttl 및 lockUntil 저장)
   - API Gateway WebSocket
     - post_to_connection() 사용
   - CloudTrail + EventBridge
   - EventBridge Scheduler: 잠금 해제 예약(단발 at(...)) 호출 타깃 = 본 Lambda
### Python 패키지
   - 표준: os, json, time, random, datetime, traceback
   - AWS SDK: boto3, botocore.exceptions.ClientError

---
## 6. 필요한 IAM 권한 (Required IAM Permissions)
### 1. DynamoDB 권한
#### 1.1 `WebSocketConnections_V2`
   - "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Scan", "dynamodb:DeleteItem"
#### 1.2 `Incident`
   - "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Scan", "dynamodb:DeleteItem"
#### 1.3 `FailedLogins`
   - "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Scan", "dynamodb:DeleteItem"
### 2. API Gateway WebSocket 연결 관리 권한
   - "execute-api:ManageConnections"
   - Resource : "arn:aws:execute-api:us-east-1:*:egtwu3mkhb/prod/POST/@connections/*"
   - WebSocket 대시보드에 실시간 이벤트 push, 연결이 죽은 클라이언트 자동 삭제
### 3. ACCOUNT_ID:user 관리 권한
   - "iam:PutUserPolicy","iam:DeleteUserPolicy", "iam:DeleteLoginProfile", "iam:ListAccessKeys", "iam:UpdateAccessKey"
   - Resource : "arn:aws:iam::ACCOUNT_ID:user/*"
   - 임계 도달 시 IAM Inline Policy옵션으로 권한이나 비밀번호 수정
### 3. ACCOUNT_ID:schedule 관리 권한
   - "scheduler:CreateSchedule"
   - Resource : "arn:aws:scheduler:*:ACCOUNT_ID:schedule/*"
   - 10분 후 잠금 해제 스케줄 생성

---
## 7. 한계 & TODO (Limitations / TODO)
   - 본 플레이북은 콘솔 로그인 실패에만 반응(프로그램 접근, 네트워크 차단은 범위 외)
   - LoginProfile 삭제 옵션 사용 시 운영 정책에 유의(해제 전 콘솔 로그인 불가)
   - Scheduler 리전/역할/타깃 ARN 불일치 시 스케줄 생성 실패
   - TODO
       - 사용자/조직 정책에 따른 잠금 강도(권한차단 vs 로그인봉쇄) 프로파일화
       - 잠금 중 재시도 이벤트에 대한 알림 빈도 제어
       - 다계정/다리전 운영 템플릿 제공
