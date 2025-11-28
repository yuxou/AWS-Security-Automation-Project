## 1. 함수 개요 (Overview)
이 Lambda 함수는 WebSocket 연결이 유휴 상태(Idle)일 때 API Gateway에 의해 자동으로 연결이 종료되는 것을 방지하기 위한 **Keep-Alive(Heartbeat) 시스템**임
* **주요 기능:** 등록된 3개의 WebSocket 채널(이벤트, 대응, 이력)에 주기적으로 Ping 메시지를 전송함
* **자동 관리:** Ping 전송 실패 시(이미 끊긴 연결, 410 Gone), 해당 연결 정보를 DynamoDB 테이블에서 자동으로 삭제하여 좀비 세션을 정리함

---

## 2. 동작 조건 및 트리거 (Conditions & Trigger)
* **트리거 소스:** Amazon EventBridge (Scheduled Event)
* **실행 주기:** WebSocket의 유휴 타임아웃(기본 10분)보다 짧은 주기로 실행 권장 
* **대상 채널:**
    1. **Event Channel:** 보안 위협 알림용
    2. **Remediation Channel:** 자동 조치 현황용
    3. **History Channel:** 인시던트 이력용

---

## 3. 처리 로직 (Logic)
함수는 세 가지 채널에 대해 순차적으로 다음 로직을 반복 수행함

1. **연결 목록 조회:** 각 채널별 DynamoDB 테이블(`Scan`)을 조회하여 활성 `connectionId` 목록을 가져옴
2. **Ping 메시지 전송:**
    * 각 클라이언트에게 `{"type": "ping", "timestamp": 1234567890}` 포맷의 메시지를 전송함
3. **연결 상태 관리 (Self-Healing):**
    * 전송 중 `GoneException`(410) 오류가 발생하면, 해당 클라이언트가 이미 연결을 종료한 것으로 판단함
    * 즉시 DynamoDB 테이블에서 해당 `connectionId`를 삭제하여 테이블을 최신 상태로 유지함
4. **결과 리턴:** 각 채널별로 Ping 성공 횟수를 집계하여 반환함

---

## 4. 환경 변수 (Environment Variables)

| 변수명 | 값 | 설명 |
| :--- | :--- | :--- |
| EVENT_API_GW_ENDPOINT | egtwu3mkhb.execute-api.us-east-1.amazonaws.com/prod/ | 보안 이벤트 채널 WebSocket 엔드포인트 |
| EVENT_CONNECTIONS_TABLE | WebSocketConnections_v2 | 보안 이벤트 채널 연결 정보 테이블 |
| REMED_API_GW_ENDPOINT | 3y9ayspfp3.execute-api.us-east-1.amazonaws.com/prod/ | 자동 조치 채널 WebSocket 엔드포인트 |
| REMED_CONNECTIONS_TABLE | RemediationWebSocketConnections | 자동 조치 채널 연결 정보 테이블 |
| HISTORY_API_GW_ENDPOINT | kote8jrryb.execute-api.us-east-1.amazonaws.com/prod/ | 인시던트 이력 채널 WebSocket 엔드포인트 |
| HISTORY_CONNECTIONS_TABLE | IncidentWebSocketConnections | 인시던트 이력 채널 연결 정보 테이블 |

---

## 5. 사용 리소스 및 의존성 (Resources & Dependencies)
**AWS Resources**
* **Amazon EventBridge:** 주기적 실행 스케줄러
* **DynamoDB:** 3개 채널의 연결 테이블 (`Scan`, `DeleteItem`)
* **API Gateway:** 3개 채널의 WebSocket (`PostToConnection`)

**Python Libraries**
* `boto3`, `botocore`
* `json`, `time`, `os`

---

## 6. 필요한 IAM 권한 (Required IAM Permissions)
이 함수는 3개의 DynamoDB 테이블과 3개의 API Gateway 엔드포인트를 모두 제어할 수 있는 통합 권한을 가짐

### 6.1. DynamoDB (Connection Management)
* `dynamodb:Scan`: 3개 연결 테이블(`WebSocketConnections_v2`, `Remediation...`, `Incident...`)의 모든 파티션 키(`connectionId`)를 조회하여 브로드캐스팅 대상을 식별함
* `dynamodb:DeleteItem`: Ping 전송 실패 시, 연결이 끊긴 세션 정보를 테이블에서 삭제하여 정합성을 유지함
* **대상 테이블:** 위 환경 변수에 정의된 3개의 WebSocket 연결 테이블

### 6.2. API Gateway (WebSocket)
* `execute-api:ManageConnections`: 연결된 클라이언트에게 Ping 데이터(`PostToConnection`)를 전송함
* **대상 API:** Event, Remediation, History 채널에 해당하는 3개의 API Gateway Stage

### 6.3. Logging (CloudWatch)
* `logs:CreateLogGroup`, `logs:CreateLogStream`, `logs:PutLogEvents`: Lambda 함수의 실행 내역 및 에러 로그를 CloudWatch에 기록함

---

## 7. 한계 및 향후 과제 (Limitations & TODO)
* **[Limit] 확장성 문제:** 현재 `Scan` 방식을 사용하므로, 접속자가 수만 명 단위로 늘어날 경우 실행 시간(Timeout) 부족 및 비용 증가 문제가 발생할 수 있음
* **[Limit] 직렬 처리:** 3개의 채널을 순차적으로 처리하므로, 앞선 채널 처리가 늦어지면 뒤쪽 채널의 Ping 전송이 지연될 수 있음
* **[TODO]** 대규모 접속 대비 `Scan` 대신 GSI/Query 방식 도입 또는 `Step Functions`를 이용한 병렬 처리 구조로 개선 검토
