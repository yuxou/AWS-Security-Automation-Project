## 1. 함수 개요 (Overview)
이 Lambda 함수는 **보안 인시던트 데이터의 변경 사항을 실시간으로 감지하여 웹소켓 대시보드로 중계**하는 스트림 프로세서 역할을 수행함
* **주요 기능:** DynamoDB Stream을 통해 새로운 인시던트나 자동 조치 로그가 생성/수정될 때 트리거됨
* **결과 처리:** 변경된 데이터를 프론트엔드에서 사용하기 쉬운 표준 포맷으로 변환한 뒤, 연결된 모든 WebSocket 클라이언트에게 브로드캐스팅함

---

## 2. 동작 조건 및 트리거 (Conditions & Trigger)
* **이벤트 소스:** DynamoDB Stream (Target Table: Incident)
* **트리거 조건:**
    * eventName이 INSERT 또는 MODIFY인 경우에만 동작함
    * 데이터 삭제(REMOVE) 이벤트는 무시함
* **데이터 흐름:** Incident 테이블에 데이터 적재 -> DynamoDB Stream 발생 -> Lambda 트리거 -> WebSocket 전송

---

## 3. 처리 로직 (Logic)
1. **데이터 디시리얼라이즈:** DynamoDB Stream의 Low-level JSON 형식을 표준 Python Dictionary로 변환하고, Decimal 타입을 JSON 호환 형식(int/float)으로 변환합니다.
2. **이벤트 유형 분류 및 포맷팅:**
    * **Case 1: 보안 인시던트 (Security Incident)**
        * incident_id 필드가 존재할 경우 인시던트 업데이트로 판단함
        * **리소스 필드 우선순위 적용:** arn > resource > sg 순서로 확인하여 가장 구체적인 식별자를 resource 필드에 매핑함
    * **Case 2: 자동 조치 로그 (Remediation Log)**
        * action 필드가 존재할 경우 자동 대응 로그로 판단함
        * 조치 유형, 대상, 상태, 타임스탬프를 추출하여 페이로드를 구성함
3. **브로드캐스팅 (Broadcasting):**
    * WebSocketConnections 테이블을 스캔하여 현재 활성화된 모든 클라이언트의 connectionId를 조회함
4. **전송 및 연결 정리:**
    * 각 클라이언트에게 포맷팅된 데이터를 post_to_connection으로 전송함
    * 전송 실패 시, 에러 코드가 410 Gone 또는 GoneException인 경우(연결이 끊긴 클라이언트) 해당 ID를 테이블에서 즉시 삭제함

---

## 4. 환경 변수 (Environment Variables)

| 변수명 | 값 | 설명 |
| :--- | :--- | :--- |
| WS_ENDPOINT | https://kote8jrryb.execute-api.us-east-1.amazonaws.com/prod/ | 메시지를 전송할 API Gateway WebSocket URL |
| CONNECTIONS_TABLE | WebSocketConnections | 활성 WebSocket 연결 정보가 저장된 DynamoDB 테이블명 |

---

## 5. 사용 리소스 및 의존성 (Resources & Dependencies)
**AWS Resources**
* **DynamoDB Stream:** 데이터 변경 감지
* **DynamoDB:** WebSocketConnections 테이블 (활성 사용자 조회 및 관리)
* **API Gateway Management API:** WebSocket 클라이언트로 데이터 푸시

**Python Libraries**
* boto3 (AWS SDK)
* json, decimal (데이터 직렬화 처리)

---

## 6. 필요한 IAM 권한 (Required IAM Permissions)
이 함수는 다음과 같은 AWS 리소스 접근 권한을 가짐

### 6.1. Logging (CloudWatch)
* `logs:CreateLogGroup`, `logs:CreateLogStream`, `logs:PutLogEvents`: Lambda 함수의 실행 그룹을 생성하고, 로그 스트림에 실행 내역 및 에러를 기록
* **대상:** `/aws/lambda/IncidentStreamProcessor` 로그 그룹

### 6.2. DynamoDB Stream
* `dynamodb:GetRecords`, `dynamodb:GetShardIterator`, `dynamodb:DescribeStream`: `Incident` 테이블에서 발생하는 실시간 데이터 변경 사항(Stream)을 감지하고 읽어오는 권한
* **대상:** `Incident` 테이블의 Stream ARN

### 6.3. DynamoDB (Connection Management)
* `dynamodb:Scan`: `WebSocketConnections` 테이블을 스캔하여 현재 접속 중인 모든 클라이언트(`connectionId`) 목록 조회
* `dynamodb:DeleteItem`: 메시지 전송 실패 시, 연결이 끊긴 클라이언트 정보를 테이블에서 삭제
* **대상:** `WebSocketConnections` 테이블

### 6.4. API Gateway (WebSocket)
* `execute-api:ManageConnections`: 연결된 WebSocket 클라이언트에게 데이터를 전송(`PostToConnection`)하는 권한
* **대상:** `connections` URL 경로
---

## 7. 한계 및 향후 과제 (Limitations & TODO)
* **[Limit] 브로드캐스팅 효율성:** 현재 WebSocketConnections 테이블 전체를 Scan하는 방식 -> 접속자가 수천 명 단위로 늘어날 경우 성능 저하가 발생할 수 있음
* **[Limit] 에러 핸들링:** 개별 클라이언트 전송 실패 시 로그만 출력하고 건너뛰는 구조 -> 중요 메시지 누락 방지를 위한 재시도 로직이나 DLQ(Dead Letter Queue)가 없음
* **[TODO]** 접속자 규모 확장에 대비하여 Scan 대신 GSI를 활용한 쿼리 방식 또는 SNS/EventBridge를 활용한 Fan-out 구조 검토
