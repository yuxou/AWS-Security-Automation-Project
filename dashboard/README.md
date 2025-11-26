## AWS Security Operations Dashboard (실시간 보안 관제 대시보드)

AWS 환경에서 발생하는 보안 위협을 **실시간(Real-time)** 으로 시각화하고, 자동 대응(Auto-Remediation) 결과를 모니터링하는 보안 관제 대시보드임

**AWS Lambda(Serverless) 백엔드**와 **EC2 기반 웹 호스팅**을 결합한 하이브리드 아키텍처로 구성되어 있음

---

## 라이브 데모 (Live Demo)

**AWS EC2 인스턴스**에 대시보드를 배포해 둠. 아래 링크를 클릭하면 즉시 확인 가능함

### [대시보드 접속하기 (Click)](http://54.235.30.142/dashboard/)
**(URL: http://54.235.30.142/dashboard/)**

---

## 테스트용 WebSocket 주소 (Test URLs)

대시보드 접속 후, 아래 주소를 복사하여 **상단 입력창(WebSocket URL)** 에 넣고 `저장 및 연결` 버튼을 누르면 됨

| 용도 (Type) | 주소 (URL) | 설명 |
| :--- | :--- | :--- |
| **이벤트 탐지**<br>(Event Detection) | `wss://egtwu3mkhb.execute-api.us-east-1.amazonaws.com/prod/` | 실시간 보안 위협 로그가 들어오는 메인 채널 |
| **자동 대응**<br>(Auto-Response) | `wss://3y9ayspfp3.execute-api.us-east-1.amazonaws.com/prod/` | Lambda가 수행한 차단/격리 조치 결과 알림 채널 |
| **히스토리**<br>(History Log) | `wss://kote8jrryb.execute-api.us-east-1.amazonaws.com/prod/` | 과거 누적된 보안 사고 이력을 조회하는 채널 |

---

## 아키텍처 및 데이터 흐름 (Architecture Flow)

1.  **Event Detection**: CloudTrail/EventBridge가 보안 위협 감지
2.  **Processing (Serverless)**: Lambda가 탐지 로직 수행 및 대응(Remediation) 실행
3.  **Push Notification**: Lambda가 **API Gateway (WebSocket)** 를 통해 클라이언트로 JSON 데이터 전송
4.  **Visualization (EC2)**: EC2 웹 서버에 호스팅된 대시보드가 데이터를 수신하여 실시간 렌더링

---

## 주요 기능 (Key Features)

### 1. WebSocket 기반 실시간 모니터링
* **Zero Latency**: 새로고침(F5) 없이 서버에서 이벤트가 발생하는 즉시 화면에 알림이 팝업됨
* **Live Status Indicator**: 우측 상단 연결 상태 표시등(정상 연결됨 / 연결 끊김)을 통해 소켓 연결 상태를 직관적으로 확인함

### 2. 시각적 위험도 표현 (Visual Severity)
* **Color Coding**: 보안 이벤트의 위험도에 따라 행(Row)의 색상이 자동으로 변경됨
    * 🔴 **High/Critical**: 즉시 대응 필요 
    * 🟡 **Medium**: 주의 요망 
    * 🟢 **Info/Safe**: 대응 완료 또는 단순 알림

### 3. 자동 대응 결과 추적 (Action Tracking)
* 보안 위협 탐지 시 수행된 Lambda의 대응 조치(Action)가 함께 기록됨
    * `Block` (보안그룹 차단), `Quarantine` (인스턴스 격리) 등

### 4. 사고 이력 조회 (Incident History)
* 대시보드 접속 시 DynamoDB에서 최근 발생한 보안 사고 내역을 자동으로 로딩하여 보여줌

---

## 실행 방법 (How to Run)

**Live Demo** 링크를 이용하는 것을 권장함

1.  위의 **[대시보드 접속하기]** 링크를 클릭함
2.  화면 상단 입력창에 **테스트용 WebSocket 주소**를 복사해 붙여넣음
3.  **[저장 및 연결]** 버튼을 클릭함
4.  상단 상태 표시등이 **정상 연결됨**로 바뀌면, AWS 환경에서 보안 이벤트를 발생시켜 실시간 알림을 확인함

---

## 접속 시 주의사항

* **HTTP 접속**: SSL 인증서가 적용되지 않은 HTTP 환경이므로, 브라우저 주소창에 '주의 요망'이 뜰 수 있음

---

## 기술 스택 (Tech Stack)

* **Frontend**: HTML5, CSS3, Vanilla JavaScript (ES6+)
* **Hosting**: AWS EC2 (Apache/Nginx)
* **Backend Logic**: AWS Lambda (Serverless), API Gateway (WebSocket)
* **Database**: DynamoDB

---

## 트러블슈팅 (Troubleshooting)

**Q. "연결 끊김" 상태가 유지됨**

* `wss://`로 시작하는 URL이 정확한지 확인 필요함
* AWS API Gateway의 `$connect` 경로가 정상적으로 배포(Deploy)되었는지 확인해야 함

**Q. 알림이 오지 않음**

* 브라우저 개발자 도구(F12) > `Network` 탭 > `WS` 필터에서 메시지가 수신되는지 확인해야 함
* AWS EventBridge 규칙이 정상적으로 Lambda를 트리거하고 있는지 확인이 필요함
