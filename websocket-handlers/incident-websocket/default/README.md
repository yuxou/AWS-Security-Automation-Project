## 1. 함수 개요 (Overview)
이 Lambda 함수는 API Gateway WebSocket의 $default 라우트로 호출되며,
클라이언트로부터 전달되는 WebSocket 메시지를 처리하는 기본 엔드포인트 역할을 합니다.

주요 기능:
1. WebSocket 클라이언트가 연결 상태 점검을 위해 전송하는 "ping" 요청 수신 시 "pong" 응답 반환
2. 그 외 모든 요청에 대해 공통적으로 "pong"을 반환하는 기본 응답 처리
이 함수는 모니터링, 연결 상태 확인(heartbeat), 디버깅에 사용되는 기본 메시지 처리 모듈로 구성되어 있습니다.

---
## 2. 동작 조건 & 트리거 (Conditions & Trigger)
### 이벤트 소스
API Gateway WebSocket ($default Route)

### 처리 대상 이벤트
| 구분          | 이벤트         | 설명                                           |
| ----------- | ----------- | -------------------------------------------- |
| 핑(Ping) 메시지 | `"ping"` 포함 | 연결 유지(keep-alive) 및 상태 점검용 메시지               |
| 기타 메시지      | 그 외 모든 body | `$default` 라우트로 들어온 메시지에 대해 동일하게 `"pong"` 반환 |

---
## 3. 처리 로직 요약 (Logic Flow)
### 1. EventBridge 또는 WebSocket → Lambda 트리거
- API Gateway WebSocket 클라이언트가 메시지를 전송하면 이 함수가 호출됨
### 2. 요청 Body 분석
```python
body = event.get('body', '')
```
### 3. 메시지 분기 처리
- Body 내 "ping" 문자열 존재 시:
   - "pong" 반환
   - CloudWatch 로그에 "DEBUG: Ping detected" 출력
- 기타 메시지:
   - "DEBUG: $default invoked" 출력
   - "pong" 반환
### 4. WebSocket 응답
Lambda 기본 응답 구조를 그대로 사용하여 HTTP 200 + "pong" 반환

---
## 4. 환경 변수 (Environment Variables)
| 이름   | 예시 | 설명                           |
| ---- | -- | ---------------------------- |
| (없음) | -  | 본 Lambda는 별도의 환경 변수를 요구하지 않음 |

---
## 5. 사용 리소스 / 의존성 (Dependencies)
### AWS 리소스
   - API Gateway WebSocket ($default route)
### Python 패키지
   - json (표준 라이브러리)

---
## 6. 필요한 IAM 권한 (Required IAM Permissions)
이 Lambda는 DynamoDB, S3, STS 등 외부 AWS 리소스를 호출하지 않으므로
추가 IAM 권한을 요구하지 않는다. 기본 Lambda 실행 역할만 필요합니다.

최소 권한 예시
- AWSLambdaBasicExecutionRole
   - CloudWatch Logs 기록을 위한 정책

---
## 7. 한계 & TODO (Limitations / TODO)
### 한계
- 메시지 "ping" 여부만 판별하며, 다른 메시지 유형에 대한 처리 로직 없음
- WebSocket 응답을 직접 push 하지 않음(APIGW post_to_connection 미사용)
- 인증·권한·메시지 라우팅 기능 없음
### TODO
- WebSocket 메시지 타입별 정교한 처리 분기 로직 추가
- post_to_connection을 통한 서버→클라이언트 메시지 push 기능 확장
- JSON 메시지 구조 표준화 및 유효성 검사 추가
