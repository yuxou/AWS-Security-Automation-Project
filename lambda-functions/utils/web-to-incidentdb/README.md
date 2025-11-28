## 1. 함수 개요 (Overview)
이 Lambda는 Incident 상태/메모 변경을 위한 HTTP API 엔드포인트입니다.
클라이언트가 incident_id, status, note를 POST로 전달하면 **DynamoDB(Incident 테이블)**의 해당 항목을 업데이트하고, 변경된 레코드를 반환합니다. CORS 및 프리플라이트(OPTIONS)를 기본 지원합니다.

주요 기능:
- 허용 상태: NEW, PROCESSING, MITIGATED, CLOSED
- status, note, updated_at 원자적 갱신
- CORS 헤더 기본 제공 및 프리플라이트 처리
- 유효성 검증(JSON 파싱, 필수 필드, 상태 값)

---
## 2. 동작 조건 & 트리거 (Conditions & Trigger)
### 이벤트 소스
- API Gateway(HTTP/REST): POST /incident/update 등으로 매핑
- CORS 프리플라이트: OPTIONS 요청 처리 시 200 반환

### 요청 본문(JSON)
- incident_id(필수): 문자열
- status(필수): NEW|PROCESSING|MITIGATED|CLOSED
- note(선택): 문자열(기본 "")

---
## 3. 처리 로직 요약 (Logic Flow)
### 1. 프리플라이트 처리(OPTIONS) → 200 + CORS 헤더 반환
### 2. 본문 파싱/검증
- JSON 파싱 실패 시 400
- incident_id/status 누락 시 400
- status가 허용 집합 외면 400
### 3. 업데이트 수행
- UpdateExpression: SET #s=:s, #n=:n, updated_at=:u
- ReturnValues="ALL_NEW"로 변경 후 전체 속성 반환
### 4. 응답
- 성공: 200 + { message:"ok", incident:{...} }
- 실패: 500 + { message:"DynamoDB update error" } (로그에 원인 기록)

---
## 4. 환경 변수 (Environment Variables)
| 이름               | 예시         | 설명                        |
| ---------------- | ---------- | ------------------------- |
| `INCIDENT_TABLE` | `Incident` | 상태/메모를 갱신할 DynamoDB 테이블명  |


---
## 5. 사용 리소스 / 의존성 (Dependencies)
### AWS 리소스
   - DynamoDB
     - INCIDENT_TABLE (Incident 저장)
   - API Gateway WebSocket
     - 통합: Lambda 프록시 통합 권장
     - 라우팅 예: POST /incident/update, OPTIONS /incident/update
### Python 패키지
   - 표준: os, json, datetime(timezone)
   - AWS SDK: boto3, botocore.exceptions.ClientError

---
## 6. 필요한 IAM 권한 (Required IAM Permissions)
### 1. DynamoDB 권한
#### 1.1 `Incident`
   - "dynamodb:UpdateItem"

---
## 7. 한계 & TODO (Limitations / TODO)
   - incident_id 존재 검증(존재하지 않는 키 요청 시 동작 정책)과 낙관적 잠금(버전 관리)은 현재 미포함
   - 상태 전이 규칙(예: CLOSED 이후 재개방 금지 등) 비즈니스 로직은 호출 측에서 보장 필요
   - TODO
       - `ConditionExpression`으로 유효 상태 전이 강제
       - 감사 필드(updated_by, 변경 이력 테이블) 도입
       - CORS 도메인 화이트리스트화 및 인증(토큰 검증) 연동
