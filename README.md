# AWS-Security-Automation-Project
# KT Cloud TECH UP 프로젝트
---

## 1. 🏷️ 프로젝트 개요 (Project Overview)

**AWS 기반 보안 이벤트 모니터링 & 자동대응 시스템(SOAR 미니 버전)**을 구현한 프로젝트입니다.
CloudTrail / EventBridge / Lambda / DynamoDB / WebSocket API / S3 / IAM 등 AWS 서비스를 이용해 **실시간 보안 이벤트 탐지, 알림, 자동대응, 웹 대시보드 시각화**까지 구현했습니다.

---

## 2. 🧩 아키텍처 (Architecture)

<img width="1512" height="937" alt="image" src="https://github.com/user-attachments/assets/85537271-85d6-44fb-866b-f7f0a676f012" />


**핵심 구성요소**

* CloudTrail (로그 수집)
* EventBridge Rule (이벤트 패턴 기반 트리거)
* 10개 이상 Lambda Security Functions
* DynamoDB(Incident / WebSocketConnections / security-alerts-state)
* Amazon API Gateway – WebSocket
* Static HTML Dashboard (보안 알림 & 자동대응 히스토리 표시)

---

## 3. 🔍 주요 기능 (Features)

### 1) **보안 이벤트 탐지**

36개의 보안 시나리오 중 **OO개 구현**
예시:

* Impossible travel login
* CloudTrail tamper detect
* Unusual region access
* AccessKey Created + 의심 국가 사용
* SSH Open to 0.0.0.0/0 반복 규칙 개방
* 취약점 스캐너 과도한 요청 탐지 등…

### 2) **자동 대응 (Auto Remediation)**

* EC2 인스턴스 격리(Quarantine)
* 보안 그룹 차단 (Deny HTTP/SSH)
* CloudTrail tamper 후 Validator로 복구
* Snapshot → S3 저장 등

### 3) **대시보드(WebSocket 실시간)**

* 보안 이벤트 알림 실시간 Push
* 자동대응 결과 알림
* 이벤트 상세 페이지
* Incident History 테이블

---

## 4. 📁 저장소 구조 (Repository Structure)

```
/lambdas/
   ├── login-cloudtrail-tamper-20251105/
   ├── impossible-travel-login-20251105/
   ├── sg-open-multiple-20251106/
   ├── ...
/dashboard/
   ├── index.html
   ├── event-detail.js
   └── styles.css
/scripts/
   ├── pull_selected.sh
   ├── pull_one.sh
   ├── deploy_one.sh
README.md
```

---

## 5. 🛠️ 기술 스택 (Tech Stack)

* **AWS**: CloudTrail, EventBridge, Lambda, DynamoDB, Route53, S3, CloudWatch, STS
* **Frontend**: HTML, JavaScript, WebSocket
* **DevOps**: CloudShell, GitHub, PyCharm Remote Sync
* **Security**: IAM Least Privilege, Event Pattern 기반 탐지

---

## 6. 💡 구현 과정 (What we did)

* 보안 시나리오 분석 → 패턴 설계 → EventBridge 매핑
* Lambda 함수 10개 이상 구현 및 테스트
* WebSocket 기반 실시간 이벤트 알림 구현
* Incident DB 설계 및 History 기능 구현
* 자동대응(action) API 완성 및 대시보드 연동
* 취약점 스캐너, EC2 공격 실 테스트로 검증
* 비용 최적화 (CloudTrail 저장 기간 단축 등)

---

## 7. 🎥 시연 영상 (Demo Video)

> 유튜브 URL or 드라이브 링크 넣기
> 없으면 “추가 예정”이라고 적어도 OK

---

## 8. 👥 팀 소개 (Team Members)

| 이름  | 역할                           |
| --- | ---------------------------- |
| 석대원 | 팀장 / 이벤트 구조 총괄               |
| 윤서원 | Lambda 구현 / GitHub / 대시보드 기능 |
| 신유주 | 자동대응 기능, IAM 정책              |
| 안지서 | 대시보드 HTML/JS / 테스트           |

(원하는 대로 조정 가능!)

---

## 9. 📌 설치 및 실행 방법 (How to Run)

### 1) CloudTrail → EventBridge 설정

(간단한 명령 또는 설정법)

### 2) Lambda 배포 스크립트

```
./deploy_one.sh <FUNCTION_NAME>
```

### 3) WebSocket URL 대시보드에 입력

dashboard/index.html 수정

### 4) Incident 저장 후 대시보드 자동 반영

DynamoDB 테이블 설정 등…

---

## 10. 📑 라이센스

MIT License or None (선택)

---

# ⭐ 최종 제출용 README 핵심 요약 (짧게)

* **프로젝트 목적**
  AWS 기반 보안 이벤트 → 실시간 알림 → 자동대응까지 동작하는 SOAR 미니 플랫폼 구축.

* **기능**
  보안 이벤트 00개 탐지, 자동대응 00개, 대시보드 실시간 시각화.

* **구성**
  CloudTrail + EventBridge + Lambda + DynamoDB + WebSocket + HTML.

* **강점**
  실제 공격 시나리오 기반 테스트로 검증 완료.

