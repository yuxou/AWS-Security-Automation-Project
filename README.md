# AWS Security Event Automated Response System 
> **AWS 클라우드 환경을 위한 실시간 보안 관제 및 자동 대응 플랫폼** > **KT Cloud TECH UP 프로젝트 최종 결과물**

![Architecture Overview](images/architecture.png)

<br/>

## 1. 프로젝트 개요 (Project Overview)
본 프로젝트는 **AWS 서비스만을 활용하여 Serverless 아키텍처**로 구축된 **미니 SOAR(Security Orchestration, Automation and Response)** 시스템입니다.
CloudTrail 로그를 실시간으로 분석하여 위협을 탐지하고, WebSocket을 통해 대시보드에 시각화하며, Lambda를 통해 즉각적인 격리 조치를 수행합니다.

* **개발 기간**: 2025.10.29 ~ 2025.12.01 (약 5주)
* **목표**: 보안 이벤트 탐지부터 대응까지 **MTTR(평균 대응 시간) 5초 미만** 달성

<br/>

## 2. 기술 스택 (Tech Stack)

| Category | Technology |
| --- | --- |
| **Compute** | ![AWS Lambda](https://img.shields.io/badge/AWS_Lambda-FF9900?style=flat-square&logo=awslambda&logoColor=white) |
| **Integration** | ![Amazon EventBridge](https://img.shields.io/badge/EventBridge-FF4F8B?style=flat-square&logo=amazonaws&logoColor=white) ![Amazon SQS](https://img.shields.io/badge/Amazon_SQS-FF4F8B?style=flat-square&logo=amazonaws&logoColor=white) |
| **Database** | ![Amazon DynamoDB](https://img.shields.io/badge/DynamoDB-4053D6?style=flat-square&logo=amazondynamodb&logoColor=white) |
| **Network & API** | ![API Gateway](https://img.shields.io/badge/API_Gateway-FF4F8B?style=flat-square&logo=amazonaws&logoColor=white) (WebSocket) |
| **Security** | ![GuardDuty](https://img.shields.io/badge/GuardDuty-DC395E?style=flat-square&logo=amazonaws&logoColor=white) ![CloudTrail](https://img.shields.io/badge/CloudTrail-DC395E?style=flat-square&logo=amazonaws&logoColor=white) ![IAM](https://img.shields.io/badge/IAM-DD344C?style=flat-square&logo=amazonaws&logoColor=white) |
| **Frontend** | ![HTML5](https://img.shields.io/badge/HTML5-E34F26?style=flat-square&logo=html5&logoColor=white) ![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=flat-square&logo=javascript&logoColor=black) ![TailwindCSS](https://img.shields.io/badge/Tailwind_CSS-38B2AC?style=flat-square&logo=tailwind-css&logoColor=white) |

<br/>

## 3. 핵심 기능 (Key Features)

### 1) 실시간 위협 탐지 (Detection)
**총 32개의 보안 위협 시나리오**를 기반으로 EventBridge 패턴을 설계하여 실시간으로 탐지합니다.

#### **핵심 탐지 카테고리 (Highlights)**
* **Identity & Access (IAM)**
    * `Root Account Usage`: 루트 계정 로그인 및 콘솔 접근 실시간 경보
    * `Impossible Travel`: 물리적으로 이동 불가능한 거리/시간 내 동시 로그인(Geo-IP 기반) 탐지
    * `Credential Tampering`: MFA 디바이스 임의 삭제, Access Key 신규 생성 및 비정상 국가(ASN) 사용 탐지
* **Network & Infrastructure**
    * `Security Group Exposure`: SSH(22), RDP(3389) 등 고위험 포트의 `0.0.0.0/0` 개방 탐지
    * `Vulnerability Scanning`: 외부에서의 대량 스캐닝 시도(DoS/Scanning) 패턴 감지 (Log Metric Filter)
    * `EC2 Misconfiguration`: 보안 그룹이 개방된 채로 배포되는 EC2 인스턴스 즉시 식별
* **Data & Logging**
    * `CloudTrail Tampering`: 로깅 중지(StopLogging), 트레일 삭제 시도 등 감사 로그 무력화 행위 탐지
    * `S3 Public Exposure`: 버킷 ACL/정책 변경으로 인한 퍼블릭 권한 부여(Public Access) 즉시 감지

<br>

<details>
<summary><strong>32개 전체 탐지 시나리오 리스트 보기 (클릭)</strong></summary>
<br>

#### **계정 및 인증 보안 (Identity & Authentication)**
> **목표:** 탈취된 자격 증명을 이용한 비정상적인 접근 및 권한 오남용 탐지
- [x] **Root/User 로그인 감지**: Root 계정 사용 및 IAM User 로그인 성공/실패 모니터링 (특정 리전 기반)
- [x] **새로운 환경 접속**: 기존에 사용하지 않던 **새로운 IP**에서의 콘솔 로그인 탐지
- [x] **새로운 기기 접속**: 기존에 기록되지 않은 **새로운 디바이스(Device)**에서의 로그인 탐지
- [x] **MFA 무력화 시도**: MFA(다요소 인증) 디바이스 비활성화, 삭제, 우회 재등록 시도 탐지
- [x] **자격 증명 변경**: IAM 자격 증명(Credential) 생성 및 변경 시도 (MFA 우회와 연관)

#### **인프라 및 이상 징후 (Infrastructure Anomaly)**
> **목표:** 공격자의 정찰 행위 및 비정상적인 리소스 사용 패턴 식별
- [x] **CloudTrail 무력화**: 로그 기록 중지(StopLogging), 트레일 삭제, 설정 변경 등 **증거 인멸 시도** 탐지
- [x] **비정상 리전 접근**: 최근 일주일간 사용 기록이 없는 리전(Unusual Region)에서의 주요 리소스 접근
- [x] **불가능한 여행 (Impossible Travel)**: 짧은 시간 내에 물리적으로 이동 불가능한 두 지점 간의 로그인 성공 감지
- [x] **Access Key 신규 생성**: IAM Access Key 생성 이벤트 실시간 탐지
- [x] **Access Key 이상 사용**: 평소와 다른 지리적 위치(Geo) 또는 ASN(통신사)에서의 키 사용 감지
- [x] **취약점 스캐닝 감지**: 외부에서 웹 애플리케이션을 대상으로 한 대량의 스캐너 작동 감지 (CloudWatch Logs Metric Filter 활용)

#### **네트워크 및 보안 그룹 (Network & Security Groups)**
> **목표:** 외부 공격에 취약한 포트 개방 및 잘못된 네트워크 설정 즉시 식별
- [x] **SSH(22) 전체 개방**: 보안 그룹 Inbound 규칙에 `0.0.0.0/0`으로 SSH 포트 오픈 감지
- [x] **규칙 수정으로 개방**: 기존 보안 그룹 규칙을 수정하여 22번 포트를 여는 행위 탐지
- [x] **신규 생성 시 개방**: 보안 그룹 생성 시점부터 22번 포트가 열려있는 경우 탐지
- [x] **고위험 포트 개방**: SSH 외 RDP(3389), DB(3306, 5432) 등 고위험 포트 전체 개방 탐지
- [x] **임시 규칙 탐지**: 설명(Description)에 'test', 'temp', 'open' 등의 키워드가 포함된 취약한 규칙 탐지
- [x] **태그 규칙 위반**: 특정 환경(예: Prod) 태그가 있는 리소스의 보안 규칙 위반 탐지
- [x] **IP 대역 제한 확인**: 22번 포트가 열렸으나 특정 IP 대역으로 제한된 경우(정상 패턴 대비)
- [x] **규칙 삭제 누락**: 개방 후 삭제된(Revoke) 로그가 없는 좀비 규칙 탐지
- [x] **개방 후 접속 감지**: 보안 그룹이 `0.0.0.0/0`으로 변경된 직후 발생하는 외부 접속 로그 상관 분석
- [x] **취약한 EC2 배포**: SSH가 열린 보안 그룹을 연결한 상태로 EC2 인스턴스 배포(RunInstances) 시 탐지
- [x] **반복적 개방 시도**: 동일 계정 내 여러 보안 그룹에서 10분 이내 반복적으로 SSH 오픈 시도 감지
- [x] **AWS Config 위반**: AWS Config 규칙(`SG_OPEN_TO_WORLD`)의 규정 준수 상태 변경(Non-Compliant) 감지
- [x] **위험 해소(Positive Feedback)**: 보안 그룹 규칙 삭제(Revoke) 또는 그룹 삭제로 인한 위험 제거 이벤트 수집

#### **스토리지 보안 (S3 Security)**
> **목표:** 데이터 유출로 이어질 수 있는 스토리지의 퍼블릭 권한 설정 감지
- [x] **객체 ACL 변경**: 개별 파일(Object) 단위로 퍼블릭 권한을 부여하는 시도
- [x] **버킷 정책 수정**: IAM 정책(Bucket Policy)을 통해 불특정 다수에게 접근 권한 부여
- [x] **퍼블릭 액세스 차단 해제**: 계정 또는 버킷 수준의 Public Access Block(BPA) 설정 비활성화 감지
- [x] **정적 웹호스팅 활성화**: 의도치 않은 S3 정적 웹사이트 호스팅 기능 활성화 탐지
- [x] **CORS 설정 변경**: 교차 출처 리소스 공유(CORS) 정책을 느슨하게 변경하는 행위
- [x] **버킷 정책 삭제**: 기존 보안 정책을 제거하여 디폴트 공개 위험에 노출시키는 행위
- [x] **ACL 제거**: ACL 설정을 제거하여 접근 제어를 무력화하는 시도
</details>

<br>

### 2) 자동 대응 (Auto Remediation)
탐지된 위협에 대해 **EventBridge → Lambda (또는 SQS) → Action** 파이프라인을 통해 즉각적인 조치를 취합니다.

| 대응 도메인 (Domain) | 구현된 자동 대응 시나리오 및 기술적 조치 |
| :--- | :--- |
| **Identity & Access** | • **Brute Force 방어**: Root/IAM User 로그인 3회 이상 실패 시, **30분간 로그인 차단 정책(Deny Policy)** 자동 부착<br>• **Anomaly Response**: 불가능한 여행(Impossible Travel) 등 이상 징후 발생 시 세션 만료 및 알림 전송 |
| **Network Security** | • **Port Auto-Close**: SSH(22), RDP(3389), DB(3306, 5432) 등 고위험 포트 개방 시 **SQS(SecurityRemediationQueue)**를 통해 안정적으로 규칙 삭제<br>• **DoS Mitigation**: 외부 취약점 스캐너 작동 감지 시 해당 소스 IP 차단 대응 (`dvwa-remediation`) |
| **Data Storage** | • **S3 Public Revert**: 버킷 정책이 퍼블릭 허용으로 변경될 경우, 이를 감지하여 **즉시 안전한 정책으로 롤백(Auto-Remediation)** 및 퍼블릭 액세스 차단 설정 |

### 3) 실시간 관제 대시보드 (Dashboard)
* **WebSocket Push**: 새로고침 없이 탐지된 위협이 화면에 팝업으로 등장
* **대응 현황 시각화**: `NEW` → `PROCESSING` → `MITIGATED` 상태 변화를 실시간 트래킹
* **이력 관리**: DynamoDB와 연동하여 과거 침해 사고 이력 조회

<div align="center">
  <img src="images/dashboard_demo.gif" width="100%" alt="Dashboard Demo">
  <p><em>실시간 보안 관제 대시보드 시연 화면</em></p>
</div>
<br/>

## 4. 시스템 아키텍처 (Architecture)
1.  **Event Source**: CloudTrail, GuardDuty, AWS Config 등에서 보안 로그 발생
2.  **Routing**: EventBridge가 사전에 정의된 Rule(패턴)에 따라 이벤트를 필터링하여 전달
3.  **Processing**: Lambda가 이벤트를 정규화하고 **SQS(대기열)**로 전송하여 트래픽 버퍼링
4.  **Action**:
    * **Notification**:SNS 및 API Gateway(WebSocket)를 통해 대시보드로 경보 전송 & Slack 알림 발송
    * **Remediation**: SQS 트리거를 받은 Lambda가 Boto3를 이용해 격리/차단 조치 수행
5.  **Storage**: 모든 탐지 및 대응 이력은 DynamoDB에 저장 및 관리 

<br/>

## 5. 프로젝트 구조 (Project Structure)
```code
├── websocket-handlers
│   ├── event-log-websocket/           # 보안 이벤트 탐지 웹소켓
│   ├── incident-websocket/            # 이벤트 히스토리 웹소켓
│   └── remediation-websocket/         # 자동 대응 웹소켓
├── lambda-functions
│   ├── detection/                     # 위협 탐지 및 알림 처리
│   ├── remediation/                   # 자동 대응 (격리/차단)
│   └── utils/                         # 유틸 함수
├── dashboard
│   └── index.html                     # 실시간 관제 대시보드 (HTML/JS)
└── README.md
```

<br/>

## 6. 설치 및 실행 (Getting Started)

### Prerequisites
* AWS 계정 및 로그인
* Python 3.9+ (Lambda 코드 수정 시)

### Installation
1.  **프로젝트 설정**
    ```bash
    git clone https://github.com/username/AWS-Security-Automation.git
    cd AWS-Security-Automation
    ```

2.  **AWS 리소스 생성 (Manual Setup)**
    > 본 프로젝트는 AWS Console을 통해 구축되었습니다. 주요 리소스 설정은 아래와 같습니다.
    
    * **DynamoDB**: `SecurityEvents` 테이블 생성 (Partition Key: `eventId`)
    * **IAM Role**: Lambda가 CloudTrail, DynamoDB, API Gateway에 접근할 수 있도록 **IAM 정책(Policy) 구성 및 역할 부여**
    * **Lambda**: `lambda-functions/` 폴더 내의 코드를 업로드하고, 위에서 생성한 IAM Role 연결
    * **EventBridge**: `default` 버스에 위협 탐지 패턴(JSON)으로 규칙(Rule) 생성 및 대상(Target)으로 Lambda 연결
    * **API Gateway**: WebSocket API 생성 후 `$connect`, `$disconnect` 라우트에 핸들러 함수 연결
    
3.  **대시보드 연결 (Connect Dashboard)**
    * `dashboard/index.html`을 브라우저에서 엽니다.
    * 우측 상단 **⚙️ 설정** 버튼을 클릭합니다.
    * 생성된 API Gateway의 **WebSocket URL**(`wss://...`)을 입력하고 **[연결]**합니다.
    
<br/>

## 7. 트러블 슈팅 (Troubleshooting & Challenges)

### 문제 1: WebSocket 연결 끊김 현상
* **현상**: 대시보드를 켜두고 일정 시간이 지나면 연결이 끊겨 알림을 받지 못함. 
* **해결**: API Gateway의 타임아웃 제한을 인지하고, 클라이언트(JS) 단에서 `reconnect` 로직과 `Heartbeat(Ping/Pong)` 메커니즘을 구현하여 연결 유지함. 

### 문제 2: Lambda 동시성 제어
* **현상**: 대량의 로그가 유입될 때 Lambda가 스로틀링(Throttling)되어 일부 이벤트가 유실됨.
* **해결**: SQS를 Lambda 앞단에 배치하여 대기열 처리를 통해 안정성 확보함 (또는 Reserved Concurrency 설정).

### 문제 3: 자동 대응 무한 루프 (Infinite Loop) 방지
* **현상**: Lambda가 보안 그룹을 차단(Revoke)하면, 이 행위 자체가 다시 CloudTrail 로그로 기록되어 EventBridge가 Lambda를 또다시 트리거하는 순환 참조 발생 위험.
* **해결**: EventBridge 패턴에서 **`userIdentity.arn`** 필드를 필터링하여, **"자동 대응 Lambda 역할(Role)이 수행한 작업"은 트리거 대상에서 제외**하도록 로직 추가.

<br/>

## 8. 팀원 소개 (Team)

| 이름 | 역할 (Role) | 주요 기여 및 담당 파트 (Key Contributions) |
| :---: | :---: | :--- |
| **석대원**<br>[![GitHub](https://img.shields.io/badge/GitHub-181717?style=flat-square&logo=github&logoColor=white)](https://github.com/SDW-2000) | **Cloud Architect** | • **전체 SOAR 아키텍처 설계** 및 리소스 파이프라인 통합<br>• IAM 보안 정책 수립 및 리소스 접근 제어(Least Privilege) 구현 |
| **신유주**<br>[![GitHub](https://img.shields.io/badge/GitHub-181717?style=flat-square&logo=github&logoColor=white)](https://github.com/yuxou)<br>[![Velog](https://img.shields.io/badge/Velog-20C997?style=flat-square&logo=velog&logoColor=white)](https://velog.io/@yuxou/posts) | **Full Stack Engineer** | • **실시간 관제 대시보드 End-to-End 구축** (EC2 배포, WebSocket API)<br>• 네트워크 보안(SSH, SG) 위협 탐지 및 **Lambda 기반 자동 대응 로직** 개발 |
| **윤서원**<br>[![GitHub](https://img.shields.io/badge/GitHub-181717?style=flat-square&logo=github&logoColor=white)](https://github.com/Wonyoon-Luciel)<br>[![Velog](https://img.shields.io/badge/Velog-20C997?style=flat-square&logo=velog&logoColor=white)](https://velog.io/@seowon6766/posts) | **Security Detection Engineer** | • 계정 보안(Root/User Login) 및 인프라 변조 시나리오 설계<br>• **AWS EventBridge 기반 탐지 룰 엔진 구축** (Account, AccessKey, SG, CloudTrail 변조 등 주요 위협 패턴 전반) |
| **안지서**<br>[![GitHub](https://img.shields.io/badge/GitHub-181717?style=flat-square&logo=github&logoColor=white)](https://github.com/vanillacustardcream) | **Cloud Engineer** | • **스토리지(S3) 보안 모니터링** (Public ACL/Policy 변경 실시간 탐지)<br>• **통합 알림 파이프라인 구축** (CloudWatch → SNS → Lambda → Slack) |

<br>

**[공통 수행 업무]**
* 탐지/대응 시나리오별 **Cross-Check** 및 통합 테스트
* 코드 리뷰(Code Review) 및 아키텍처 검증

<br/>

---
MIT License © 2025 KT Cloud TECH UP Team Layer 3
