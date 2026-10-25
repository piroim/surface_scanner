# Web Surface Scanner

`surface_scan.py`는 허가된 웹 자산의 URL 목록을 기준으로 DNS IP, HTTP 서버, 런타임, 백엔드 기술 및 프런트엔드 프레임워크 단서를 수집하는 1차 표면 조사 도구입니다.

취약점 공격이나 원격 코드 실행 여부를 시험하지 않습니다. 모든 네트워크 요청은 `GET`이며, 탐지 결과는 응답에 노출된 정보와 제한된 동일 호스트 경로를 바탕으로 한 추정입니다.

## 파일 구조

```text
surface_scanner/
├── surface_scan.py          # 메인 CLI 및 수집 흐름
├── ip_search.py             # DNS/IP 동작 확인용 독립 도구
├── scan_modules/
│   ├── base.py              # 공통 응답·증거·서명 자료형
│   ├── server.py            # 웹 서버와 프록시 헤더 수집
│   ├── php.py               # PHP, CMS, PHP 프레임워크
│   ├── jsp.py               # JSP, Servlet, Java 프레임워크
│   ├── asp.py               # ASP, ASP.NET, .NET
│   └── nodejs.py            # Node.js 및 JS 프레임워크
├── targets.txt              # 대상 목록 예시
└── result.txt / *.csv       # 실행 시 생성하는 결과 파일
```

## 준비

Python 3과 `requests`가 필요합니다.

```powershell
python -m pip install requests
```

## 기본 실행

단일 URL 또는 도메인:

```powershell
python .\surface_scanner\surface_scan.py https://example.com
```

대상 목록과 상세 결과:

```powershell
python .\surface_scanner\surface_scan.py `
  -f .\surface_scanner\targets.txt `
  -o .\surface_scanner\result.txt `
  --csv .\surface_scanner\result.csv
```

특정 기술 모듈만 실행:

```powershell
python .\surface_scanner\surface_scan.py -f targets.txt -e php
python .\surface_scanner\surface_scan.py -f targets.txt -e jsp,asp
python .\surface_scanner\surface_scan.py --list-modules
```

주요 옵션:

| 옵션 | 설명 |
|---|---|
| `-f, --file FILE` | 한 줄에 하나씩 작성한 대상 목록 |
| `-o, --output FILE` | 사람이 읽는 상세 결과 저장 |
| `--csv FILE` | 요약 CSV 저장 |
| `-e, --extension TYPE` | `php`, `jsp`, `asp`, `nodejs`, `all` 선택 |
| `--timeout SEC` | 요청별 제한 시간, 기본 5초 |
| `--max-js N` | 동일 호스트 JavaScript 추가 요청 수, 기본 3 |
| `--max-backend-links N` | 발견된 백엔드 URL 추가 요청 수, 기본 5 |
| `--probe-wordpress` | WordPress 단서가 없어도 알려진 경로 확인 |
| `--no-probe-wordpress` | WordPress 경로 확인 비활성화 |
| `--insecure` | 자체 서명 TLS 인증서 허용 |
| `--color auto\|always\|never` | CLI ANSI 색상 설정 |

## 전체 동작 구조

```text
대상 입력
  → URL 정규화
  → DNS/IP 조회
  → 시작 페이지 GET
  → 서버 헤더 수집
  → 기술 모듈 지문 비교
  → HTML 및 동일 호스트 JS 분석
  → 발견된 백엔드 경로 제한적 GET
  → 조건부 WordPress 경로 확인
  → PHP 정보 페이지 후보 확인
  → 증거 우선순위와 복수 기술 정리
  → CLI / 상세 TXT / CSV 출력
```

### 1. 대상과 URL 정규화

- `https://` 또는 `http://`가 명시된 URL은 해당 스킴만 사용합니다.
- 도메인만 입력하면 HTTPS를 먼저 시도하고 접속 실패 시 HTTP를 시도합니다.
- 입력 URL의 포트와 경로는 유지합니다.
- 외부 호스트 리디렉션은 중단합니다.
- 원래 호스트와 `www.` 유무만 다른 호스트까지 동일 범위로 허용합니다.

### 2. DNS/IP 조회

입력 URL에서 포트를 제외한 호스트명을 추출하고 다음 운영체제 API를 호출합니다.

```python
socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
```

IPv4와 IPv6를 반환 순서대로 중복 제거하여 저장합니다. 이는 실제 HTTP 소켓의 상대 IP가 아니라 로컬 DNS·캐시·`hosts` 파일 환경에서 해석된 주소입니다. CDN이나 WAF가 있으면 원본 서버가 아닌 엣지 IP가 표시될 수 있습니다.

동작만 별도로 확인하려면 다음 명령을 사용합니다.

```powershell
python .\surface_scanner\ip_search.py example.com --raw
```

### 3. 시작 페이지와 리디렉션

- User-Agent는 `web-surface-scanner/2.0 (authorized inventory)`입니다.
- 자동 리디렉션 대신 각 `Location`을 검사한 후 동일 범위일 때만 이동합니다.
- 텍스트, JavaScript, JSON, XML 응답 본문은 최대 1MB까지만 읽습니다.
- 공격용 POST, 파일 업로드, 메모리 손상 검사는 수행하지 않습니다.

### 4. 공통 서버 정보

`scan_modules/server.py`는 다음과 같은 응답 헤더를 자산 정보로 수집합니다.

```text
Server
Via
X-Powered-By
X-Generator
X-AspNet-Version
X-AspNetMvc-Version
X-Runtime
X-Served-By
X-Backend-Server
```

Apache, nginx, WebtoB, AmazonS3, CloudFront, awselb 같은 값은 서버·프록시·인프라 정보이며 백엔드 프레임워크를 단독으로 확정하지 않습니다.

### 5. 기술 모듈

각 모듈은 URL 경로, 세션 쿠키, 응답 헤더와 HTML 본문을 독립적으로 검사합니다.

| 모듈 | 주요 예시 |
|---|---|
| PHP | `.php`, `PHPSESSID`, `X-Powered-By: PHP`, PHP 오류, WordPress, Laravel |
| JSP/Java | `.jsp`, `.do`, `.action`, `JSESSIONID`, Tomcat, WebLogic, Spring |
| ASP/.NET | `.asp`, `.aspx`, ASP.NET 세션, ViewState, ASP.NET Core |
| Node.js/JS | Node.js, Express, `connect.sid`, Next.js, Nuxt, Vue.js, Remix |

새 기술은 해당 모듈의 `signatures` 또는 `route_suffixes`에 추가합니다. 완전히 새로운 계열은 `TechnologyModule`을 상속한 파일을 만들고 `scan_modules/__init__.py`에 등록합니다.

### 6. 증거 우선순위와 복수 기술

기본 우선순위는 다음과 같습니다.

```text
URL 확장자/경로 > 세션 쿠키 > 응답 헤더 > HTML 본문
```

강한 증거와 프런트엔드 증거가 함께 있으면 복수 기술을 출력할 수 있습니다.

```text
Server=Apache | Framework=JSP/Java; Nuxt; Vue.js
```

예를 들어 `JSESSIONID`는 Java Servlet 계열의 강한 단서이고, Nuxt/Vue는 같은 서비스 앞단의 프런트엔드일 수 있습니다. Nuxt 본문만으로 Node.js 백엔드 런타임을 확정하지 않습니다.

`.do` 경로에서 PHP 버전 문자열이 발견되는 것처럼 강한 경로 증거와 약한 본문 증거가 충돌하면, 약한 증거는 상세 결과에 남기되 CLI 프레임워크 요약에는 올리지 않습니다.

### 7. 오류 응답 처리

- HTTP `404`와 `500~599` 응답은 기술 모듈의 경로·헤더·본문 증거로 사용하지 않습니다.
- 해당 응답의 일반 `Server` 정보는 자산 정보로 유지할 수 있습니다.
- `401`이나 `403`은 접근제어 앞에서 반환될 수 있으므로 상태 코드만으로 특정 런타임을 확정하지 않습니다.

### 8. HTML, JavaScript와 백엔드 경로

- 시작 HTML의 링크, 폼, iframe, script와 generator 메타 태그를 분석합니다.
- 동일 호스트 JavaScript만 `--max-js` 한도까지 추가로 읽습니다.
- `.php`, `.jsp`, `.do`, `.asp` 등 서버가 HTML/JS에서 실제로 노출한 경로는 `--max-backend-links` 한도까지 확인합니다.
- 브라우저 JavaScript 파일이라는 이유만으로 Node.js 서버로 판정하지 않습니다.

### 9. 스캐너가 생성한 경로

PHP 정보 페이지와 WordPress 경로는 스캐너가 직접 만든 후보입니다.

```text
/phpinfo.php
/info.php
/status.php
/wp-login.php
/wp-json/
```

이러한 URL의 `.php` 확장자는 기술 증거로 사용하지 않습니다. `403`이나 일반 fallback 페이지가 반환돼도 PHP로 탐지하지 않습니다. 실제 응답에서 PHP 버전, phpinfo 내용, PHP 헤더 또는 PHP 세션 쿠키가 확인될 때만 PHP 증거로 등록합니다.

WordPress 경로는 기본적으로 기존 HTML·헤더에 WordPress 단서가 있을 때만 확인하고, `--probe-wordpress`를 사용하면 강제로 실행합니다.

## 판정과 CLI 색상

- `[탐지]`: 서버·인프라 또는 선택 기술 단서를 하나 이상 확인
- `[미탐]`: DNS/IP만 확인했거나 응답에서 기술 정보를 식별하지 못함

`[탐지]`는 취약 판정이나 런타임 확정을 의미하지 않습니다.

CLI 색상:

| 값 | 색상 |
|---|---|
| 탐지 | 초록색 |
| 미탐 | 회색 |
| 서버·인프라 제품 | 청록색 |
| PHP | 자홍색 |
| JSP/Java | 노란색 |
| ASP/.NET | 파란색 |
| Node.js/Nuxt/Vue | 초록색 |

색상 코드는 상세 TXT와 CSV에 저장하지 않습니다.

## 결과 파일

### 상세 TXT

`-o` 결과에는 다음 항목을 저장합니다.

- 전체 탐지/미탐 요약
- 입력 도메인, DNS IP, 최종 URL과 HTTP 상태
- 서버, 프레임워크와 노출 버전
- 스캔 유형별 실행 결과
- 기술 모듈별 원본 증거와 출처 URL
- 실제로 추가 요청한 JS, 백엔드, 정보 페이지와 WordPress 경로
- 네트워크 및 범위 오류
- 파일 마지막의 색상 없는 CLI 결과 요약

### CSV

CSV 열은 다음과 같습니다.

```text
no,status,url,domain,ip,server,framework,version,remarks
```

- `ip`에는 DNS가 가장 먼저 반환한 주소만 저장합니다.
- 두 번째 이후 IP는 `remarks`에 `추가 IP: ...` 형식으로 저장합니다.
- `framework`에는 상세 기술 이름을 저장할 수 있습니다.
- 버전은 응답에 실제 노출된 문자열이며 설치 패키지나 패치 상태를 보증하지 않습니다.

## 한계

- DNS IP는 실제 원본 서버 IP가 아닐 수 있습니다.
- 응답 헤더는 프록시, CDN 또는 관리자가 변경할 수 있습니다.
- 쿠키 이름은 강한 단서지만 임의로 같은 이름을 사용할 수도 있습니다.
- SPA fallback과 사용자 정의 오류 페이지는 요청 확장자와 무관한 프런트엔드를 반환할 수 있습니다.
- JavaScript 실행 후 생성되는 DOM과 동적 API 호출은 현재 `requests` 기반 수집에서 보지 못합니다.
- 로그인 후에만 나타나는 기술은 비인증 스캔에서 확인되지 않을 수 있습니다.
- 배포판 백포트와 실제 설치 버전은 원격 노출 문자열만으로 확인할 수 없습니다.

허가된 대상에서만 사용하고, 결과는 후속 자산 확인을 위한 1차 조사 자료로 취급하세요.
