# Source Code Vulnerability Scanner

사용자가 입력한 소스코드를 정적 분석하여 SQL Injection, XSS, Command Injection 같은 보안 취약점을 탐지하고, 위험도와 수정 방향을 보여주는 오픈소스 기반 보안 분석 프로젝트입니다.

이 프로젝트는 직접 취약점 탐지 엔진을 처음부터 만드는 대신, 오픈소스 정적 분석 도구인 Semgrep을 기반으로 사용합니다. 그 위에 코드 입력 UI, 사용자 정의 보안 규칙, 결과 요약, 수정 가이드를 추가하여 하나의 보안 분석 프로그램처럼 동작하도록 구성했습니다.

## 주요 기능

- 직접 소스코드 입력 후 취약점 분석
- Python, JavaScript, PHP, Java, C 계열 코드 분석 지원
- Semgrep 기반 정적 분석 실행
- 사용자 정의 보안 규칙 제공
- 위험도, 파일 위치, 취약점 설명, 수정 가이드 출력
- CLI와 웹 UI 모두 지원

## 탐지 대상 예시

| 취약점 유형 | 설명 |
| --- | --- |
| Command Injection | 사용자 입력값이 OS 명령어 실행에 직접 사용되는 경우 |
| SQL Injection | 사용자 입력값이 SQL 쿼리에 직접 연결되는 경우 |
| XSS | 검증되지 않은 값이 HTML/DOM에 직접 삽입되는 경우 |
| Path Traversal | 사용자 입력값이 파일 경로에 직접 사용되는 경우 |
| Insecure Deserialization | 신뢰할 수 없는 데이터를 역직렬화하는 경우 |

## 프로젝트 구조

```text
.
├── app.py
├── scanner.py
├── requirements.txt
├── rules
│   └── custom-security.yml
├── examples
│   ├── vulnerable_sample.py
│   └── vulnerable_sample.js
└── README.md
```

## 설치 방법

```bash
pip install -r requirements.txt
```

Semgrep이 정상적으로 설치되었는지 확인합니다.

```bash
semgrep --version
```

## 웹 UI 실행

```bash
streamlit run app.py
```

브라우저에서 열리는 화면에 코드를 입력하고 `Analyze Code` 버튼을 누르면 취약점 분석 결과를 확인할 수 있습니다.

## CLI 실행

예제 파일을 분석하려면 다음 명령어를 실행합니다.

```bash
python scanner.py --file examples/vulnerable_sample.py --language python
```

코드 문자열을 직접 분석할 수도 있습니다.

```bash
python scanner.py --code "import os\nos.system(input('cmd: '))" --language python
```

## 예시 입력

```python
import os

user_input = input("command: ")
os.system(user_input)
```

예상 결과:

```text
HIGH - Possible command injection
사용자 입력값이 OS 명령어 실행 함수에 직접 전달될 수 있습니다.
수정 방향: shell 명령어 실행을 피하고, 허용된 명령어만 실행하도록 제한합니다.
```

## 프로젝트 발전 방향

- GitHub Repository URL 입력 후 자동 clone 및 분석
- 분석 결과 HTML/PDF 리포트 생성
- Gitleaks 연동으로 API Key, Token, Password 유출 탐지 추가
- 취약점별 수정 예시 자동 생성
- CodeBERT 모델을 추가하여 규칙 기반 탐지와 AI 기반 분류 비교

## 사용한 오픈소스

- Semgrep: 오픈소스 정적 분석 도구
- Streamlit: 간단한 웹 UI 프레임워크

## 주의사항

이 프로젝트는 학습 및 방어 목적의 보안 분석 도구입니다. 본인이 소유하거나 허가받은 코드에 대해서만 분석을 수행해야 합니다.
