# ML Security Project

AI 기반 소스코드 취약점 탐지 프로젝트입니다.  
기존 CodeBERT 기반 취약점 분류 실험 자료를 보존하면서, 실제로 바로 시연할 수 있는 Semgrep 기반 소스코드 취약점 스캐너를 함께 구성했습니다.

## 프로젝트 개요

이 프로젝트는 사용자가 입력한 소스코드 또는 예제 파일을 분석하여 SQL Injection, XSS, Command Injection, Path Traversal, Buffer Overflow 같은 보안 취약점을 탐지합니다.

프로젝트는 두 가지 방향으로 구성됩니다.

| 구분 | 설명 |
| --- | --- |
| Rule-based Scanner | Semgrep과 사용자 정의 규칙을 이용해 취약 코드 패턴을 탐지 |
| AI Model Experiment | GitHub 취약 코드 데이터셋과 CodeBERT를 이용해 취약점 유형을 분류 |

현재 바로 실행 가능한 결과물은 `app.py`, `scanner.py`, `rules/custom-security.yml`로 구성된 Semgrep 기반 스캐너입니다.

## 주요 기능

- 직접 소스코드 입력 후 취약점 분석
- Python, JavaScript, PHP, Java, C 계열 코드 분석 지원
- Semgrep 기반 정적 분석 실행
- Semgrep이 설치되어 있지 않아도 기본 fallback 탐지 규칙으로 데모 실행 가능
- AI Rule Generator를 통해 새로운 fallback 탐지 규칙 후보 생성 및 저장
- 위험도, 파일 위치, 취약점 설명, 수정 방향 출력
- CLI와 웹 UI 모두 지원
- 기존 CodeBERT 학습 코드와 데이터셋 보존

## 탐지 대상 취약점

| 취약점 유형 | 설명 |
| --- | --- |
| Command Injection | 사용자 입력값이 OS 명령어 실행에 직접 사용되는 경우 |
| SQL Injection | 사용자 입력값이 SQL 쿼리에 직접 연결되는 경우 |
| XSS | 검증되지 않은 값이 HTML/DOM에 직접 삽입되는 경우 |
| Path Traversal | 사용자 입력값이 파일 경로에 직접 사용되는 경우 |
| Buffer Overflow | 안전하지 않은 C/C++ 문자열 함수 사용으로 메모리 오버플로우가 발생할 수 있는 경우 |

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
├── dataset
│   └── github_vulnerability_dataset.csv
├── ml_security_model_code.py
└── README.md
```

## 설치 방법

```bash
pip install -r requirements.txt
```

Semgrep 설치 여부를 확인하려면 다음 명령어를 실행합니다.

```bash
semgrep --version
```

Semgrep이 설치되어 있지 않아도 `scanner.py`의 기본 fallback 규칙으로 간단한 탐지 데모는 실행됩니다.

## 웹 UI 실행

```bash
streamlit run app.py
```

브라우저에서 열리는 화면에 코드를 입력하고 `Analyze Code` 버튼을 누르면 취약점 분석 결과를 확인할 수 있습니다.

### AI Rule Generator 사용

웹 UI의 `AI Rule Generator` 탭에서 기존 규칙으로 탐지되지 않는 취약 코드 예시를 입력하면 새 탐지 규칙 후보를 만들 수 있습니다.

OpenAI API 키가 있으면 더 유연한 AI 규칙 생성을 사용합니다.

```bash
set OPENAI_API_KEY=your_api_key
streamlit run app.py
```

API 키가 없으면 로컬 템플릿 기반 추천기로 동작합니다. 생성된 fallback 규칙은 `rules/generated-fallback-rules.json`에 저장되고, 다음 분석부터 자동으로 적용됩니다.

## CLI 실행

Python 예제 파일 분석:

```bash
python scanner.py --file examples/vulnerable_sample.py --language python
```

JavaScript 예제 파일 분석:

```bash
python scanner.py --file examples/vulnerable_sample.js --language javascript
```

코드 문자열 직접 분석:

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

## CodeBERT 모델 실험

기존 `ml_security_model_code.py`는 GitHub에서 취약 코드 예제를 수집하고, CodeBERT 기반 모델을 fine-tuning하여 취약점 유형을 분류하는 실험 코드입니다.

모델 실험 흐름:

```text
GitHub Code
→ CSV Dataset
→ Tokenization
→ CodeBERT Fine-tuning
→ Vulnerability Classification
```

## 프로젝트 발전 방향

- GitHub Repository URL 입력 후 자동 clone 및 분석
- 분석 결과 HTML/PDF 리포트 생성
- Gitleaks 연동으로 API Key, Token, Password 유출 탐지 추가
- 취약점별 수정 예시 자동 생성
- Semgrep 규칙 기반 탐지와 CodeBERT AI 분류 결과 비교

## 사용한 오픈소스

- Semgrep: 오픈소스 정적 분석 도구
- Streamlit: 간단한 웹 UI 프레임워크
- CodeBERT: 소스코드 이해를 위한 Transformer 기반 모델

## 주의사항

이 프로젝트는 학습 및 방어 목적의 보안 분석 도구입니다. 본인이 소유하거나 허가받은 코드에 대해서만 분석을 수행해야 합니다.
