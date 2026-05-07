# ML Security Project

AI 기반 소스코드 취약점 탐지 프로젝트

---

# 프로젝트 개요

GitHub 기반 소스코드를 수집하고,
CodeBERT 기반 머신러닝 모델을 활용하여
취약점 유형(SQL Injection, XSS, Command Injection 등)을
자동 분류하는 AI 모델을 개발하는 프로젝트.

---

# 프로젝트 목표

- GitHub 기반 취약 코드 수집
- 취약점 유형별 데이터셋 구축
- CodeBERT Fine-tuning 수행
- 취약점 유형 자동 분류 모델 구현
- 웹 기반 취약점 탐지 시스템 연동

---

# 탐지 대상 취약점

| 취약점 | 설명 |
|---|---|
| SQL Injection | SQL 쿼리 조작 공격 |
| XSS | 악성 스크립트 삽입 공격 |
| Command Injection | OS 명령어 실행 공격 |
| Path Traversal | 파일 경로 조작 공격 |
| Buffer Overflow | 메모리 오버플로우 공격 |

---

# 사용 기술

- Python
- HuggingFace Transformers
- CodeBERT
- PyTorch
- Google Colab
- GitHub

---

# 모델 구조

```text
GitHub Code
→ CSV Dataset
→ Tokenization
→ CodeBERT Fine-tuning
→ Vulnerability Classification
