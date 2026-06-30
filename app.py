from __future__ import annotations

import streamlit as st

from scanner import Finding, scan_code


DEFAULT_CODE = """import os

user_input = input("command: ")
os.system(user_input)
"""


LANGUAGES = {
    "Python": "python",
    "JavaScript": "javascript",
    "TypeScript": "typescript",
    "PHP": "php",
    "Java": "java",
    "C": "c",
    "C++": "cpp",
}


def severity_label(severity: str) -> str:
    return {
        "ERROR": "HIGH",
        "WARNING": "MEDIUM",
        "INFO": "LOW",
    }.get(severity, severity)


def render_finding(finding: Finding) -> None:
    severity = severity_label(finding.severity)
    st.markdown(f"### {severity} - {finding.title}")
    st.write(finding.message)

    col1, col2 = st.columns(2)
    col1.metric("Line", finding.line)
    col2.metric("Column", finding.column)

    st.code(f"Rule: {finding.rule_id}", language="text")
    st.info(f"수정 방향: {finding.fix}")


st.set_page_config(
    page_title="Source Code Vulnerability Scanner",
    page_icon="🔍",
    layout="wide",
)

st.title("Source Code Vulnerability Scanner")
st.caption("Semgrep 기반 소스코드 취약점 분석 도구")

left, right = st.columns([0.58, 0.42])

with left:
    language_name = st.selectbox("Language", list(LANGUAGES.keys()))
    code = st.text_area("Source Code", value=DEFAULT_CODE, height=430)
    analyze = st.button("Analyze Code", type="primary", use_container_width=True)

with right:
    st.subheader("Analysis Result")

    if analyze:
        if not code.strip():
            st.warning("분석할 코드를 입력하세요.")
        else:
            try:
                findings = scan_code(code, LANGUAGES[language_name])
            except Exception as exc:
                st.error(str(exc))
            else:
                if not findings:
                    st.success("탐지된 취약점이 없습니다.")
                else:
                    st.warning(f"{len(findings)}개의 보안 이슈가 탐지되었습니다.")
                    for finding in findings:
                        with st.container(border=True):
                            render_finding(finding)
    else:
        st.write("코드를 입력한 뒤 분석 버튼을 누르면 결과가 여기에 표시됩니다.")
