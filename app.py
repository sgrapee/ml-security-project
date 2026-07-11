from __future__ import annotations

import streamlit as st

from rule_generator import (
    generate_rule_suggestion,
    save_generated_rule,
    suggestion_from_dict,
    suggestion_to_dict,
)
from scanner import Finding, scan_code


DEFAULT_CODE = """import os

user_input = input("command: ")
os.system(user_input)
"""

DEFAULT_GENERATOR_CODE = """import pickle

data = input("data: ")
obj = pickle.loads(data)
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
    st.info(f"Fix: {finding.fix}")


def render_scanner_tab() -> None:
    left, right = st.columns([0.58, 0.42])

    with left:
        language_name = st.selectbox("Language", list(LANGUAGES.keys()), key="scan_language")
        code = st.text_area("Source Code", value=DEFAULT_CODE, height=430, key="scan_code")
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


def render_rule_generator_tab() -> None:
    st.subheader("AI Rule Generator")
    st.write(
        "기존 규칙으로 잡히지 않는 코드가 있을 때, AI 또는 로컬 추천기가 새 탐지 규칙 후보를 만듭니다. "
        "후보를 확인한 뒤 저장하면 다음 분석부터 fallback 규칙으로 적용됩니다."
    )

    left, right = st.columns([0.54, 0.46])

    with left:
        language_name = st.selectbox("Language", list(LANGUAGES.keys()), key="generator_language")
        vulnerability_hint = st.text_input(
            "Vulnerability hint",
            placeholder="예: insecure deserialization, eval usage, hardcoded secret",
        )
        generator_code = st.text_area(
            "Code to learn from",
            value=DEFAULT_GENERATOR_CODE,
            height=360,
            key="generator_code",
        )
        generate = st.button("Generate Rule Candidate", type="primary", use_container_width=True)

    if generate:
        if not generator_code.strip():
            st.warning("규칙을 만들 기준 코드가 필요합니다.")
        else:
            with st.spinner("규칙 후보를 생성하는 중입니다..."):
                suggestion = generate_rule_suggestion(
                    generator_code,
                    LANGUAGES[language_name],
                    vulnerability_hint,
                )
            st.session_state["rule_suggestion"] = suggestion_to_dict(suggestion)

    with right:
        suggestion_data = st.session_state.get("rule_suggestion")

        if not suggestion_data:
            st.info("취약한 코드 예시를 넣고 규칙 후보 생성 버튼을 누르세요.")
            return

        suggestion = suggestion_from_dict(suggestion_data)
        st.caption(f"Generator source: {suggestion.source}")
        st.markdown(f"### {suggestion.severity} - {suggestion.title}")
        st.write(suggestion.explanation)

        editable_pattern = st.text_input("Fallback regex", value=suggestion.pattern)
        editable_rule_id = st.text_input("Rule ID", value=suggestion.rule_id)
        editable_message = st.text_area("Message", value=suggestion.message, height=90)
        editable_fix = st.text_area("Fix guidance", value=suggestion.fix, height=90)

        st.markdown("Semgrep YAML candidate")
        st.code(suggestion.semgrep_yaml, language="yaml")

        if st.button("Add Rule", use_container_width=True):
            edited_suggestion = suggestion_from_dict(
                {
                    **suggestion_to_dict(suggestion),
                    "pattern": editable_pattern,
                    "rule_id": editable_rule_id,
                    "message": editable_message,
                    "fix": editable_fix,
                }
            )
            try:
                path = save_generated_rule(edited_suggestion)
            except Exception as exc:
                st.error(f"규칙 저장 실패: {exc}")
            else:
                st.success(f"규칙이 저장되었습니다: {path}")
                st.info("Scanner 탭으로 돌아가서 같은 코드를 다시 분석해보세요.")


st.set_page_config(
    page_title="Source Code Vulnerability Scanner",
    page_icon="🔍",
    layout="wide",
)

st.title("Source Code Vulnerability Scanner")
st.caption("Semgrep + fallback rules + AI-assisted rule generation")

scanner_tab, generator_tab = st.tabs(["Scanner", "AI Rule Generator"])

with scanner_tab:
    render_scanner_tab()

with generator_tab:
    render_rule_generator_tab()
