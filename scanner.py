from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT_DIR = Path(__file__).resolve().parent
RULE_PATH = ROOT_DIR / "rules" / "custom-security.yml"
GENERATED_RULE_PATH = ROOT_DIR / "rules" / "generated-fallback-rules.json"

LANGUAGE_EXTENSIONS = {
    "python": ".py",
    "javascript": ".js",
    "typescript": ".ts",
    "php": ".php",
    "java": ".java",
    "c": ".c",
    "cpp": ".cpp",
}

FALLBACK_RULES = {
    "python": [
        {
            "pattern": r"\bos\.system\s*\(",
            "severity": "ERROR",
            "title": "Possible command injection",
            "message": "os.system()에 사용자 입력값이 전달되면 Command Injection 위험이 있습니다.",
            "fix": "subprocess.run을 리스트 인자와 함께 사용하고, 허용된 명령어만 실행하도록 제한하세요.",
            "rule_id": "fallback.python.command-injection",
        },
        {
            "pattern": r"\.execute\s*\([^)]*(\+|\.format\(|f[\"'])",
            "severity": "ERROR",
            "title": "Possible SQL injection",
            "message": "문자열 결합 또는 포매팅으로 SQL 쿼리를 만들면 SQL Injection 위험이 있습니다.",
            "fix": "파라미터 바인딩 또는 ORM의 안전한 쿼리 API를 사용하세요.",
            "rule_id": "fallback.python.sql-injection",
        },
        {
            "pattern": r"\bopen\s*\(",
            "severity": "WARNING",
            "title": "Possible path traversal",
            "message": "사용자 입력값이 파일 경로로 직접 사용되면 Path Traversal 위험이 있습니다.",
            "fix": "허용된 디렉터리 내부 경로인지 검증하고, 파일명 화이트리스트를 적용하세요.",
            "rule_id": "fallback.python.path-traversal",
        },
    ],
    "javascript": [
        {
            "pattern": r"\.innerHTML\s*=",
            "severity": "ERROR",
            "title": "Possible XSS through innerHTML",
            "message": "검증되지 않은 값이 innerHTML에 삽입되면 XSS 위험이 있습니다.",
            "fix": "textContent를 사용하거나 HTML sanitizer를 적용하세요.",
            "rule_id": "fallback.javascript.xss",
        },
        {
            "pattern": r"\b(exec|child_process\.exec)\s*\(",
            "severity": "ERROR",
            "title": "Possible command injection",
            "message": "사용자 입력값이 shell 명령 실행에 사용될 수 있습니다.",
            "fix": "exec 대신 execFile/spawn을 사용하고, 인자를 배열로 분리하세요.",
            "rule_id": "fallback.javascript.command-injection",
        },
    ],
    "typescript": [],
    "php": [
        {
            "pattern": r"(mysqli_query|->query)\s*\([^)]*\.",
            "severity": "ERROR",
            "title": "Possible SQL injection",
            "message": "문자열 결합으로 SQL 쿼리를 생성하면 SQL Injection 위험이 있습니다.",
            "fix": "prepared statement와 bound parameter를 사용하세요.",
            "rule_id": "fallback.php.sql-injection",
        },
    ],
    "java": [
        {
            "pattern": r"\.execute(Query|Update)?\s*\([^)]*\+",
            "severity": "ERROR",
            "title": "Possible SQL injection",
            "message": "문자열 결합으로 SQL 쿼리를 실행하면 SQL Injection 위험이 있습니다.",
            "fix": "Statement 대신 PreparedStatement를 사용하세요.",
            "rule_id": "fallback.java.sql-injection",
        },
    ],
    "c": [
        {
            "pattern": r"\b(gets|strcpy|strcat)\s*\(",
            "severity": "ERROR",
            "title": "Possible buffer overflow",
            "message": "gets, strcpy, strcat 같은 함수는 Buffer Overflow 위험이 있습니다.",
            "fix": "fgets, strncpy, strncat처럼 크기를 제한할 수 있는 함수를 사용하세요.",
            "rule_id": "fallback.c.buffer-overflow",
        },
    ],
    "cpp": [],
}

FALLBACK_RULES["typescript"] = FALLBACK_RULES["javascript"]
FALLBACK_RULES["cpp"] = FALLBACK_RULES["c"]


def load_generated_rules() -> dict[str, list[dict[str, str]]]:
    if not GENERATED_RULE_PATH.exists():
        return {}

    try:
        raw_rules = json.loads(GENERATED_RULE_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}

    if not isinstance(raw_rules, dict):
        return {}

    generated_rules: dict[str, list[dict[str, str]]] = {}
    for language, rules in raw_rules.items():
        if not isinstance(language, str) or not isinstance(rules, list):
            continue

        valid_rules = []
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            required_keys = {"pattern", "severity", "title", "message", "fix", "rule_id"}
            if required_keys.issubset(rule):
                valid_rules.append({key: str(rule[key]) for key in required_keys})

        if valid_rules:
            generated_rules[language] = valid_rules

    return generated_rules


def get_fallback_rules(language: str) -> list[dict[str, str]]:
    built_in_rules = list(FALLBACK_RULES.get(language, []))
    generated_rules = load_generated_rules().get(language, [])
    return built_in_rules + generated_rules


@dataclass
class Finding:
    severity: str
    title: str
    message: str
    file_path: str
    line: int
    column: int
    rule_id: str
    fix: str


def _run_semgrep(target: Path) -> dict[str, Any]:
    command = [
        "semgrep",
        "scan",
        "--config",
        str(RULE_PATH),
        "--json",
        "--quiet",
        str(target),
    ]

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            encoding="utf-8",
        )
    except FileNotFoundError as exc:
        raise RuntimeError(
            "Semgrep is not installed. Run `pip install -r requirements.txt` first."
        ) from exc

    if completed.stdout.strip():
        try:
            return json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            output = completed.stderr.strip() or completed.stdout.strip()
            raise RuntimeError(output or "Semgrep did not return valid JSON.") from exc

    if completed.returncode not in (0, 1):
        raise RuntimeError(completed.stderr.strip() or "Semgrep scan failed.")

    return {"results": []}


def _line_and_column(code: str, offset: int) -> tuple[int, int]:
    prefix = code[:offset]
    line = prefix.count("\n") + 1
    last_newline = prefix.rfind("\n")
    column = offset + 1 if last_newline == -1 else offset - last_newline
    return line, column


def _fallback_scan_code(code: str, language: str, file_path: str = "input") -> list[Finding]:
    findings: list[Finding] = []

    for rule in get_fallback_rules(language):
        for match in re.finditer(rule["pattern"], code, flags=re.MULTILINE):
            line, column = _line_and_column(code, match.start())
            findings.append(
                Finding(
                    severity=rule["severity"],
                    title=rule["title"],
                    message=rule["message"],
                    file_path=file_path,
                    line=line,
                    column=column,
                    rule_id=rule["rule_id"],
                    fix=rule["fix"],
                )
            )

    severity_order = {"ERROR": 0, "WARNING": 1, "INFO": 2}
    return sorted(findings, key=lambda finding: severity_order.get(finding.severity, 3))


def _to_findings(raw_result: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []

    for item in raw_result.get("results", []):
        extra = item.get("extra", {})
        metadata = extra.get("metadata", {})
        start = item.get("start", {})

        findings.append(
            Finding(
                severity=extra.get("severity", "INFO"),
                title=metadata.get("title", item.get("check_id", "Security finding")),
                message=extra.get("message", ""),
                file_path=item.get("path", ""),
                line=start.get("line", 0),
                column=start.get("col", 0),
                rule_id=item.get("check_id", ""),
                fix=metadata.get("fix", "Review this code and validate user-controlled input."),
            )
        )

    severity_order = {"ERROR": 0, "WARNING": 1, "INFO": 2}
    return sorted(findings, key=lambda finding: severity_order.get(finding.severity, 3))


def scan_file(file_path: str | Path) -> list[Finding]:
    target = Path(file_path).resolve()
    if not target.exists():
        raise FileNotFoundError(f"File not found: {target}")

    try:
        findings = _to_findings(_run_semgrep(target))
    except RuntimeError as exc:
        extension = target.suffix.lower()
        language = next(
            (lang for lang, ext in LANGUAGE_EXTENSIONS.items() if ext == extension),
            "python",
        )
        return _fallback_scan_code(
            target.read_text(encoding="utf-8", errors="ignore"),
            language,
            str(target),
        )

    if findings:
        return findings

    extension = target.suffix.lower()
    language = next(
        (lang for lang, ext in LANGUAGE_EXTENSIONS.items() if ext == extension),
        "python",
    )
    return _fallback_scan_code(
        target.read_text(encoding="utf-8", errors="ignore"),
        language,
        str(target),
    )


def scan_code(code: str, language: str) -> list[Finding]:
    normalized_language = language.lower()
    extension = LANGUAGE_EXTENSIONS.get(normalized_language)
    if extension is None:
        supported = ", ".join(sorted(LANGUAGE_EXTENSIONS))
        raise ValueError(f"Unsupported language: {language}. Supported: {supported}")

    with tempfile.TemporaryDirectory(prefix="security-scan-") as temp_dir:
        target = Path(temp_dir) / f"input{extension}"
        target.write_text(code, encoding="utf-8")
        try:
            findings = _to_findings(_run_semgrep(target))
        except RuntimeError as exc:
            return _fallback_scan_code(code, normalized_language, str(target))

        if findings:
            return findings

        return _fallback_scan_code(code, normalized_language, str(target))


def print_findings(findings: list[Finding]) -> None:
    if not findings:
        print("No findings detected.")
        return

    for index, finding in enumerate(findings, start=1):
        print(f"[{index}] {finding.severity} - {finding.title}")
        print(f"    Rule: {finding.rule_id}")
        print(f"    Location: {finding.file_path}:{finding.line}:{finding.column}")
        print(f"    Message: {finding.message}")
        print(f"    Fix: {finding.fix}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Source code vulnerability scanner")
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--file", help="Path to a source file")
    input_group.add_argument("--code", help="Source code string to scan")
    parser.add_argument("--language", default="python", help="Language for --code input")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.file:
            findings = scan_file(args.file)
        else:
            findings = scan_code(args.code, args.language)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print_findings(findings)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
