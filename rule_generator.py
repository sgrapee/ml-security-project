from __future__ import annotations

import json
import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import requests

from scanner import GENERATED_RULE_PATH, LANGUAGE_EXTENSIONS, load_generated_rules


OPENAI_RESPONSES_URL = "https://api.openai.com/v1/responses"
DEFAULT_MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")


@dataclass
class RuleSuggestion:
    language: str
    pattern: str
    severity: str
    title: str
    message: str
    fix: str
    rule_id: str
    semgrep_yaml: str
    explanation: str
    source: str


LOCAL_TEMPLATES = [
    {
        "languages": ["python"],
        "needle": r"\beval\s*\(",
        "pattern": r"\beval\s*\(",
        "severity": "ERROR",
        "title": "Dangerous eval usage",
        "message": "eval() executes strings as code and can lead to arbitrary code execution.",
        "fix": "Avoid eval(). Use a safe parser or explicit allowlisted operations instead.",
        "rule_id": "generated.python.dangerous-eval",
        "semgrep_pattern": "eval($VALUE)",
    },
    {
        "languages": ["python"],
        "needle": r"\bexec\s*\(",
        "pattern": r"\bexec\s*\(",
        "severity": "ERROR",
        "title": "Dangerous exec usage",
        "message": "exec() can execute attacker-controlled Python code.",
        "fix": "Avoid exec(). Replace dynamic code execution with explicit functions or allowlisted commands.",
        "rule_id": "generated.python.dangerous-exec",
        "semgrep_pattern": "exec($VALUE)",
    },
    {
        "languages": ["python"],
        "needle": r"\bpickle\.loads\s*\(",
        "pattern": r"\bpickle\.loads\s*\(",
        "severity": "ERROR",
        "title": "Insecure deserialization with pickle",
        "message": "pickle.loads() can execute code when deserializing untrusted data.",
        "fix": "Do not use pickle for untrusted input. Prefer JSON or another safe data format.",
        "rule_id": "generated.python.insecure-pickle-loads",
        "semgrep_pattern": "pickle.loads($DATA)",
    },
    {
        "languages": ["python"],
        "needle": r"debug\s*=\s*True",
        "pattern": r"debug\s*=\s*True",
        "severity": "WARNING",
        "title": "Debug mode enabled",
        "message": "Debug mode can expose stack traces and sensitive application internals.",
        "fix": "Disable debug mode in production and load the setting from a safe environment configuration.",
        "rule_id": "generated.python.debug-enabled",
        "semgrep_pattern": "app.run(..., debug=True, ...)",
    },
    {
        "languages": ["javascript", "typescript"],
        "needle": r"\beval\s*\(",
        "pattern": r"\beval\s*\(",
        "severity": "ERROR",
        "title": "Dangerous JavaScript eval usage",
        "message": "eval() can execute attacker-controlled JavaScript code.",
        "fix": "Avoid eval(). Use JSON.parse for data or explicit allowlisted behavior.",
        "rule_id": "generated.javascript.dangerous-eval",
        "semgrep_pattern": "eval($VALUE)",
    },
    {
        "languages": ["javascript", "typescript"],
        "needle": r"localStorage\.setItem\s*\([^)]*(token|jwt|password|secret)",
        "pattern": r"localStorage\.setItem\s*\([^)]*(token|jwt|password|secret)",
        "severity": "WARNING",
        "title": "Sensitive value stored in localStorage",
        "message": "Tokens or secrets in localStorage can be stolen by XSS.",
        "fix": "Store sensitive session data in secure, HttpOnly cookies when possible.",
        "rule_id": "generated.javascript.localstorage-secret",
        "semgrep_pattern": "localStorage.setItem($KEY, $VALUE)",
    },
    {
        "languages": ["php"],
        "needle": r"\b(eval|shell_exec|system|passthru)\s*\(",
        "pattern": r"\b(eval|shell_exec|system|passthru)\s*\(",
        "severity": "ERROR",
        "title": "Dangerous PHP execution function",
        "message": "Dangerous PHP execution functions can lead to code or command injection.",
        "fix": "Avoid dynamic execution and validate any command arguments with an allowlist.",
        "rule_id": "generated.php.dangerous-execution",
        "semgrep_pattern": "eval($VALUE)",
    },
    {
        "languages": ["java"],
        "needle": r"Runtime\.getRuntime\(\)\.exec\s*\(",
        "pattern": r"Runtime\.getRuntime\(\)\.exec\s*\(",
        "severity": "ERROR",
        "title": "Possible Java command injection",
        "message": "Runtime.exec() can execute attacker-controlled OS commands.",
        "fix": "Use ProcessBuilder with separated arguments and validate values with an allowlist.",
        "rule_id": "generated.java.runtime-exec",
        "semgrep_pattern": "Runtime.getRuntime().exec($CMD)",
    },
]


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", value.lower()).strip("-")
    return slug or "custom-rule"


def _semgrep_yaml(language: str, rule_id: str, severity: str, message: str, title: str, fix: str, pattern: str) -> str:
    return "\n".join(
        [
            f"- id: {rule_id.replace('generated.', 'ai-')}",
            "  languages:",
            f"    - {language}",
            f"  severity: {severity}",
            f"  message: {message}",
            "  metadata:",
            f"    title: {title}",
            f"    fix: {fix}",
            f"  pattern: {pattern}",
        ]
    )


def _fallback_from_template(code: str, language: str) -> RuleSuggestion | None:
    for template in LOCAL_TEMPLATES:
        if language not in template["languages"]:
            continue
        if re.search(template["needle"], code, flags=re.IGNORECASE | re.MULTILINE):
            return RuleSuggestion(
                language=language,
                pattern=template["pattern"],
                severity=template["severity"],
                title=template["title"],
                message=template["message"],
                fix=template["fix"],
                rule_id=template["rule_id"].replace("javascript", language),
                semgrep_yaml=_semgrep_yaml(
                    language=language,
                    rule_id=template["rule_id"].replace("javascript", language),
                    severity=template["severity"],
                    message=template["message"],
                    title=template["title"],
                    fix=template["fix"],
                    pattern=template["semgrep_pattern"],
                ),
                explanation="Local rule generator matched a known risky API pattern in the submitted code.",
                source="local",
            )

    title = f"Review suspicious {language} code"
    rule_id = f"generated.{language}.{_slugify(title)}"
    return RuleSuggestion(
        language=language,
        pattern=r"(TODO_REPLACE_WITH_REGEX)",
        severity="WARNING",
        title=title,
        message="The code may contain a security issue, but no built-in local template matched it.",
        fix="Review data flow from user input to sensitive APIs and replace this placeholder regex before saving.",
        rule_id=rule_id,
        semgrep_yaml=_semgrep_yaml(
            language=language,
            rule_id=rule_id,
            severity="WARNING",
            message="Potential security issue. Review this code path before production use.",
            title=title,
            fix="Replace this placeholder with a precise Semgrep pattern.",
            pattern="$X",
        ),
        explanation="No API key was available and the local generator did not recognize a known pattern.",
        source="local",
    )


def _extract_text_from_response(payload: dict[str, Any]) -> str:
    if isinstance(payload.get("output_text"), str):
        return payload["output_text"]

    parts: list[str] = []
    for item in payload.get("output", []):
        for content in item.get("content", []):
            text = content.get("text")
            if isinstance(text, str):
                parts.append(text)
    return "\n".join(parts)


def _generate_with_openai(code: str, language: str, vulnerability_hint: str) -> RuleSuggestion:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY is not set.")

    prompt = {
        "language": language,
        "vulnerability_hint": vulnerability_hint,
        "code": code,
        "instructions": (
            "Return only JSON with keys: pattern, severity, title, message, fix, "
            "rule_id, semgrep_yaml, explanation. The pattern must be a Python regex "
            "for a fallback scanner. The Semgrep YAML must be one rule item, not a full rules document."
        ),
    }

    response = requests.post(
        OPENAI_RESPONSES_URL,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": DEFAULT_MODEL,
            "input": [
                {
                    "role": "system",
                    "content": (
                        "You generate cautious source-code security scanner rules. "
                        "Prefer precise patterns over broad noisy patterns."
                    ),
                },
                {"role": "user", "content": json.dumps(prompt, ensure_ascii=False)},
            ],
        },
        timeout=45,
    )
    response.raise_for_status()

    text = _extract_text_from_response(response.json()).strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?", "", text).strip()
        text = re.sub(r"```$", "", text).strip()

    data = json.loads(text)
    return RuleSuggestion(
        language=language,
        pattern=str(data["pattern"]),
        severity=str(data.get("severity", "WARNING")).upper(),
        title=str(data["title"]),
        message=str(data["message"]),
        fix=str(data["fix"]),
        rule_id=str(data.get("rule_id", f"generated.{language}.{_slugify(data['title'])}")),
        semgrep_yaml=str(data["semgrep_yaml"]),
        explanation=str(data.get("explanation", "Generated by AI from the submitted code.")),
        source="openai",
    )


def generate_rule_suggestion(code: str, language: str, vulnerability_hint: str = "") -> RuleSuggestion:
    normalized_language = language.lower()
    if normalized_language not in LANGUAGE_EXTENSIONS:
        raise ValueError(f"Unsupported language: {language}")

    if os.getenv("OPENAI_API_KEY"):
        try:
            return _generate_with_openai(code, normalized_language, vulnerability_hint)
        except Exception as exc:
            suggestion = _fallback_from_template(code, normalized_language)
            suggestion.explanation = f"OpenAI generation failed, so local generator was used. Reason: {exc}"
            return suggestion

    return _fallback_from_template(code, normalized_language)


def validate_regex(pattern: str) -> None:
    if "TODO_REPLACE_WITH_REGEX" in pattern:
        raise ValueError("Replace the placeholder regex before saving this rule.")
    re.compile(pattern)


def save_generated_rule(suggestion: RuleSuggestion) -> Path:
    validate_regex(suggestion.pattern)

    generated_rules = load_generated_rules()
    language_rules = generated_rules.setdefault(suggestion.language, [])
    new_rule = {
        "pattern": suggestion.pattern,
        "severity": suggestion.severity,
        "title": suggestion.title,
        "message": suggestion.message,
        "fix": suggestion.fix,
        "rule_id": suggestion.rule_id,
    }

    language_rules[:] = [
        rule for rule in language_rules if rule.get("rule_id") != suggestion.rule_id
    ]
    language_rules.append(new_rule)

    GENERATED_RULE_PATH.parent.mkdir(parents=True, exist_ok=True)
    GENERATED_RULE_PATH.write_text(
        json.dumps(generated_rules, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return GENERATED_RULE_PATH


def suggestion_to_dict(suggestion: RuleSuggestion) -> dict[str, Any]:
    return asdict(suggestion)


def suggestion_from_dict(data: dict[str, Any]) -> RuleSuggestion:
    return RuleSuggestion(**data)
