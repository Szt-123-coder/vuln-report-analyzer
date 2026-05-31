import json
import os
import re
from typing import Any, Dict, List

from dotenv import load_dotenv
from openai import OpenAI
from pydantic import ValidationError

from models import Severity, VulnerabilityAnalysis


load_dotenv()


class AnalyzerError(Exception):
    """Base exception for analyzer failures."""


class InvalidLLMResponseError(AnalyzerError):
    """Raised when an LLM response cannot be parsed or validated."""


VULNERABILITY_KEYWORDS = {
    "SQL Injection": ["sql injection", "sqli", "union select", "database error"],
    "Cross-Site Scripting": ["xss", "cross-site scripting", "<script", "javascript:"],
    "Server-Side Request Forgery": ["ssrf", "server-side request forgery", "metadata"],
    "Command Injection": ["command injection", "remote code execution", "rce", "shell"],
    "Authentication Bypass": ["auth bypass", "authentication bypass", "unauthorized"],
    "Insecure Direct Object Reference": ["idor", "direct object reference"],
    "Information Disclosure": ["information disclosure", "leak", "exposed", "debug"],
    "Access Control": ["privilege escalation", "access control", "permission"],
}


SEVERITY_KEYWORDS = {
    Severity.CRITICAL: ["critical", "rce", "remote code execution", "system compromise"],
    Severity.HIGH: ["high", "sql injection", "authentication bypass", "privilege escalation"],
    Severity.MEDIUM: ["medium", "xss", "ssrf", "information disclosure"],
    Severity.LOW: ["low", "missing header", "minor", "informational"],
}


def analyze_report(report_text: str, use_llm: bool = False) -> VulnerabilityAnalysis:
    if use_llm:
        return analyze_with_llm(report_text)
    return analyze_with_mock(report_text)


def analyze_with_mock(report_text: str) -> VulnerabilityAnalysis:
    normalized = report_text.lower()
    vulnerability_type = _detect_vulnerability_type(normalized)
    severity = _detect_severity(normalized, vulnerability_type)
    affected_component = _detect_affected_component(report_text)
    evidence = _extract_evidence(report_text)
    title = _make_title(vulnerability_type, affected_component)

    return VulnerabilityAnalysis(
        title=title,
        summary=(
            f"The report appears to describe {vulnerability_type.lower()} affecting "
            f"{affected_component}. The mock analyzer assigned {severity.value} "
            "severity based on keywords, exploitability indicators, and impact language."
        ),
        vulnerability_type=vulnerability_type,
        affected_component=affected_component,
        severity=severity,
        impact=_mock_impact(severity, vulnerability_type, affected_component),
        evidence=evidence,
        remediation=_mock_remediation(vulnerability_type),
        confidence=_mock_confidence(normalized, evidence),
    )


def analyze_with_llm(report_text: str) -> VulnerabilityAnalysis:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise AnalyzerError(
            "OPENAI_API_KEY is not set. Choose mock mode or add an API key to your environment."
        )

    client = OpenAI(
        api_key=api_key,
        base_url=os.getenv("OPENAI_BASE_URL") or None,
    )
    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    try:
        response = client.chat.completions.create(
            model=model,
            temperature=0.1,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You convert vulnerability reports into validated JSON for triage. "
                        "Return only one JSON object with these exact keys: title, summary, "
                        "vulnerability_type, affected_component, severity, impact, evidence, "
                        "remediation, confidence. severity must be Low, Medium, High, or "
                        "Critical. evidence must be an array of strings. remediation must "
                        "be a single string, not an array. confidence must be a number from "
                        "0 to 1."
                    ),
                },
                {
                    "role": "user",
                    "content": f"Analyze this vulnerability report:\n\n{report_text}",
                },
            ],
        )
    except Exception as exc:
        raise AnalyzerError(f"LLM request failed: {exc}") from exc

    content = response.choices[0].message.content or ""
    return _parse_llm_json(content)


def _parse_llm_json(content: str) -> VulnerabilityAnalysis:
    json_text = _extract_json_object(content)
    try:
        payload: Dict[str, Any] = json.loads(json_text)
    except json.JSONDecodeError as exc:
        raise InvalidLLMResponseError(
            "The LLM response was not valid JSON. Try again or use mock mode."
        ) from exc

    try:
        return VulnerabilityAnalysis.model_validate(payload)
    except ValidationError as exc:
        raise InvalidLLMResponseError(
            f"The LLM returned JSON, but it did not match the expected schema: {exc}"
        ) from exc


def _extract_json_object(content: str) -> str:
    stripped = content.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\s*", "", stripped)
        stripped = re.sub(r"\s*```$", "", stripped)

    start = stripped.find("{")
    end = stripped.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise InvalidLLMResponseError(
            "The LLM response did not include a JSON object. Try again or use mock mode."
        )
    return stripped[start : end + 1]


def _detect_vulnerability_type(normalized_text: str) -> str:
    for vulnerability_type, keywords in VULNERABILITY_KEYWORDS.items():
        if any(keyword in normalized_text for keyword in keywords):
            return vulnerability_type
    return "Security Misconfiguration"


def _detect_severity(normalized_text: str, vulnerability_type: str) -> Severity:
    for severity, keywords in SEVERITY_KEYWORDS.items():
        if any(keyword in normalized_text for keyword in keywords):
            return severity

    if vulnerability_type in {"Command Injection", "Authentication Bypass"}:
        return Severity.HIGH
    if vulnerability_type in {"SQL Injection", "Server-Side Request Forgery"}:
        return Severity.HIGH
    if vulnerability_type in {"Cross-Site Scripting", "Information Disclosure"}:
        return Severity.MEDIUM
    return Severity.LOW


def _detect_affected_component(report_text: str) -> str:
    patterns = [
        r"(?:endpoint|url|route|path)\s*[:=-]\s*([^\n\r]+)",
        r"(?:component|module|service)\s*[:=-]\s*([^\n\r]+)",
        r"(?:affected component|affected asset)\s*[:=-]\s*([^\n\r]+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, report_text, flags=re.IGNORECASE)
        if match:
            return match.group(1).strip()[:200]
    return "Unspecified application component"


def _extract_evidence(report_text: str) -> List[str]:
    lines = [line.strip("-* \t") for line in report_text.splitlines() if line.strip()]
    evidence_markers = (
        "evidence",
        "proof",
        "poc",
        "request",
        "response",
        "payload",
        "observed",
        "error",
        "endpoint",
        "url",
    )
    evidence = [
        line[:300]
        for line in lines
        if any(marker in line.lower() for marker in evidence_markers)
    ]
    if evidence:
        return evidence[:5]

    compact = re.sub(r"\s+", " ", report_text).strip()
    return [compact[:300] or "Report text was provided but no specific evidence was detected."]


def _make_title(vulnerability_type: str, affected_component: str) -> str:
    if affected_component == "Unspecified application component":
        return f"Potential {vulnerability_type}"
    return f"Potential {vulnerability_type} in {affected_component}"


def _mock_impact(
    severity: Severity,
    vulnerability_type: str,
    affected_component: str,
) -> str:
    if severity in {Severity.CRITICAL, Severity.HIGH}:
        return (
            f"Attackers may exploit the {vulnerability_type.lower()} issue in "
            f"{affected_component} to gain unauthorized access, alter sensitive data, "
            "or disrupt application behavior."
        )
    if severity == Severity.MEDIUM:
        return (
            f"The issue may expose users or systems to meaningful security risk if "
            f"{affected_component} is reachable by untrusted users."
        )
    return (
        f"The issue appears limited, but hardening {affected_component} would reduce "
        "attack surface and prevent escalation with other weaknesses."
    )


def _mock_remediation(vulnerability_type: str) -> str:
    remediation_map = {
        "SQL Injection": (
            "Use parameterized queries or prepared statements, avoid string-built SQL, "
            "and add regression tests for malicious input."
        ),
        "Cross-Site Scripting": (
            "Encode untrusted output, sanitize rich text inputs, apply a restrictive "
            "Content Security Policy, and test dangerous payloads."
        ),
        "Server-Side Request Forgery": (
            "Validate outbound request destinations, deny private network ranges, and "
            "use an allowlist for approved upstream services."
        ),
        "Command Injection": (
            "Avoid shell execution for user-controlled input, use safe library calls, "
            "and enforce strict allowlists for command arguments."
        ),
        "Authentication Bypass": (
            "Centralize authorization checks, enforce authentication on every sensitive "
            "route, and add tests for anonymous and low-privilege users."
        ),
        "Insecure Direct Object Reference": (
            "Verify object ownership on every request, avoid predictable identifiers "
            "where possible, and add authorization tests across tenants."
        ),
        "Information Disclosure": (
            "Remove sensitive data from responses and logs, disable debug output in "
            "production, and review access controls around exposed resources."
        ),
        "Access Control": (
            "Apply least-privilege authorization checks server-side and test each role "
            "against restricted actions."
        ),
    }
    return remediation_map.get(
        vulnerability_type,
        "Validate configuration, restrict risky defaults, and add security regression tests.",
    )


def _mock_confidence(normalized_text: str, evidence: List[str]) -> float:
    confidence = 0.45
    if len(normalized_text) > 500:
        confidence += 0.15
    if len(evidence) >= 2:
        confidence += 0.15
    if any(keyword in normalized_text for keyword in ("poc", "payload", "request", "response")):
        confidence += 0.15
    if any(keyword in normalized_text for keyword in ("cvss", "cwe", "severity")):
        confidence += 0.1
    return min(round(confidence, 2), 0.95)
