import json
import re

import streamlit as st
from dotenv import load_dotenv
from pypdf import PdfReader

from analyzer import AnalyzerError, InvalidLLMResponseError, analyze_report
from database import (
    get_analysis_by_ids,
    get_analysis_history,
    get_highest_severity_reports,
    init_db,
    save_analysis,
)
from models import EVIDENCE_NOT_IDENTIFIED


load_dotenv()
init_db()

SEVERITY_OPTIONS = ["All", "Critical", "High", "Medium", "Low", "Informational", "Info", "Unknown"]


st.set_page_config(
    page_title="AI-assisted Vulnerability Report Analysis Tool",
    page_icon=":shield:",
    layout="wide",
)


def extract_text_from_uploaded_file(uploaded_file) -> str:
    if uploaded_file is None:
        return ""

    filename = uploaded_file.name.lower()
    if filename.endswith(".pdf"):
        try:
            uploaded_file.seek(0)
            reader = PdfReader(uploaded_file)
            pages = [page.extract_text() or "" for page in reader.pages]
        except Exception as exc:
            st.error(f"Could not read PDF file: {exc}")
            return ""

        extracted_text = "\n\n".join(page.strip() for page in pages if page.strip())
        if not extracted_text:
            st.warning("No extractable text found. This PDF may be scanned or image-based.")
        return extracted_text

    try:
        return uploaded_file.getvalue().decode("utf-8")
    except UnicodeDecodeError:
        return uploaded_file.getvalue().decode("utf-8", errors="replace")


def evidence_text(value) -> str:
    if value is None:
        return EVIDENCE_NOT_IDENTIFIED
    cleaned = str(value).strip()
    return cleaned or EVIDENCE_NOT_IDENTIFIED


def render_field_with_evidence(label: str, value: str, evidence: str) -> None:
    st.markdown(f"**{label}:** {value}")
    st.caption(f"Evidence: {evidence_text(evidence)}")


def render_review_status(review_required: bool, review_reason: str) -> None:
    reason = review_reason.strip() if review_reason else "No review reason provided."
    if review_required:
        st.warning(f"Human review required: {reason}")
    else:
        st.success(f"No human review required: {reason}")


def format_confidence(value) -> str:
    try:
        score = float(value)
    except (TypeError, ValueError):
        score = 0.0
    return f"{score:.0%}"


def analysis_dict_value(analysis: dict, key: str, default: str = "Unavailable") -> str:
    value = analysis.get(key)
    if value is None or value == "":
        return default
    return str(value)


def render_history_field(
    label: str,
    analysis: dict,
    value_key: str,
    evidence_key: str,
) -> None:
    render_field_with_evidence(
        label,
        analysis_dict_value(analysis, value_key),
        analysis.get(evidence_key, EVIDENCE_NOT_IDENTIFIED),
    )


def affected_component_options(history: list[dict]) -> list[str]:
    components = sorted(
        {
            (item.get("analysis") or {}).get("affected_component", "").strip()
            for item in history
            if (item.get("analysis") or {}).get("affected_component", "").strip()
        },
        key=str.lower,
    )
    return ["All", *components]


def review_filter_value(label: str) -> bool | None:
    if label == "Review required":
        return True
    if label == "No review required":
        return False
    return None


def report_label(item: dict) -> str:
    analysis = item.get("analysis") or {}
    title = analysis.get("title", "Untitled analysis")
    severity = item.get("severity", analysis.get("severity", "Unknown"))
    component = analysis.get("affected_component", "Unknown component")
    return f"#{item['id']} | {severity} | {component} | {title}"


def evidence_is_missing(value) -> bool:
    return evidence_text(value) == EVIDENCE_NOT_IDENTIFIED


def evidence_is_weak(value) -> bool:
    text = evidence_text(value)
    if text == EVIDENCE_NOT_IDENTIFIED:
        return True
    return len(text.split()) < 4


def evidence_completeness(analysis: dict) -> int:
    evidence_fields = (
        "severity_evidence",
        "impact_evidence",
        "remediation_evidence",
        "affected_component_evidence",
    )
    return sum(0 if evidence_is_weak(analysis.get(field)) else 1 for field in evidence_fields)


def report_column_label(item: dict) -> str:
    return f"Report #{item['id']}"


def comparison_label_map(reports: list[dict]) -> dict[int, str]:
    return {int(item["id"]): f"Report #{index + 1}" for index, item in enumerate(reports)}


def comparison_label(item: dict, labels: dict[int, str]) -> str:
    return labels.get(int(item["id"]), report_column_label(item))


GENERIC_SECURITY_STOPWORDS = {
    "access",
    "application",
    "attacker",
    "attackers",
    "behavior",
    "behaviour",
    "could",
    "data",
    "exploit",
    "exploited",
    "gain",
    "impact",
    "issue",
    "sensitive",
    "system",
    "unauthorized",
    "vulnerability",
}

GENERIC_SECURITY_PHRASES = (
    "attacker may exploit",
    "gain unauthorized access",
    "disrupt application behavior",
    "disrupt application behaviour",
    "sensitive data",
)

PLACEHOLDER_VALUES = {
    "n/a",
    "none",
    "not specified",
    "unavailable",
    "unknown",
    "unspecified",
    "unspecified application component",
}

STRONG_SIMILARITY_SIGNALS = {
    "same vulnerability type",
    "same affected component",
    "similar affected component",
    "similar title keywords with similar remediation theme",
}


def normalize_text(value) -> str:
    if isinstance(value, list):
        value = " ".join(str(item) for item in value)
    text = str(value or "").lower()
    text = re.sub(r"[^a-z0-9/_-]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def remove_generic_security_phrases(value) -> str:
    text = normalize_text(value)
    for phrase in GENERIC_SECURITY_PHRASES:
        normalized_phrase = normalize_text(phrase)
        text = re.sub(rf"\b{re.escape(normalized_phrase)}\b", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def tokenize_keywords(value) -> set[str]:
    stopwords = {
        "and",
        "are",
        "for",
        "from",
        "has",
        "into",
        "may",
        "not",
        "the",
        "this",
        "use",
        "user",
        "users",
        "with",
        "vulnerability",
        "potential",
        "report",
        "evidence",
        "severity",
        "critical",
        "high",
        "medium",
        "low",
        "informational",
        "info",
        "endpoint",
        "payload",
        "observed",
        "response",
        "returned",
        "data",
    } | GENERIC_SECURITY_STOPWORDS
    return {
        token
        for token in remove_generic_security_phrases(value).split()
        if len(token) > 2 and token not in stopwords
    }


def is_meaningful_text(value) -> bool:
    text = normalize_text(value)
    return bool(text) and text not in PLACEHOLDER_VALUES


def token_similarity(left, right) -> float:
    left_tokens = tokenize_keywords(left)
    right_tokens = tokenize_keywords(right)
    if not left_tokens or not right_tokens:
        return 0.0
    return len(left_tokens & right_tokens) / len(left_tokens | right_tokens)


def overlapping_keyword_count(left, right) -> int:
    return len(tokenize_keywords(left) & tokenize_keywords(right))


def combined_evidence_text(analysis: dict) -> str:
    values = [
        analysis.get("severity_evidence", ""),
        analysis.get("impact_evidence", ""),
        analysis.get("remediation_evidence", ""),
        analysis.get("affected_component_evidence", ""),
    ]
    evidence = analysis.get("evidence", [])
    if isinstance(evidence, list):
        values.extend(evidence)
    else:
        values.append(evidence)
    return " ".join(str(value) for value in values)


def affected_components_are_similar(component_a, component_b) -> bool:
    if not is_meaningful_text(component_a) or not is_meaningful_text(component_b):
        return False
    normalized_a = normalize_text(component_a)
    normalized_b = normalize_text(component_b)
    return normalized_a == normalized_b or token_similarity(component_a, component_b) >= 0.5


def vulnerability_types_match(type_a, type_b) -> bool:
    return is_meaningful_text(type_a) and is_meaningful_text(type_b) and normalize_text(type_a) == normalize_text(type_b)


def vulnerability_types_differ(type_a, type_b) -> bool:
    return is_meaningful_text(type_a) and is_meaningful_text(type_b) and normalize_text(type_a) != normalize_text(type_b)


def affected_components_differ(component_a, component_b) -> bool:
    return (
        is_meaningful_text(component_a)
        and is_meaningful_text(component_b)
        and not affected_components_are_similar(component_a, component_b)
    )


def calculate_similarity_signals(report_a: dict, report_b: dict) -> list[str]:
    analysis_a = report_a.get("analysis") or {}
    analysis_b = report_b.get("analysis") or {}
    signals = []

    component_a = analysis_a.get("affected_component")
    component_b = analysis_b.get("affected_component")
    if is_meaningful_text(component_a) and is_meaningful_text(component_b):
        if normalize_text(component_a) == normalize_text(component_b):
            signals.append("same affected component")
        elif affected_components_are_similar(component_a, component_b):
            signals.append("similar affected component")

    type_a = analysis_a.get("vulnerability_type")
    type_b = analysis_b.get("vulnerability_type")
    if vulnerability_types_match(type_a, type_b):
        signals.append("same vulnerability type")

    title_similar = (
        token_similarity(analysis_a.get("title", ""), analysis_b.get("title", "")) >= 0.45
        and overlapping_keyword_count(analysis_a.get("title", ""), analysis_b.get("title", "")) >= 2
    )

    remediation_similar = (
        token_similarity(analysis_a.get("remediation", ""), analysis_b.get("remediation", "")) >= 0.35
        and overlapping_keyword_count(analysis_a.get("remediation", ""), analysis_b.get("remediation", "")) >= 2
    )

    if title_similar and remediation_similar:
        signals.append("similar title keywords with similar remediation theme")

    if overlapping_keyword_count(
        combined_evidence_text(analysis_a),
        combined_evidence_text(analysis_b),
    ) >= 3:
        signals.append("overlapping evidence keywords")

    if remediation_similar:
        signals.append("similar remediation theme")

    if (
        token_similarity(analysis_a.get("impact", ""), analysis_b.get("impact", "")) >= 0.35
        and overlapping_keyword_count(analysis_a.get("impact", ""), analysis_b.get("impact", "")) >= 2
    ):
        signals.append("similar impact wording")

    return signals


def has_strong_similarity_signal(signals: list[str]) -> bool:
    return any(signal in STRONG_SIMILARITY_SIGNALS for signal in signals)


def has_different_type_and_component(report_a: dict, report_b: dict) -> bool:
    analysis_a = report_a.get("analysis") or {}
    analysis_b = report_b.get("analysis") or {}
    return vulnerability_types_differ(
        analysis_a.get("vulnerability_type"),
        analysis_b.get("vulnerability_type"),
    ) and affected_components_differ(
        analysis_a.get("affected_component"),
        analysis_b.get("affected_component"),
    )


def find_related_report_pairs(selected_reports: list[dict]) -> list[dict]:
    related_pairs = []
    for left_index, left in enumerate(selected_reports):
        for right in selected_reports[left_index + 1 :]:
            if has_different_type_and_component(left, right):
                continue
            signals = calculate_similarity_signals(left, right)
            if has_strong_similarity_signal(signals):
                related_pairs.append(
                    {
                        "left": left,
                        "right": right,
                        "signals": signals,
                    }
                )
    return related_pairs


def format_list(items: list[str]) -> str:
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    if len(items) == 2:
        return f"{items[0]} and {items[1]}"
    return f"{', '.join(items[:-1])}, and {items[-1]}"


def plural_verb(items: list[str], singular: str, plural: str) -> str:
    return singular if len(items) == 1 else plural


def sentence(text: str) -> str:
    cleaned = text.strip()
    if not cleaned:
        return ""
    if cleaned.endswith((".", "!", "?")):
        return cleaned
    return f"{cleaned}."


def join_sentences(parts: list[str]) -> str:
    return " ".join(sentence(part) for part in parts if part.strip())


def truncate_text(value, max_chars: int = 240) -> str:
    text = str(value or "")
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 3].rstrip() + "..."


def render_analysis_result(analysis) -> None:
    severity_to_type = {
        "Low": "success",
        "Medium": "info",
        "High": "warning",
        "Critical": "error",
    }
    alert = getattr(st, severity_to_type.get(analysis.severity.value, "info"))
    alert(f"{analysis.severity.value} severity: {analysis.title}")

    left, right = st.columns([2, 1])
    with left:
        st.subheader("Structured analysis")
        render_field_with_evidence(
            "Summary",
            analysis.summary,
            analysis.summary_evidence,
        )
        render_field_with_evidence(
            "Severity",
            analysis.severity.value,
            analysis.severity_evidence,
        )
        st.markdown(f"**Vulnerability type:** {analysis.vulnerability_type}")
        render_field_with_evidence(
            "Affected component",
            analysis.affected_component,
            analysis.affected_component_evidence,
        )
        render_field_with_evidence(
            "Impact",
            analysis.impact,
            analysis.impact_evidence,
        )
        render_field_with_evidence(
            "Remediation",
            analysis.remediation,
            analysis.remediation_evidence,
        )

    with right:
        st.metric("Confidence score", format_confidence(analysis.confidence_score))
        render_review_status(analysis.review_required, analysis.review_reason)
        st.markdown("**Evidence**")
        if analysis.evidence:
            for item in analysis.evidence:
                st.write(f"- {item}")
        else:
            st.write(f"- {EVIDENCE_NOT_IDENTIFIED}")

    with st.expander("Validated JSON output", expanded=False):
        st.json(json.loads(analysis.model_dump_json()))


def render_history() -> None:
    st.subheader("Previous analysis results")
    all_history = get_analysis_history(limit=1000)
    if not all_history:
        st.info("No analysis results have been saved yet.")
        return

    search_query = st.text_input(
        "Search history",
        placeholder="Search title, summary, impact, remediation, component, or evidence",
    )
    severity_col, component_col, review_col, sort_col = st.columns([1, 2, 1, 1])
    with severity_col:
        selected_severity = st.selectbox(
            "Severity",
            SEVERITY_OPTIONS,
        )
    with component_col:
        selected_component = st.selectbox(
            "Affected component",
            affected_component_options(all_history),
        )
    with review_col:
        selected_review = st.selectbox(
            "Review status",
            ["All", "Review required", "No review required"],
        )
    with sort_col:
        selected_sort = st.selectbox(
            "Sort",
            ["Newest first", "Oldest first"],
        )

    history = get_analysis_history(
        limit=200,
        search_query=search_query,
        severity=None if selected_severity == "All" else selected_severity,
        affected_component=None if selected_component == "All" else selected_component,
        review_required=review_filter_value(selected_review),
        sort_desc=(selected_sort == "Newest first"),
    )

    if not history:
        st.info("No matching reports found")
        return

    st.caption(f"Showing {len(history)} matching report(s).")

    for item in history:
        analysis = item.get("analysis") or {}
        title = analysis.get("title", "Untitled analysis")
        component = analysis.get("affected_component", "Unknown component")
        review_label = (
            "Review required"
            if bool(analysis.get("review_required", False))
            else "No review required"
        )
        label = (
            f"#{item['id']} | {item['created_at']} | {item['severity']} | "
            f"{review_label} | {component} | {title}"
        )
        with st.expander(label):
            confidence_score = analysis.get("confidence_score", analysis.get("confidence", 0.0))
            st.metric("Confidence score", format_confidence(confidence_score))
            render_review_status(
                bool(analysis.get("review_required", False)),
                analysis.get("review_reason", "No review required."),
            )
            render_history_field("Summary", analysis, "summary", "summary_evidence")
            render_history_field("Severity", analysis, "severity", "severity_evidence")
            render_history_field(
                "Affected component",
                analysis,
                "affected_component",
                "affected_component_evidence",
            )
            render_history_field("Impact", analysis, "impact", "impact_evidence")
            render_history_field(
                "Remediation",
                analysis,
                "remediation",
                "remediation_evidence",
            )

            raw_tab, json_tab = st.tabs(["Raw report", "Structured JSON"])
            with raw_tab:
                st.code(item["raw_report"], language="text")
            with json_tab:
                if item.get("analysis") is not None:
                    st.json(item["analysis"])
                else:
                    st.code(item["structured_json"], language="json")


def render_highest_severity() -> None:
    st.subheader("Highest Severity Reports")
    all_reports = get_analysis_history(limit=1000)
    if not all_reports:
        st.info("No analysed reports available.")
        return

    top_col, severity_col, component_col, review_col = st.columns([1, 1, 2, 1])
    with top_col:
        top_n = st.number_input("Top N", min_value=1, max_value=100, value=10, step=1)
    with severity_col:
        selected_severity = st.selectbox("Severity", SEVERITY_OPTIONS, key="top_severity")
    with component_col:
        selected_component = st.selectbox(
            "Affected component",
            affected_component_options(all_reports),
            key="top_component",
        )
    with review_col:
        selected_review = st.selectbox(
            "Review status",
            ["All", "Review required", "No review required"],
            key="top_review",
        )

    search_query = st.text_input(
        "Keyword search",
        placeholder="Search title, summary, impact, remediation, component, or evidence",
        key="top_search",
    )

    reports = get_highest_severity_reports(
        limit=int(top_n),
        search_query=search_query,
        severity=None if selected_severity == "All" else selected_severity,
        affected_component=None if selected_component == "All" else selected_component,
        review_required=review_filter_value(selected_review),
    )
    if not reports:
        st.info("No matching reports found.")
        return

    rows = []
    for item in reports:
        analysis = item.get("analysis") or {}
        rows.append(
            {
                "Title": analysis.get("title", "Untitled analysis"),
                "Severity": item.get("severity", analysis.get("severity", "Unknown")),
                "Confidence": format_confidence(
                    analysis.get("confidence_score", item.get("confidence_score", 0.0))
                ),
                "Review required": "Yes" if analysis.get("review_required") else "No",
                "Affected component": analysis.get("affected_component", "Unavailable"),
                "Summary": analysis.get("summary", "Unavailable"),
                "Created at": item.get("created_at", ""),
            }
        )
    st.caption(
        "Sorted by severity priority, then confidence score, then newest created time."
    )
    st.dataframe(rows, width="stretch", hide_index=True)


def render_compare_reports() -> None:
    st.subheader("Compare Reports")
    all_reports = get_analysis_history(limit=1000)
    if not all_reports:
        st.info("No analysed reports available.")
        return

    label_to_id = {report_label(item): int(item["id"]) for item in all_reports}
    selected_labels = st.multiselect(
        "Select reports to compare",
        list(label_to_id.keys()),
        placeholder="Choose at least two reports",
    )
    if len(selected_labels) < 2:
        st.info("Select at least two reports to compare.")
        return

    selected_ids = [label_to_id[label] for label in selected_labels]
    reports = get_analysis_by_ids(selected_ids)
    if len(reports) < 2:
        st.info("Select at least two reports to compare.")
        return

    labels = comparison_label_map(reports)
    render_selected_report_titles(reports, labels)
    render_comparison_summary(reports, labels)
    st.dataframe(build_comparison_rows(reports, labels), width="stretch", hide_index=True)


def render_selected_report_titles(reports: list[dict], labels: dict[int, str]) -> None:
    title_rows = []
    for item in reports:
        analysis = item.get("analysis") or {}
        title_rows.append(
            {
                "Report": comparison_label(item, labels),
                "Record ID": f"#{item['id']}",
                "Title": analysis.get("title", "Untitled analysis"),
                "Severity": item.get("severity", analysis.get("severity", "Unknown")),
                "Affected component": truncate_text(analysis.get("affected_component", "Unavailable"), 120),
            }
        )
    st.markdown("**Selected reports**")
    st.dataframe(title_rows, width="stretch", hide_index=True)


def render_comparison_summary(reports: list[dict], labels: dict[int, str]) -> None:
    st.markdown("### Comparison Summary")
    priority = get_priority_report(reports)
    render_priority_recommendation(priority, reports, labels)
    render_risk_difference_summary(reports, priority, labels)
    render_evidence_quality_summary(reports, labels)
    render_remediation_comparison(reports, priority, labels)
    render_similarity_summary(reports, labels)


def get_priority_report(reports: list[dict]) -> dict:
    return max(
        reports,
        key=lambda item: (
            int(item.get("severity_rank", 0)),
            float((item.get("analysis") or {}).get("confidence_score", item.get("confidence_score", 0.0))),
            0 if bool((item.get("analysis") or {}).get("review_required", False)) else 1,
            evidence_completeness(item.get("analysis") or {}),
        ),
    )


def render_priority_recommendation(
    priority: dict,
    reports: list[dict],
    labels: dict[int, str],
) -> None:
    analysis = priority.get("analysis") or {}
    label = comparison_label(priority, labels)
    tied_severity = [
        item
        for item in reports
        if int(item.get("severity_rank", 0)) == int(priority.get("severity_rank", 0))
    ]
    confidence = format_confidence(analysis.get("confidence_score", priority.get("confidence_score", 0.0)))
    review_status = "requires human review" if analysis.get("review_required") else "does not currently require human review"
    evidence_score = evidence_completeness(analysis)

    sentences = [
        (
            f"Prioritise {label}. It has severity "
            f"{priority.get('severity', analysis.get('severity', 'Unknown'))} "
            f"(rank {priority.get('severity_rank', 0)}) with {confidence} confidence."
        ),
        f"It {review_status} and has {evidence_score}/4 key evidence fields present.",
    ]
    if len(tied_severity) > 1:
        sentences.append(
            "Severity is tied, so confidence, review status, and evidence completeness were used as tie-breakers."
        )
    st.warning("**Priority recommendation:** " + join_sentences(sentences))


def summarize_field_differences(
    reports: list[dict],
    labels: dict[int, str],
    field_name: str,
    display_name: str,
) -> str:
    values = {}
    for item in reports:
        analysis = item.get("analysis") or {}
        values[comparison_label(item, labels)] = analysis.get(field_name, "Unavailable")
    unique_values = {normalize_text(value) for value in values.values()}
    if len(unique_values) <= 1:
        return f"{display_name} is consistent across selected reports."
    return (
        f"{display_name} differs: "
        + "; ".join(f"{label}: {truncate_text(value, 120)}" for label, value in values.items())
    )


def render_risk_difference_summary(
    reports: list[dict],
    priority: dict,
    labels: dict[int, str],
) -> None:
    priority_analysis = priority.get("analysis") or {}
    priority_label = comparison_label(priority, labels)
    severity_values = {
        comparison_label(item, labels): item.get("severity", (item.get("analysis") or {}).get("severity", "Unknown"))
        for item in reports
    }
    same_severity = len({int(item.get("severity_rank", 0)) for item in reports}) == 1

    if same_severity:
        urgency = (
            "Severity is tied across the selected reports. "
            "Prioritisation uses confidence, review status, and evidence completeness as tie-breakers. "
            f"{priority_label} appears more urgent based on its impact: "
            f"{truncate_text(priority_analysis.get('impact', 'Unavailable'), 180)}"
        )
    else:
        urgency = (
            "Severity differs across the selected reports. "
            f"{priority_label} carries the highest ranked risk."
        )

    details = [
        "Severity comparison: "
        + "; ".join(f"{label}: {severity}" for label, severity in severity_values.items()),
        summarize_field_differences(reports, labels, "vulnerability_type", "Vulnerability type"),
        summarize_field_differences(reports, labels, "affected_component", "Affected component"),
        summarize_field_differences(reports, labels, "impact", "Impact"),
        urgency,
    ]
    st.info("**Risk difference:** " + join_sentences(details))


def evidence_field_label(field: str) -> str:
    labels = {
        "severity_evidence": "severity",
        "impact_evidence": "impact",
        "remediation_evidence": "remediation",
        "affected_component_evidence": "affected-component",
    }
    return labels.get(field, field.replace("_", " "))


def render_evidence_quality_summary(reports: list[dict], labels: dict[int, str]) -> None:
    evidence_fields = (
        "severity_evidence",
        "impact_evidence",
        "remediation_evidence",
        "affected_component_evidence",
    )
    scores = []
    findings = []
    for item in reports:
        analysis = item.get("analysis") or {}
        missing = [
            evidence_field_label(field)
            for field in evidence_fields
            if evidence_is_weak(analysis.get(field))
        ]
        label = comparison_label(item, labels)
        score = evidence_completeness(analysis)
        scores.append((score, label))
        if missing:
            findings.append(
                f"{label} is missing or has weak {format_list(missing)} evidence."
            )

    max_score = max(score for score, _ in scores)
    min_score = min(score for score, _ in scores)
    strongest = [label for score, label in scores if score == max_score]
    weakest = [label for score, label in scores if score == min_score]

    if findings:
        summary = (
            (
                f"{format_list(strongest)} "
                f"{plural_verb(strongest, 'has', 'have')} stronger overall evidence."
            )
            if strongest != weakest
            else "The selected reports have similar overall evidence quality."
        )
        extra_details = [
            summary,
            (
                f"{format_list(weakest)} "
                f"{plural_verb(weakest, 'has', 'have')} the weakest evidence profile."
                if strongest != weakest
                else ""
            ),
            join_sentences(findings),
            "Reports with weak evidence should receive human review before final triage.",
        ]
        st.warning("**Evidence quality:** " + join_sentences(extra_details))
    else:
        st.success(
            "**Evidence quality:** The selected reports include adequate field-level evidence for severity, "
            "impact, remediation, and affected component."
        )


def render_remediation_comparison(
    reports: list[dict],
    priority: dict,
    labels: dict[int, str],
) -> None:
    remediations = [
        ((item.get("analysis") or {}).get("remediation", "").strip(), comparison_label(item, labels))
        for item in reports
    ]
    normalized = {re.sub(r"\s+", " ", remediation.lower()) for remediation, _ in remediations if remediation}
    if len(normalized) <= 1:
        relationship = "The remediation guidance is similar or overlapping across selected reports."
    else:
        relationship = "The remediation guidance differs across selected reports."

    priority_remediation = (priority.get("analysis") or {}).get("remediation", "Unavailable")
    st.info(
        "**Remediation comparison:** "
        f"{relationship} Start with {comparison_label(priority, labels)} because it is the priority "
        f"risk. Recommended action: {truncate_text(priority_remediation, 180)}"
    )


def render_similarity_summary(reports: list[dict], labels: dict[int, str]) -> None:
    related_pairs = find_related_report_pairs(reports)

    if related_pairs:
        descriptions = [
            (
                f"{comparison_label(pair['left'], labels)} and {comparison_label(pair['right'], labels)} "
                f"({format_list(pair['signals'])})"
            )
            for pair in related_pairs
        ]
        st.info("**Possible duplicate or related reports:** " + "; ".join(descriptions))
    else:
        st.info("**Possible duplicate or related reports:** No strong duplicate or related-report signal detected.")


def build_comparison_rows(reports: list[dict], labels: dict[int, str]) -> list[dict]:
    fields = [
        ("Title", lambda item, analysis: analysis.get("title", "Untitled analysis")),
        ("Severity", lambda item, analysis: item.get("severity", analysis.get("severity", "Unknown"))),
        ("Severity evidence", lambda item, analysis: evidence_text(analysis.get("severity_evidence"))),
        (
            "Confidence score",
            lambda item, analysis: format_confidence(
                analysis.get("confidence_score", item.get("confidence_score", 0.0))
            ),
        ),
        (
            "Review required",
            lambda item, analysis: "Yes" if analysis.get("review_required") else "No",
        ),
        (
            "Review reason",
            lambda item, analysis: analysis.get("review_reason", "No review reason provided."),
        ),
        (
            "Affected component",
            lambda item, analysis: analysis.get("affected_component", "Unavailable"),
        ),
        ("Impact", lambda item, analysis: analysis.get("impact", "Unavailable")),
        ("Remediation", lambda item, analysis: analysis.get("remediation", "Unavailable")),
        ("Created at", lambda item, analysis: item.get("created_at", "")),
    ]

    rows = []
    for field_label, value_getter in fields:
        row = {"Field": field_label}
        for item in reports:
            analysis = item.get("analysis") or {}
            row[comparison_label(item, labels)] = truncate_text(value_getter(item, analysis))
        rows.append(row)
    return rows


st.title("AI-assisted Vulnerability Report Analysis Tool")
st.caption(
    "Paste or upload a vulnerability report, validate the structured triage output, "
    "and store the result in SQLite."
)

analyze_tab, history_tab, highest_tab, compare_tab = st.tabs(
    ["Analyze", "History", "Highest Severity", "Compare Reports"]
)

with analyze_tab:
    st.subheader("Report input")
    uploaded_file = st.file_uploader(
        "Upload a .txt, .md, or .pdf vulnerability report",
        type=["txt", "md", "pdf"],
    )
    uploaded_text = extract_text_from_uploaded_file(uploaded_file)

    report_text = st.text_area(
        "Paste vulnerability report",
        value=uploaded_text,
        height=280,
        placeholder=(
            "Example: Endpoint: /api/search\n"
            "The q parameter appears vulnerable to SQL injection. Payload: ' OR '1'='1 ..."
        ),
    )

    mode = st.radio(
        "Analyzer mode",
        options=["Mock analyzer", "LLM analyzer"],
        horizontal=True,
        help="Mock mode works offline. LLM mode uses OPENAI_API_KEY and optional OPENAI_BASE_URL.",
    )

    if st.button("Analyze report", type="primary"):
        cleaned_report = report_text.strip()
        if not cleaned_report:
            st.error("Paste a report or upload a .txt/.md/.pdf file before analyzing.")
        else:
            try:
                with st.spinner("Analyzing report..."):
                    analysis = analyze_report(
                        cleaned_report,
                        use_llm=(mode == "LLM analyzer"),
                    )
                    result_id = save_analysis(cleaned_report, analysis)
                st.success(f"Analysis saved to SQLite with record ID {result_id}.")
                render_analysis_result(analysis)
            except InvalidLLMResponseError as exc:
                st.error(str(exc))
                st.info(
                    "The response must be a single JSON object matching the expected schema. "
                    "Switch to mock mode if you want to continue without an LLM."
                )
            except AnalyzerError as exc:
                st.error(str(exc))
            except Exception as exc:
                st.error(f"Unexpected analysis error: {exc}")

with history_tab:
    render_history()

with highest_tab:
    render_highest_severity()

with compare_tab:
    render_compare_reports()
