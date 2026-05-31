import json

import streamlit as st
from dotenv import load_dotenv
from pypdf import PdfReader

from analyzer import AnalyzerError, InvalidLLMResponseError, analyze_report
from database import get_analysis_history, init_db, save_analysis
from models import EVIDENCE_NOT_IDENTIFIED


load_dotenv()
init_db()


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
            ["All", "Critical", "High", "Medium", "Low"],
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


st.title("AI-assisted Vulnerability Report Analysis Tool")
st.caption(
    "Paste or upload a vulnerability report, validate the structured triage output, "
    "and store the result in SQLite."
)

analyze_tab, history_tab = st.tabs(["Analyze", "History"])

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
