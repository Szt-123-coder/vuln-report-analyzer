import json

import streamlit as st
from dotenv import load_dotenv
from pypdf import PdfReader

from analyzer import AnalyzerError, InvalidLLMResponseError, analyze_report
from database import get_analysis_history, init_db, save_analysis


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
        st.write(analysis.summary)
        st.markdown(f"**Vulnerability type:** {analysis.vulnerability_type}")
        st.markdown(f"**Affected component:** {analysis.affected_component}")
        st.markdown(f"**Impact:** {analysis.impact}")
        st.markdown(f"**Remediation:** {analysis.remediation}")

    with right:
        st.metric("Confidence", f"{analysis.confidence:.0%}")
        st.markdown("**Evidence**")
        for item in analysis.evidence:
            st.write(f"- {item}")

    with st.expander("Validated JSON output", expanded=False):
        st.json(json.loads(analysis.model_dump_json()))


def render_history() -> None:
    st.subheader("Previous analysis results")
    history = get_analysis_history()
    if not history:
        st.info("No analysis results have been saved yet.")
        return

    for item in history:
        analysis = item.get("analysis") or {}
        title = analysis.get("title", "Untitled analysis")
        label = (
            f"#{item['id']} | {item['created_at']} | {item['severity']} | "
            f"{item['vulnerability_type']} | {title}"
        )
        with st.expander(label):
            st.markdown(f"**Summary:** {analysis.get('summary', 'Unavailable')}")
            st.markdown(f"**Affected component:** {analysis.get('affected_component', 'Unavailable')}")
            st.markdown(f"**Remediation:** {analysis.get('remediation', 'Unavailable')}")

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
