# AI-assisted Vulnerability Report Analysis Tool

A Python Streamlit app that turns unstructured vulnerability reports into validated, structured security triage records. The first working path is a mock analyzer, so the app runs without an API key. Optional OpenAI-compatible LLM support can be enabled with environment variables.

## Features

- Paste a vulnerability report or upload a `.txt`, `.md`, or `.pdf` file.
- Convert report text into structured fields for vulnerability triage.
- Validate every analysis result with a Pydantic schema.
- Store raw reports and structured JSON results in SQLite.
- Review previous analyses in a built-in History tab.
- Run offline with mock analyzer mode.
- Optionally use a real OpenAI-compatible LLM API.
- Show clear errors when an LLM returns malformed JSON or schema-invalid data.

## Structured Output

Each analysis includes:

- `title`
- `summary`
- `vulnerability_type`
- `affected_component`
- `severity`: `Low`, `Medium`, `High`, or `Critical`
- `impact`
- `evidence`: list of strings
- `remediation`
- `confidence`: float between `0` and `1`

## Setup

```bash
pip install -r requirements.txt
streamlit run app.py
```

The app creates `vulnerability_reports.db` automatically in the project directory.

## File Uploads

Text and Markdown uploads are read directly. PDF uploads are processed with `pypdf` and text is extracted from every page before analysis.

PDF extraction only works when the PDF contains selectable text. If a PDF is scanned or image-based, the app shows:

```text
No extractable text found. This PDF may be scanned or image-based.
```

## Mock Analyzer

Mock mode is the default path and does not require network access or an API key. It uses keyword-based heuristics to estimate vulnerability type, affected component, severity, evidence, impact, remediation, and confidence.

This makes the project easy to run for demos, coursework, and local development before integrating a real LLM.

## Optional LLM Analyzer

Set `OPENAI_API_KEY` to enable LLM mode:

```bash
OPENAI_API_KEY=your_api_key_here streamlit run app.py
```

For OpenAI-compatible providers, you can also set:

```bash
OPENAI_BASE_URL=https://your-compatible-provider.example/v1
OPENAI_MODEL=your-model-name
```

You can place these variables in a `.env` file:

```env
OPENAI_API_KEY=your_api_key_here
OPENAI_BASE_URL=https://api.openai.com/v1
OPENAI_MODEL=gpt-4o-mini
```

LLM mode asks the model to return a single JSON object. The app then parses and validates that object with Pydantic. If the model returns non-JSON text, missing fields, invalid severity values, or a confidence outside `0` to `1`, the app displays a clear validation error instead of saving bad data.

## How It Demonstrates LLM-assisted Vulnerability Triage

Security reports often arrive as free-form notes, proof-of-concept snippets, screenshots, payloads, or partial reproduction steps. This app demonstrates an LLM-assisted workflow by converting that unstructured text into consistent triage fields that can be reviewed, searched, stored, and compared.

The Pydantic model acts as a guardrail around the AI output. SQLite persistence turns each analysis into an auditable record, while mock mode proves the end-to-end workflow before any real API integration is required.
