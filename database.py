import json
import os
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any, Dict, List

from models import EVIDENCE_NOT_IDENTIFIED, VulnerabilityAnalysis


DB_PATH = Path(os.getenv("VULN_REPORT_DB_PATH", "vulnerability_reports.db"))
EVIDENCE_FIELDS = (
    "summary_evidence",
    "severity_evidence",
    "impact_evidence",
    "remediation_evidence",
    "affected_component_evidence",
)
REVIEW_DEFAULTS = {
    "confidence_score": 0.0,
    "review_required": False,
    "review_reason": "No review required.",
}


def get_connection(db_path: Path = DB_PATH) -> sqlite3.Connection:
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    return connection


def init_db(db_path: Path = DB_PATH) -> None:
    with closing(get_connection(db_path)) as connection:
        with connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS analysis_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    raw_report TEXT NOT NULL,
                    structured_json TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    vulnerability_type TEXT NOT NULL,
                    confidence_score REAL NOT NULL DEFAULT 0,
                    review_required INTEGER NOT NULL DEFAULT 0,
                    review_reason TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                )
                """
            )
            _ensure_columns(connection)


def _ensure_columns(connection: sqlite3.Connection) -> None:
    existing_columns = {
        row["name"] for row in connection.execute("PRAGMA table_info(analysis_results)")
    }
    migrations = {
        "confidence_score": "ALTER TABLE analysis_results ADD COLUMN confidence_score REAL NOT NULL DEFAULT 0",
        "review_required": "ALTER TABLE analysis_results ADD COLUMN review_required INTEGER NOT NULL DEFAULT 0",
        "review_reason": "ALTER TABLE analysis_results ADD COLUMN review_reason TEXT NOT NULL DEFAULT ''",
    }
    for column, statement in migrations.items():
        if column not in existing_columns:
            connection.execute(statement)


def save_analysis(
    raw_report: str,
    analysis: VulnerabilityAnalysis,
    db_path: Path = DB_PATH,
) -> int:
    structured_json = analysis.model_dump_json(indent=2)
    with closing(get_connection(db_path)) as connection:
        with connection:
            cursor = connection.execute(
                """
                INSERT INTO analysis_results (
                    raw_report,
                    structured_json,
                    severity,
                    vulnerability_type,
                    confidence_score,
                    review_required,
                    review_reason
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    raw_report,
                    structured_json,
                    analysis.severity.value,
                    analysis.vulnerability_type,
                    analysis.confidence_score,
                    int(analysis.review_required),
                    analysis.review_reason,
                ),
            )
            return int(cursor.lastrowid)


def get_analysis_history(
    limit: int = 100,
    search_query: str = "",
    severity: str | None = None,
    affected_component: str | None = None,
    review_required: bool | None = None,
    sort_desc: bool = True,
    db_path: Path = DB_PATH,
) -> List[Dict[str, Any]]:
    where_clauses = []
    params: List[Any] = []
    if severity:
        where_clauses.append("severity = ?")
        params.append(severity)
    if review_required is not None:
        where_clauses.append("review_required = ?")
        params.append(int(review_required))

    where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
    sort_direction = "DESC" if sort_desc else "ASC"

    with closing(get_connection(db_path)) as connection:
        rows = connection.execute(
            f"""
            SELECT
                id,
                raw_report,
                structured_json,
                severity,
                vulnerability_type,
                confidence_score,
                review_required,
                review_reason,
                created_at
            FROM analysis_results
            {where_sql}
            ORDER BY datetime(created_at) {sort_direction}, id {sort_direction}
            """,
            params,
        ).fetchall()

    history: List[Dict[str, Any]] = []
    for row in rows:
        item = _normalize_history_item(row)
        if not _matches_affected_component(item, affected_component):
            continue
        if not _matches_search(item, search_query):
            continue
        history.append(item)
        if len(history) >= limit:
            break
    return history


def _normalize_history_item(row: sqlite3.Row) -> Dict[str, Any]:
    item = dict(row)
    item["review_required"] = bool(item.get("review_required", False))
    try:
        item["analysis"] = json.loads(item["structured_json"])
    except json.JSONDecodeError:
        item["analysis"] = None

    if isinstance(item["analysis"], dict):
        for field in EVIDENCE_FIELDS:
            item["analysis"].setdefault(field, EVIDENCE_NOT_IDENTIFIED)
        item["analysis"].setdefault(
            "confidence_score",
            item["analysis"].get("confidence", REVIEW_DEFAULTS["confidence_score"]),
        )
        item["analysis"].setdefault(
            "review_required",
            item["review_required"],
        )
        item["analysis"].setdefault(
            "review_reason",
            item.get("review_reason") or REVIEW_DEFAULTS["review_reason"],
        )
    return item


def _matches_affected_component(
    item: Dict[str, Any],
    affected_component: str | None,
) -> bool:
    if not affected_component:
        return True
    analysis = item.get("analysis") or {}
    return analysis.get("affected_component", "").strip() == affected_component


def _matches_search(item: Dict[str, Any], search_query: str) -> bool:
    query = search_query.strip().lower()
    if not query:
        return True
    return query in _history_search_text(item)


def _history_search_text(item: Dict[str, Any]) -> str:
    analysis = item.get("analysis") or {}
    values = [
        analysis.get("title", ""),
        analysis.get("summary", ""),
        analysis.get("impact", ""),
        analysis.get("remediation", ""),
        analysis.get("affected_component", ""),
    ]
    values.extend(analysis.get(field, "") for field in EVIDENCE_FIELDS)

    evidence = analysis.get("evidence", [])
    if isinstance(evidence, list):
        values.extend(str(item) for item in evidence)
    else:
        values.append(str(evidence))

    return " ".join(str(value) for value in values).lower()
