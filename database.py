import json
import os
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any, Dict, List

from models import VulnerabilityAnalysis


DB_PATH = Path(os.getenv("VULN_REPORT_DB_PATH", "vulnerability_reports.db"))


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
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                )
                """
            )


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
                    vulnerability_type
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    raw_report,
                    structured_json,
                    analysis.severity.value,
                    analysis.vulnerability_type,
                ),
            )
            return int(cursor.lastrowid)


def get_analysis_history(
    limit: int = 50,
    db_path: Path = DB_PATH,
) -> List[Dict[str, Any]]:
    with closing(get_connection(db_path)) as connection:
        rows = connection.execute(
            """
            SELECT
                id,
                raw_report,
                structured_json,
                severity,
                vulnerability_type,
                created_at
            FROM analysis_results
            ORDER BY datetime(created_at) DESC, id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    history: List[Dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        try:
            item["analysis"] = json.loads(item["structured_json"])
        except json.JSONDecodeError:
            item["analysis"] = None
        history.append(item)
    return history
