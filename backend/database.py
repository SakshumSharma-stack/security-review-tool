import sqlite3
import json
from pathlib import Path
from datetime import datetime, timezone

DB_PATH = Path(__file__).parent / "scans.db"


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp           TEXT    NOT NULL,
                code_snippet        TEXT    NOT NULL,
                vulnerabilities_found TEXT  NOT NULL,
                fixed_code          TEXT    NOT NULL,
                summary             TEXT    NOT NULL
            )
        """)
        conn.commit()


def save_scan(
    code_snippet: str,
    vulnerabilities_found: list[dict],
    fixed_code: str,
    summary: str,
) -> int:
    timestamp = datetime.now(timezone.utc).isoformat()
    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO scans (timestamp, code_snippet, vulnerabilities_found, fixed_code, summary)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                code_snippet,
                json.dumps(vulnerabilities_found),
                fixed_code,
                summary,
            ),
        )
        conn.commit()
        return cursor.lastrowid


def get_recent_scans(limit: int = 10) -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT id, timestamp, code_snippet, vulnerabilities_found, fixed_code, summary
            FROM scans
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [
        {
            "id": row["id"],
            "timestamp": row["timestamp"],
            "code_snippet": row["code_snippet"],
            "vulnerabilities_found": json.loads(row["vulnerabilities_found"]),
            "fixed_code": row["fixed_code"],
            "summary": row["summary"],
        }
        for row in rows
    ]
