import os
import sqlite3
import json
from typing import List, Dict, Any, Optional
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "shield.db"


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Creates the persistent database tables and indexes if they do not exist."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_audits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                scan_timestamp TEXT NOT NULL,
                overall_score INTEGER NOT NULL,
                grade TEXT NOT NULL,
                posture_status TEXT,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                ssl_score INTEGER DEFAULT 0,
                headers_score INTEGER DEFAULT 0,
                cookies_score INTEGER DEFAULT 0,
                edge_score INTEGER DEFAULT 0,
                full_report_json TEXT NOT NULL
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_target ON scan_audits(target)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_timestamp ON scan_audits(scan_timestamp DESC)")
        conn.commit()


def save_scan(result: Dict[str, Any]) -> int:
    """Inserts a completed scan audit record into SQLite."""
    init_db()
    target = result.get("target", "unknown")
    timestamp = result.get("scan_timestamp", "")
    score_data = result.get("score", {})
    sev_counts = score_data.get("severity_counts", {})
    cats = score_data.get("category_breakdown", {})

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scan_audits (
                target, scan_timestamp, overall_score, grade, posture_status,
                critical_count, high_count, medium_count, low_count,
                ssl_score, headers_score, cookies_score, edge_score,
                full_report_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            target,
            timestamp,
            score_data.get("overall_score", 0),
            score_data.get("grade", "F"),
            score_data.get("posture_status", ""),
            sev_counts.get("CRITICAL", 0),
            sev_counts.get("HIGH", 0),
            sev_counts.get("MEDIUM", 0),
            sev_counts.get("LOW", 0),
            cats.get("ssl_tls", {}).get("score", 0),
            cats.get("headers", {}).get("score", 0),
            cats.get("cookies", {}).get("score", 0),
            cats.get("edge_cases", {}).get("score", 0),
            json.dumps(result)
        ))
        conn.commit()
        return cursor.lastrowid


def get_recent_scans(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieves recent scan audit summaries from SQLite."""
    init_db()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, target, scan_timestamp as timestamp, overall_score as score,
                   grade, posture_status, critical_count, high_count, medium_count, low_count
            FROM scan_audits
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))
        return [dict(row) for row in cursor.fetchall()]


def get_scan_by_target(target: str) -> Optional[Dict[str, Any]]:
    """Retrieves the latest full scan report for a specific domain."""
    init_db()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT full_report_json FROM scan_audits
            WHERE target = ?
            ORDER BY id DESC
            LIMIT 1
        """, (target,))
        row = cursor.fetchone()
        if row:
            return json.loads(row["full_report_json"])
        return None
