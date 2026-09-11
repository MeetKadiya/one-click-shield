#!/usr/bin/env python3
"""
One-Click Shield - Database Viewer Utility
Inspects persistent scan audit logs stored in SQLite (backend/shield.db).
"""

import os
import sys
import sqlite3
import argparse
from pathlib import Path

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Locate database
DB_PATH = Path(__file__).resolve().parent / "backend" / "shield.db"

def view_db(limit=20, target_filter=None):
    if not DB_PATH.exists():
        print(f"[!] Database file not found at: {DB_PATH}")
        print("[*] Run a scan via the Web UI (http://localhost:3000) or CLI to populate the database.")
        return

    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    query = """
        SELECT id, target, scan_timestamp, overall_score, grade, posture_status,
               critical_count, high_count, ssl_score, headers_score, cookies_score, edge_score
        FROM scan_audits
    """
    params = []
    if target_filter:
        query += " WHERE target LIKE ?"
        params.append(f"%{target_filter}%")

    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    cursor.execute(query, params)
    rows = cursor.fetchall()

    print("\n" + "="*85)
    print(f" 🛡️  ONE-CLICK SHIELD - SQLITE AUDIT DATABASE ({DB_PATH.name})")
    print("="*85)

    if not rows:
        print(" [i] No scan records found in database yet.")
        print("="*85 + "\n")
        return

    # Header
    print(f"{'ID':<4} | {'Target Host':<22} | {'Score':<6} | {'Grade':<5} | {'Crits':<6} | {'Highs':<6} | {'Timestamp':<20}")
    print("-" * 85)

    for r in rows:
        print(f"{r['id']:<4} | {r['target']:<22} | {r['overall_score']:>3}/100 | {r['grade']:<5} | {r['critical_count']:<6} | {r['high_count']:<6} | {r['scan_timestamp'][:19]}")

    print("="*85)
    print(f"Total records displayed: {len(rows)} (Database Location: {DB_PATH})")
    print("="*85 + "\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Query One-Click Shield SQLite Database")
    parser.add_argument("--limit", type=int, default=20, help="Number of records to fetch (default: 20)")
    parser.add_argument("--target", type=str, default=None, help="Filter by target host")
    args = parser.parse_args()

    view_db(limit=args.limit, target_filter=args.target)
