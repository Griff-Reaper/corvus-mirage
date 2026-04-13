"""
Red Team Simulator — DB Writer
Persists run summaries and per-attack findings to the shared threat_intel.db.

Two tables:
  red_team_runs     — one row per simulation run (summary + coverage score)
  red_team_findings — one row per attack result (already existed in schema)
"""

import json
import logging
import os
import sqlite3
import uuid
from datetime import datetime
from typing import List

logger = logging.getLogger("red_team.db_writer")


def _get_conn(db_path: str) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_schema(db_path: str) -> None:
    """
    Create red_team_runs if it doesn't exist.
    red_team_findings already exists in the shared schema.
    """
    conn = _get_conn(db_path)
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS red_team_runs (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id              TEXT    NOT NULL UNIQUE,
                started_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                overall_coverage_pct    REAL,
                weighted_coverage_pct   REAL,
                total_attacks       INTEGER,
                total_caught        INTEGER,
                errors_skipped      INTEGER,
                pitch_ready         BOOLEAN,
                category_breakdown  TEXT,
                report_json_path    TEXT,
                report_txt_path     TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS red_team_findings (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id              TEXT    NOT NULL,
                target_component    TEXT    NOT NULL,
                attack_type         TEXT    NOT NULL,
                severity            TEXT,
                detected            BOOLEAN,
                detection_time_ms   INTEGER,
                proof_of_concept    TEXT,
                reproduction_steps  TEXT,
                found_at            TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()
        logger.debug("red_team_runs schema verified")
    finally:
        conn.close()


def save_run(
    db_path: str,
    score_data: dict,
    run_id: str = None,
    report_json_path: str = None,
    report_txt_path: str = None,
) -> str:
    """
    Write a completed simulation run to red_team_runs.
    Returns the run_id.
    """
    if run_id is None:
        run_id = str(uuid.uuid4())

    ensure_schema(db_path)

    summary = score_data.get("summary", {})
    categories = score_data.get("categories", {})

    # Slim category breakdown for storage — drop missed_attacks payloads
    slim_categories = {
        cat: {
            "detected": data["detected"],
            "total": data["total"],
            "coverage_pct": data["coverage_pct"],
            "weighted_coverage_pct": data["weighted_coverage_pct"],
            "passing": data["passing"],
        }
        for cat, data in categories.items()
    }

    conn = _get_conn(db_path)
    try:
        conn.execute(
            """
            INSERT OR REPLACE INTO red_team_runs (
                run_id, started_at,
                overall_coverage_pct, weighted_coverage_pct,
                total_attacks, total_caught, errors_skipped,
                pitch_ready, category_breakdown,
                report_json_path, report_txt_path
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                score_data.get("generated_at", datetime.utcnow().isoformat()),
                summary.get("overall_coverage_pct"),
                summary.get("weighted_coverage_pct"),
                summary.get("total_attacks"),
                summary.get("total_caught"),
                summary.get("errors_skipped", 0),
                int(summary.get("pitch_ready", False)),
                json.dumps(slim_categories),
                report_json_path,
                report_txt_path,
            ),
        )
        conn.commit()
        logger.info(
            f"Run saved | run_id={run_id} "
            f"coverage={summary.get('overall_coverage_pct')}% "
            f"pitch_ready={summary.get('pitch_ready')}"
        )
    finally:
        conn.close()

    return run_id


def save_findings(db_path: str, results: list, run_id: str) -> int:
    """
    Write per-attack results to red_team_findings.
    Returns the number of rows inserted.
    """
    # Import here to avoid circular dependency
    from core.attack_runner import DetectionResult

    conn = _get_conn(db_path)
    rows_written = 0
    try:
        for r in results:
            detected = r.result in (DetectionResult.DETECTED, DetectionResult.BLOCKED)
            conn.execute(
                """
                INSERT INTO red_team_findings (
                    run_id, target_component, attack_type,
                    severity, detected, detection_time_ms,
                    proof_of_concept, found_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    r.attack.vector.value if hasattr(r.attack.vector, "value") else str(r.attack.vector),
                    r.attack.category.value,
                    r.attack.severity.value,
                    int(detected),
                    int(r.response_time_ms),
                    r.attack.id,               # proof_of_concept = attack ID for now
                    datetime.utcnow().isoformat(),
                ),
            )
            rows_written += 1
        conn.commit()
        logger.info(f"Findings saved | run_id={run_id} count={rows_written}")
    finally:
        conn.close()

    return rows_written


def get_recent_runs(db_path: str, limit: int = 10) -> list:
    """
    Fetch recent runs for the dashboard. Returns list of dicts.
    """
    conn = _get_conn(db_path)
    try:
        cur = conn.execute(
            """
            SELECT run_id, started_at, overall_coverage_pct,
                   weighted_coverage_pct, total_attacks, total_caught,
                   errors_skipped, pitch_ready, category_breakdown
            FROM red_team_runs
            ORDER BY started_at DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = []
        for row in cur.fetchall():
            d = dict(row)
            d["category_breakdown"] = json.loads(d["category_breakdown"] or "{}")
            d["pitch_ready"] = bool(d["pitch_ready"])
            rows.append(d)
        return rows
    finally:
        conn.close()


def get_latest_run(db_path: str) -> dict | None:
    """Return the most recent run, or None if no runs exist."""
    runs = get_recent_runs(db_path, limit=1)
    return runs[0] if runs else None