import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import sqlite3
import json
from fastapi import APIRouter, HTTPException
from shared.threat_intel import get_recent_events, get_cross_vector_sessions

router = APIRouter()

# ── Shared DB path (mirrors Red Team Simulator config) ─────────────────────────
_DB_PATH = os.getenv("THREAT_INTEL_DB_PATH", "./shared/data/threat_intel.db")


def _redteam_conn():
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ── Existing endpoints ──────────────────────────────────────────────────────────

@router.get("/events")
async def events(limit: int = 50, component: str = "all"):
    all_events = get_recent_events(limit=limit)
    if component != "all":
        all_events = [e for e in all_events if e.get("component") == component]
    return {"events": all_events, "count": len(all_events)}


@router.get("/profiles")
async def profiles():
    cross = get_cross_vector_sessions()
    return {"profiles": cross, "count": len(cross)}


@router.get("/stats")
async def stats():
    all_events = get_recent_events(limit=1000)
    cross = get_cross_vector_sessions()

    aria_count    = sum(1 for e in all_events if e.get("component") == "aria")
    gateway_count = sum(1 for e in all_events if e.get("component") == "gateway")
    high_threat   = sum(1 for e in all_events if e.get("threat_level") == "high")
    malicious     = sum(1 for e in all_events if e.get("is_malicious"))

    # Red team coverage from latest run
    latest_coverage_pct = None
    total_redteam_runs  = 0
    pitch_ready         = False
    try:
        conn = _redteam_conn()
        row = conn.execute(
            "SELECT overall_coverage_pct, pitch_ready FROM red_team_runs ORDER BY started_at DESC LIMIT 1"
        ).fetchone()
        count_row = conn.execute("SELECT COUNT(*) as c FROM red_team_runs").fetchone()
        conn.close()
        if row:
            latest_coverage_pct = row["overall_coverage_pct"]
            pitch_ready = bool(row["pitch_ready"])
        if count_row:
            total_redteam_runs = count_row["c"]
    except Exception:
        pass  # DB may not exist yet if no runs have completed

    return {
        "total_events":          len(all_events),
        "aria_events":           aria_count,
        "gateway_events":        gateway_count,
        "cross_vector_hits":     len(cross),
        "high_threat_count":     high_threat,
        "malicious_count":       malicious,
        # Red team
        "redteam_runs":          total_redteam_runs,
        "latest_coverage_pct":   latest_coverage_pct,
        "pitch_ready":           pitch_ready,
    }


# ── Red Team endpoints ──────────────────────────────────────────────────────────

@router.get("/redteam/runs")
async def redteam_runs(limit: int = 10):
    """
    Return recent red team simulation runs for the dashboard coverage panel.
    Each row has: run_id, started_at, overall_coverage_pct, weighted_coverage_pct,
                  total_attacks, total_caught, pitch_ready, category_breakdown
    """
    try:
        conn = _redteam_conn()
        cur = conn.execute(
            """
            SELECT run_id, started_at, overall_coverage_pct, weighted_coverage_pct,
                   total_attacks, total_caught, errors_skipped, pitch_ready,
                   category_breakdown
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
        conn.close()
        return {"runs": rows, "count": len(rows)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/redteam/latest")
async def redteam_latest():
    """
    Return the most recent red team run plus its per-attack findings.
    Used by the dashboard coverage card and the detail panel.
    """
    try:
        conn = _redteam_conn()

        run_row = conn.execute(
            """
            SELECT run_id, started_at, overall_coverage_pct, weighted_coverage_pct,
                   total_attacks, total_caught, errors_skipped, pitch_ready,
                   category_breakdown, report_json_path, report_txt_path
            FROM red_team_runs
            ORDER BY started_at DESC
            LIMIT 1
            """
        ).fetchone()

        if not run_row:
            conn.close()
            return {"run": None, "findings": []}

        run = dict(run_row)
        run["category_breakdown"] = json.loads(run["category_breakdown"] or "{}")
        run["pitch_ready"] = bool(run["pitch_ready"])

        findings_rows = conn.execute(
            """
            SELECT target_component, attack_type, severity, detected,
                   detection_time_ms, proof_of_concept, found_at
            FROM red_team_findings
            WHERE run_id = ?
            ORDER BY severity DESC, detected ASC
            """,
            (run["run_id"],),
        ).fetchall()
        conn.close()

        findings = [dict(f) for f in findings_rows]
        for f in findings:
            f["detected"] = bool(f["detected"])

        return {"run": run, "findings": findings}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/redteam/findings/{run_id}")
async def redteam_findings(run_id: str):
    """Return all findings for a specific run_id."""
    try:
        conn = _redteam_conn()
        rows = conn.execute(
            """
            SELECT target_component, attack_type, severity, detected,
                   detection_time_ms, proof_of_concept, found_at
            FROM red_team_findings
            WHERE run_id = ?
            ORDER BY severity DESC, detected ASC
            """,
            (run_id,),
        ).fetchall()
        conn.close()
        findings = [dict(r) for r in rows]
        for f in findings:
            f["detected"] = bool(f["detected"])
        return {"run_id": run_id, "findings": findings, "count": len(findings)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── IP Correlation endpoints ────────────────────────────────────────────────────

@router.get("/ip/{ip_address}")
async def ip_summary(ip_address: str):
    """
    Return aggregate threat summary and recent events for a specific IP.
    Used by the dashboard to surface repeat offenders across ARIA and Gateway.
    """
    from shared.threat_intel import get_events_by_ip, get_ip_threat_summary
    return {
        "summary": get_ip_threat_summary(ip_address),
        "events":  get_events_by_ip(ip_address, limit=20),
    }