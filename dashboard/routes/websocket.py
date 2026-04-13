import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import json
import sqlite3
import asyncio
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from shared.threat_intel import get_recent_events

router = APIRouter()

_DB_PATH = os.getenv("THREAT_INTEL_DB_PATH", "./shared/data/threat_intel.db")


def _get_recent_redteam_runs(limit: int = 5) -> list:
    """Pull recent red team runs from the shared DB. Returns [] if table absent."""
    try:
        conn = sqlite3.connect(_DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT run_id, started_at, overall_coverage_pct,
                   total_attacks, total_caught, pitch_ready
            FROM red_team_runs
            ORDER BY started_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        conn.close()
        result = []
        for row in rows:
            d = dict(row)
            d["pitch_ready"] = bool(d["pitch_ready"])
            result.append(d)
        return result
    except Exception:
        return []


@router.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    await websocket.accept()
    seen_event_ids = set()
    seen_run_ids   = set()

    # ── Initial load: threat events ─────────────────────────────────────────────
    try:
        existing = get_recent_events(limit=50)
        for ev in reversed(existing):
            ev_id = ev.get("id")
            if ev_id:
                seen_event_ids.add(ev_id)
            await websocket.send_text(json.dumps({
                "event_type": "threat",
                "data": ev,
            }))
    except Exception as e:
        print(f"Initial event load error: {e}")

    # ── Initial load: red team runs ─────────────────────────────────────────────
    try:
        recent_runs = _get_recent_redteam_runs(limit=5)
        for run in reversed(recent_runs):
            seen_run_ids.add(run["run_id"])
            await websocket.send_text(json.dumps({
                "event_type": "redteam_run",
                "data": run,
            }))
    except Exception as e:
        print(f"Initial redteam load error: {e}")

    # ── Poll loop ────────────────────────────────────────────────────────────────
    try:
        while True:
            await asyncio.sleep(2)

            # New threat events
            try:
                events = get_recent_events(limit=20)
                for ev in reversed(events):
                    ev_id = ev.get("id")
                    if ev_id and ev_id not in seen_event_ids:
                        seen_event_ids.add(ev_id)
                        await websocket.send_text(json.dumps({
                            "event_type": "threat",
                            "data": ev,
                        }))
            except Exception as e:
                print(f"Event poll error: {e}")

            # New red team runs
            try:
                runs = _get_recent_redteam_runs(limit=5)
                for run in reversed(runs):
                    run_id = run.get("run_id")
                    if run_id and run_id not in seen_run_ids:
                        seen_run_ids.add(run_id)
                        await websocket.send_text(json.dumps({
                            "event_type": "redteam_run",
                            "data": run,
                        }))
            except Exception as e:
                print(f"Redteam poll error: {e}")

    except WebSocketDisconnect:
        pass
    except Exception as e:
        print(f"WebSocket error: {e}")