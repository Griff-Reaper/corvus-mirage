import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import json
import asyncio
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from shared.threat_intel import get_recent_events

router = APIRouter()

@router.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    await websocket.accept()
    seen_ids = set()

    # Send existing events on connect
    try:
        existing = get_recent_events(limit=50)
        for ev in reversed(existing):
            ev_id = ev.get("id")
            if ev_id:
                seen_ids.add(ev_id)
            await websocket.send_text(json.dumps({
                "event_type": "threat",
                "data": ev
            }))
    except Exception as e:
        print(f"Initial load error: {e}")

    # Poll for new events
    try:
        while True:
            await asyncio.sleep(2)
            events = get_recent_events(limit=20)
            for ev in reversed(events):
                ev_id = ev.get("id")
                if ev_id and ev_id not in seen_ids:
                    seen_ids.add(ev_id)
                    await websocket.send_text(json.dumps({
                        "event_type": "threat",
                        "data": ev
                    }))
    except WebSocketDisconnect:
        pass
    except Exception as e:
        print(f"WebSocket error: {e}")