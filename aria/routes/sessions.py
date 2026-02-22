"""
Corvus Mirage — ARIA
Session Routes
Dashboard queries session data here.
"""

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from routes.voice import active_sessions

router = APIRouter()


@router.get("/")
async def get_sessions():
    """Return all sessions."""
    return {"sessions": list(active_sessions.values())}


@router.get("/{session_id}")
async def get_session(session_id: str):
    """Return a specific session by ID."""
    session = active_sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session


@router.websocket("/live")
async def live_sessions(websocket: WebSocket):
    """
    WebSocket for dashboard to receive real-time session updates.
    """
    ws_manager = websocket.app.state.ws_manager
    await ws_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
