"""
Corvus Mirage — ARIA
WebSocket Manager
Handles real-time streaming to the dashboard.
All events (voice transcripts, detections, alerts) flow through here.
"""

import json
from typing import Dict, Set
from fastapi import WebSocket
import logging

logger = logging.getLogger("corvus.aria.websocket")


class WebSocketManager:
    def __init__(self):
        # All connected dashboard clients
        self.active_connections: Set[WebSocket] = set()
        # Session-specific connections for targeted updates
        self.session_connections: Dict[str, Set[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, session_id: str = None):
        await websocket.accept()
        self.active_connections.add(websocket)
        if session_id:
            if session_id not in self.session_connections:
                self.session_connections[session_id] = set()
            self.session_connections[session_id].add(websocket)
        logger.info(f"Dashboard client connected. Total: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket, session_id: str = None):
        self.active_connections.discard(websocket)
        if session_id and session_id in self.session_connections:
            self.session_connections[session_id].discard(websocket)
        logger.info(f"Dashboard client disconnected. Total: {len(self.active_connections)}")

    async def broadcast(self, event_type: str, data: dict):
        """Broadcast an event to all connected dashboard clients."""
        message = json.dumps({"type": event_type, "data": data})
        disconnected = set()
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception:
                disconnected.add(connection)
        # Clean up dead connections
        for conn in disconnected:
            self.active_connections.discard(conn)

    async def send_to_session(self, session_id: str, event_type: str, data: dict):
        """Send an event to clients watching a specific session."""
        if session_id not in self.session_connections:
            return
        message = json.dumps({"type": event_type, "data": data})
        disconnected = set()
        for connection in self.session_connections[session_id]:
            try:
                await connection.send_text(message)
            except Exception:
                disconnected.add(connection)
        for conn in disconnected:
            self.session_connections[session_id].discard(conn)

    # ── Event helpers ──────────────────────────────────────────────

    async def emit_transcript_update(self, session_id: str, transcript: str, is_final: bool):
        """Stream live transcript to dashboard."""
        await self.broadcast("transcript_update", {
            "session_id": session_id,
            "transcript": transcript,
            "is_final": is_final
        })

    async def emit_detection(self, session_id: str, detection: dict):
        """Notify dashboard of a new detection."""
        await self.broadcast("detection", {
            "session_id": session_id,
            **detection
        })

    async def emit_session_update(self, session: dict):
        """Push updated session state to dashboard."""
        await self.broadcast("session_update", session)

    async def emit_alert(self, alert: dict):
        """Push a high-priority alert to dashboard."""
        await self.broadcast("alert", alert)
