"""
Corvus Mirage — Gateway
WebSocket Manager

Real-time event streaming to the unified dashboard.
Mirrors ARIA's websocket_manager pattern exactly so
the dashboard consumes both components identically.
"""
import json
import logging
from typing import Set
from fastapi import WebSocket


logger = logging.getLogger("gateway.websocket_manager")


class WebSocketManager:
    """
    Manages active WebSocket connections and broadcasts
    Gateway inspection events to all connected dashboard clients.
    """

    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info(f"Dashboard connected | total={len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        self.active_connections.discard(websocket)
        logger.info(f"Dashboard disconnected | total={len(self.active_connections)}")

    async def broadcast(self, event_type: str, data: dict):
        """
        Broadcast an event to all connected dashboard clients.

        Args:
            event_type: e.g. "inspection_complete", "threat_blocked", "policy_triggered"
            data:       Serializable dict payload
        """
        if not self.active_connections:
            return

        message = json.dumps({"event": event_type, "data": data})
        dead = set()

        for ws in self.active_connections:
            try:
                await ws.send_text(message)
            except Exception:
                dead.add(ws)

        for ws in dead:
            self.active_connections.discard(ws)

    async def broadcast_inspection(self, response_dict: dict):
        """Shortcut for inspection result events."""
        await self.broadcast("inspection_complete", response_dict)

    async def broadcast_threat(self, response_dict: dict):
        """Shortcut for blocked/high-severity threat events."""
        await self.broadcast("threat_detected", response_dict)


# Singleton
_manager: WebSocketManager = None

def get_websocket_manager() -> WebSocketManager:
    global _manager
    if _manager is None:
        _manager = WebSocketManager()
    return _manager
