"""
Gateway routes/inspect.py — with shared threat intel integration

Replace your existing gateway/routes/inspect.py with this file.
"""
import time
import uuid
import logging
import sys
from pathlib import Path

# Add monorepo root to path so shared/ is importable
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Request

from core import (
    get_detection_engine, get_policy_engine, get_sanitizer,
    get_websocket_manager, Action
)

logger = logging.getLogger("gateway.routes.inspect")
router = APIRouter(prefix="/inspect", tags=["inspect"])


@router.post("")
async def inspect_prompt(request: Request):
    body       = await request.json()
    prompt     = body.get("prompt", "")
    model      = body.get("model", None)
    user_id    = body.get("user_id", None)
    session_id = body.get("session_id", None) or str(uuid.uuid4())

    start      = time.time()
    request_id = str(uuid.uuid4())

    detection_engine = get_detection_engine()
    policy_engine    = get_policy_engine()
    sanitizer        = get_sanitizer()
    ws_manager       = get_websocket_manager()

    detection    = detection_engine.analyze(prompt)
    policy_match = policy_engine.evaluate(detection)

    sanitized_prompt = None
    changes = []
    if policy_match.action == Action.SANITIZE:
        sanitized_prompt, changes = sanitizer.sanitize(prompt)

    allowed = policy_match.action not in (Action.BLOCK,)
    processing_ms = round((time.time() - start) * 1000, 2)

    response = {
        "request_id":         request_id,
        "action":             policy_match.action.value,
        "allowed":            allowed,
        "original_prompt":    prompt,
        "sanitized_prompt":   sanitized_prompt,
        "threat_score":       detection.threat_score,
        "threat_level":       detection.threat_level.value,
        "detection":          detection.to_dict(),
        "policy_match":       policy_match.to_dict(),
        "sanitize_changes":   changes,
        "model":              model,
        "user_id":            user_id,
        "session_id":         session_id,
        "processing_time_ms": processing_ms,
    }

    # ── Write to shared threat intelligence DB ────────────────────────────
    if detection.is_malicious:
        try:
            from shared.threat_intel import write_event
            from shared.models import ThreatEvent, ThreatSource, ThreatStatus

            event = ThreatEvent(
                session_id=session_id,
                source=ThreatSource.GATEWAY,
                user_id=user_id,
                threat_score=detection.threat_score,
                threat_level=detection.threat_level.value,
                is_malicious=detection.is_malicious,
                confidence=detection.confidence,
                categories=detection.categories,
                action_taken=policy_match.action.value,
                raw_content=prompt,
                sanitized_content=sanitized_prompt,
                component_metadata={
                    "model":          model,
                    "request_id":     request_id,
                    "policy_matched": policy_match.policy_name,
                    "method_scores":  detection.method_scores,
                }
            )
            write_event(event)
            logger.info(f"[INTEL] Gateway event written | session={session_id}")

            # Publish to shared event bus
            from shared.event_bus import get_event_bus
            await get_event_bus().publish_threat("gateway", response)

        except Exception as e:
            print(f"SHARED INTEL ERROR: {e}")
    # ─────────────────────────────────────────────────────────────────────

    if detection.is_malicious:
        await ws_manager.broadcast_threat(response)
    else:
        await ws_manager.broadcast_inspection(response)

    logger.info(
        f"[{policy_match.action.value.upper()}] "
        f"score={detection.threat_score} | "
        f"level={detection.threat_level.value} | "
        f"{processing_ms}ms"
    )

    return response


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    manager = get_websocket_manager()
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)