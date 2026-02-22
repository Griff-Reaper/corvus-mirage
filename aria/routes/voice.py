"""
Corvus Mirage — ARIA
Voice Routes
Handles Twilio webhooks and Deepgram real-time streaming.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import json
import uuid
import base64
import asyncio
import logging
from datetime import datetime
from fastapi import APIRouter, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import Response
from twilio.twiml.voice_response import VoiceResponse, Connect, Stream
from deepgram import DeepgramClient, LiveTranscriptionEvents, LiveOptions
from shared.config import config
from shared.alerting import Alert, fire_alert
from core.detection_engine import analyze_transcript

logger = logging.getLogger("corvus.aria.voice")
router = APIRouter()

active_sessions = {}


@router.post("/incoming")
async def handle_incoming_call(request: Request):
    form_data = await request.form()
    call_sid = form_data.get("CallSid", "unknown")
    caller = form_data.get("From", "unknown")
    called = form_data.get("To", "unknown")

    session_id = str(uuid.uuid4())

    active_sessions[session_id] = {
        "id": session_id,
        "call_sid": call_sid,
        "caller": caller,
        "called": called,
        "start_time": datetime.utcnow().isoformat(),
        "transcript": "",
        "threat_score": 0,
        "status": "ACTIVE",
        "techniques": [],
        "mitre_tags": []
    }

    logger.info(f"Incoming call [{session_id}] from {caller}")

    ws_manager = request.app.state.ws_manager
    await ws_manager.emit_session_update(active_sessions[session_id])

    host = request.headers.get("host", "localhost")
    response = VoiceResponse()
    response.say("Thank you for calling. Please hold while we connect you.", voice="alice")
    connect = Connect()
    stream = Stream(url=f"wss://{host}/voice/stream/{session_id}")
    connect.append(stream)
    response.append(connect)

    return Response(content=str(response), media_type="application/xml")


@router.websocket("/stream/{session_id}")
async def voice_stream(websocket: WebSocket, session_id: str):
    await websocket.accept()
    ws_manager = websocket.app.state.ws_manager
    logger.info(f"Voice stream connected [{session_id}]")

    deepgram = DeepgramClient(config.deepgram_api_key)
    dg_connection = deepgram.listen.live.v("1")

    loop = asyncio.get_event_loop()
    full_transcript = []
    last_analysis_length = [0]

    def on_transcript(self, result, **kwargs):
        try:
            sentence = result.channel.alternatives[0].transcript
            if not sentence or not result.is_final:
                return

            full_transcript.append(sentence)
            current = " ".join(full_transcript).strip()

            asyncio.run_coroutine_threadsafe(
                ws_manager.emit_transcript_update(session_id, current, True),
                loop
            )

            new_chars = len(current) - last_analysis_length[0]
            if new_chars >= 50:
                last_analysis_length[0] = len(current)
                asyncio.run_coroutine_threadsafe(
                    _run_detection(session_id, current, ws_manager),
                    loop
                )
        except Exception as e:
            logger.error(f"Transcript handler error: {e}")

    dg_connection.on(LiveTranscriptionEvents.Transcript, on_transcript)

    options = LiveOptions(
        model="nova-2",
        language="en-US",
        smart_format=True,
        interim_results=True,
        utterance_end_ms="1000",
        vad_events=True,
        encoding="mulaw",
        sample_rate=8000,
    )

    dg_connection.start(options)

    try:
        while True:
            message = await websocket.receive_text()
            data = json.loads(message)
            if data.get("event") == "media":
                audio_data = base64.b64decode(data["media"]["payload"])
                dg_connection.send(audio_data)
            elif data.get("event") == "stop":
                logger.info(f"Call ended [{session_id}]")
                break
    except WebSocketDisconnect:
        logger.info(f"Voice stream disconnected [{session_id}]")
    finally:
        dg_connection.finish()
        if session_id in active_sessions:
            active_sessions[session_id]["status"] = "CLOSED"
            active_sessions[session_id]["end_time"] = datetime.utcnow().isoformat()
            await ws_manager.emit_session_update(active_sessions[session_id])


async def _run_detection(session_id: str, transcript: str, ws_manager):
    try:
        result = await analyze_transcript(transcript, session_id)
        if session_id not in active_sessions:
            return

        session = active_sessions[session_id]
        session["threat_score"] = max(session.get("threat_score", 0), result.get("threat_score", 0))

        for t in result.get("techniques", []):
            if t not in session["techniques"]:
                session["techniques"].append(t)

        for tag in result.get("mitre_tags", []):
            if tag not in session["mitre_tags"]:
                session["mitre_tags"].append(tag)

        await ws_manager.emit_detection(session_id, result)
        await ws_manager.emit_session_update(session)

        if result.get("is_attack") and result.get("threat_score", 0) >= 60:
            alert = Alert(
                title="Vishing Attack Detected",
                description=f"Social engineering attempt. Objective: {result.get('primary_objective', 'Unknown')}",
                severity=result.get("sophistication", "HIGH"),
                component="aria",
                session_id=session_id,
                techniques=result.get("techniques", []),
                mitre_tags=result.get("mitre_tags", []),
                metadata={"caller": session.get("caller"), "evidence": result.get("evidence", [])}
            )
            await fire_alert(alert)
    except Exception as e:
        logger.error(f"Detection run failed [{session_id}]: {e}")