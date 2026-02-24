"""
Corvus Mirage — ARIA
Red Team Analysis Route
Accepts transcript payloads directly from the Red Team Simulator,
bypassing the Twilio/Deepgram voice pipeline entirely.

POST /analyze-transcript
{
    "transcript": "Hello, this is Microsoft Support...",
    "source": "red_team_simulator",
    "session_id": "rt_vs_001_1234567890"
}
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import uuid
import logging
from datetime import datetime
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional

from core.detection_engine import analyze_transcript

logger = logging.getLogger("corvus.aria.redteam")
router = APIRouter()


class TranscriptRequest(BaseModel):
    transcript: str
    source: Optional[str] = "unknown"
    session_id: Optional[str] = None


@router.post("/analyze-transcript")
async def analyze_transcript_direct(request: TranscriptRequest):
    """
    Direct transcript analysis endpoint for the Red Team Simulator.
    Runs the same detection engine as the live voice pipeline.
    """
    session_id = request.session_id or f"rt_{str(uuid.uuid4())[:8]}"

    logger.info(f"Red team transcript analysis [{session_id}] source={request.source}")

    result = await analyze_transcript(request.transcript, session_id)

    score = result.get("threat_score", 0)
    is_attack = result.get("is_attack", False)

    # Normalize to the response shape the runner expects
    return {
        "session_id": session_id,
        "vishing_detected": is_attack,
        "confidence": result.get("confidence", 0.0),
        "threat_score": score,
        "risk_level": _score_to_level(score),
        "tactics_identified": result.get("techniques", []),
        "mitre_tags": result.get("mitre_tags", []),
        "primary_objective": result.get("primary_objective"),
        "sophistication": result.get("sophistication"),
        "evidence": result.get("evidence", []),
        "recommended_action": result.get("recommended_action"),
        "alert_triggered": is_attack and score >= 60,
        "summary": result.get("summary", ""),
        "analyzed_at": datetime.utcnow().isoformat() + "Z",
        "source": request.source,
    }


def _score_to_level(score: float) -> str:
    if score >= 75:   return "critical"
    elif score >= 55: return "high"
    elif score >= 35: return "medium"
    elif score >= 15: return "low"
    else:             return "safe"
