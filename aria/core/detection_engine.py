"""
Corvus Mirage — ARIA
Vishing Detection Engine
Analyzes real-time transcripts for social engineering techniques.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import anthropic
import json
import logging
from typing import Optional
from shared.config import config, Severity, MITRE_TECHNIQUES

logger = logging.getLogger("corvus.aria.detection")

client = anthropic.Anthropic(api_key=config.anthropic_api_key)

DETECTION_PROMPT = """You are ARIA, the detection engine for Corvus Mirage — an AI security platform.
Analyze this phone call transcript for social engineering and vishing techniques.

Transcript so far:
{transcript}

Analyze for these techniques:
- Pretexting (creating a false scenario)
- Authority impersonation (claiming to be IT, management, vendor)
- Urgency manipulation (creating false time pressure)
- Credential fishing (requesting passwords, codes, access)
- Verification bypass (trying to skip security procedures)
- Identity probing (gathering personal/employee information)

Respond ONLY with a JSON object in this exact format:
{{
  "is_attack": true/false,
  "confidence": 0.0-1.0,
  "threat_score": 0-100,
  "sophistication": "LOW/MEDIUM/HIGH/CRITICAL",
  "techniques": ["technique1", "technique2"],
  "mitre_tags": ["T1566", "T1078"],
  "primary_objective": "brief description of what attacker is trying to accomplish",
  "evidence": ["specific quote or behavior that triggered detection"],
  "recommended_action": "MONITOR/FLAG/ALERT/TERMINATE"
}}"""


async def analyze_transcript(
    transcript: str,
    session_id: str,
    conversation_history: Optional[list] = None
) -> dict:
    """
    Analyze a transcript for vishing techniques.
    Returns detection result with threat assessment.
    """
    if not transcript or len(transcript.strip()) < 10:
        return _empty_result()

    try:
        response = client.messages.create(
            model=config.anthropic_model,
            max_tokens=1000,
            messages=[
                {
                    "role": "user",
                    "content": DETECTION_PROMPT.format(transcript=transcript)
                }
            ]
        )

        result_text = response.content[0].text.strip()

        # Strip markdown if present
        if result_text.startswith("```"):
            result_text = result_text.split("```")[1]
            if result_text.startswith("json"):
                result_text = result_text[4:]

        result = json.loads(result_text)

        # Map techniques to MITRE tags
        if result.get("techniques"):
            mitre_tags = []
            for technique in result["techniques"]:
                tag = MITRE_TECHNIQUES.get(technique.lower().replace(" ", "_"))
                if tag and tag not in mitre_tags:
                    mitre_tags.append(tag)
            if mitre_tags:
                result["mitre_tags"] = mitre_tags

        result["session_id"] = session_id
        logger.info(
            f"Detection [{session_id}]: attack={result.get('is_attack')}, "
            f"score={result.get('threat_score')}, "
            f"techniques={result.get('techniques')}"
        )
        return result

    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse detection response: {e}")
        return _empty_result()
    except Exception as e:
        logger.error(f"Detection engine error: {e}")
        return _empty_result()


def _empty_result() -> dict:
    return {
        "is_attack": False,
        "confidence": 0.0,
        "threat_score": 0,
        "sophistication": Severity.LOW,
        "techniques": [],
        "mitre_tags": [],
        "primary_objective": None,
        "evidence": [],
        "recommended_action": "MONITOR"
    }
