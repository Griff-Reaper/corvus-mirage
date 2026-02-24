"""
Red Team Simulator — Configuration
Reads endpoints from environment, falls back to defaults matching the platform.
"""

import os
from dataclasses import dataclass


@dataclass
class RedTeamConfig:
    # Target endpoints
    gateway_api: str = os.getenv("GATEWAY_API", "http://localhost:8002")
    aria_api: str = os.getenv("ARIA_API", "http://localhost:8001")

    # Gateway analyze endpoint — adjust if your route differs
    gateway_analyze_route: str = "/inspect"
    gateway_health_route: str = "/health"

    # ARIA transcript simulation endpoint
    # We simulate vishing by posting transcripts directly
    aria_transcript_route: str = "/analyze-transcript"
    aria_health_route: str = "/health"

    # Runner behavior
    request_timeout_seconds: int = 10
    delay_between_attacks_ms: int = 200   # throttle to avoid hammering local services
    max_retries: int = 2

    # Scoring thresholds
    detection_pass_threshold: float = 0.70   # 70% = passing coverage per category
    overall_pass_threshold: float = 0.75     # 75% overall to be "pitchable"

    # Report output
    reports_dir: str = os.path.join(os.path.dirname(__file__), "reports")

    # Shared threat intel DB (same path as rest of platform)
    threat_intel_db_path: str = os.getenv(
        "THREAT_INTEL_DB_PATH", "./shared/data/threat_intel.db"
    )


config = RedTeamConfig()
