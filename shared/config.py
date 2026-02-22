"""
Corvus Mirage — Shared Configuration
All components import from here for consistency.
"""

import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class Config:
    # Anthropic
    anthropic_api_key: str = os.getenv("ANTHROPIC_API_KEY", "")
    anthropic_model: str = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6")

    # Twilio
    twilio_account_sid: str = os.getenv("TWILIO_ACCOUNT_SID", "")
    twilio_auth_token: str = os.getenv("TWILIO_AUTH_TOKEN", "")
    twilio_phone_number: str = os.getenv("TWILIO_PHONE_NUMBER", "")

    # Deepgram
    deepgram_api_key: str = os.getenv("DEEPGRAM_API_KEY", "")

    # Database
    threat_intel_db_path: str = os.getenv(
        "THREAT_INTEL_DB_PATH", "./shared/data/threat_intel.db"
    )

    # Alerting
    alert_webhook_url: Optional[str] = os.getenv("ALERT_WEBHOOK_URL")

    # Environment
    environment: str = os.getenv("ENVIRONMENT", "development")
    log_level: str = os.getenv("LOG_LEVEL", "INFO")

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def is_development(self) -> bool:
        return self.environment == "development"


# Severity levels used across all components
class Severity:
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    SCORES = {
        LOW: (0, 30),
        MEDIUM: (31, 60),
        HIGH: (61, 85),
        CRITICAL: (86, 100),
    }

    @staticmethod
    def from_score(score: int) -> str:
        for level, (low, high) in Severity.SCORES.items():
            if low <= score <= high:
                return level
        return Severity.CRITICAL


# MITRE ATT&CK technique mappings relevant to Corvus Mirage
MITRE_TECHNIQUES = {
    # Social Engineering / Vishing
    "pretexting": "T1566",
    "authority_impersonation": "T1078",
    "urgency_manipulation": "T1566.004",
    "credential_fishing": "T1598",
    "verification_bypass": "T1566.003",
    "social_engineering": "T1566",

    # AI-Specific Attacks
    "prompt_injection": "T1059",
    "jailbreak_attempt": "T1059.007",
    "model_extraction": "T1588",
    "adversarial_input": "T1059",
    "data_exfiltration_via_model": "T1041",

    # General
    "privilege_escalation": "T1078.004",
    "lateral_movement": "T1550",
    "reconnaissance": "T1592",
}


config = Config()
