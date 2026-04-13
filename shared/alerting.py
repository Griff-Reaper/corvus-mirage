"""
Corvus Mirage — Shared Alerting
Unified alert pipeline. All components call this to fire alerts.
Supports Slack webhooks, email (future), and custom webhooks.
"""

import httpx
import logging
from datetime import datetime
from typing import Optional
from shared.config import config, Severity

logger = logging.getLogger("corvus.alerting")


class Alert:
    def __init__(
        self,
        title: str,
        description: str,
        severity: str,
        component: str,          # 'aria', 'gateway', 'red_team'
        session_id: Optional[str] = None,
        techniques: Optional[list] = None,
        mitre_tags: Optional[list] = None,
        metadata: Optional[dict] = None,
    ):
        self.title = title
        self.description = description
        self.severity = severity
        self.component = component
        self.session_id = session_id
        self.techniques = techniques or []
        self.mitre_tags = mitre_tags or []
        self.metadata = metadata or {}
        self.timestamp = datetime.utcnow().isoformat()

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "component": self.component,
            "session_id": self.session_id,
            "techniques": self.techniques,
            "mitre_tags": self.mitre_tags,
            "metadata": self.metadata,
            "timestamp": self.timestamp,
        }

    def to_slack_payload(self) -> dict:
        # Keys match the string values from Severity class
        severity_colors = {
            Severity.LOW:      "#36a64f",
            Severity.MEDIUM:   "#ff9900",
            Severity.HIGH:     "#ff4444",
            Severity.CRITICAL: "#8b0000",
        }

        color = severity_colors.get(self.severity.upper(), "#cccccc")
        techniques_str = ", ".join(self.techniques) if self.techniques else "Unknown"
        mitre_str = ", ".join(self.mitre_tags) if self.mitre_tags else "N/A"

        return {
            "attachments": [
                {
                    "color": color,
                    "title": f"🦅 Corvus Mirage — {self.title}",
                    "text": self.description,
                    "fields": [
                        {"title": "Severity",   "value": self.severity,              "short": True},
                        {"title": "Component",  "value": self.component.upper(),     "short": True},
                        {"title": "Techniques", "value": techniques_str,             "short": False},
                        {"title": "MITRE Tags", "value": mitre_str,                  "short": False},
                        {"title": "Session ID", "value": self.session_id or "N/A",  "short": True},
                        {"title": "Time",       "value": self.timestamp,             "short": True},
                    ],
                    "footer": "Corvus Mirage Security Platform",
                }
            ]
        }


async def fire_alert(alert: Alert) -> bool:
    """Fire an alert through all configured channels."""
    success = True

    # Log regardless of webhook config
    log_fn = {
        Severity.LOW:      logger.info,
        Severity.MEDIUM:   logger.warning,
        Severity.HIGH:     logger.error,
        Severity.CRITICAL: logger.critical,
    }.get(alert.severity.upper(), logger.warning)

    log_fn(f"[ALERT][{alert.component.upper()}][{alert.severity}] {alert.title} — {alert.description}")

    # Webhook (Slack or custom)
    if config.alert_webhook_url:
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    config.alert_webhook_url,
                    json=alert.to_slack_payload(),
                    timeout=5.0,
                )
                response.raise_for_status()
                logger.info(f"Alert delivered to webhook | status={response.status_code}")
        except Exception as e:
            logger.error(f"Failed to send alert to webhook: {e}")
            success = False
    else:
        logger.debug("No ALERT_WEBHOOK_URL configured — alert logged only")

    return success


def build_gateway_alert(response: dict) -> Alert:
    """
    Build a standard Alert from a Gateway inspection response dict.
    Call this for HIGH and CRITICAL detections.
    """
    threat_level = response.get("threat_level", "unknown").upper()
    categories   = response.get("detection", {}).get("categories", [])
    session_id   = response.get("session_id")
    score        = response.get("threat_score", 0)
    ip           = response.get("ip_address", "unknown")
    prompt       = (response.get("original_prompt") or "")[:120]

    severity = Severity.from_score(int(score))

    return Alert(
        title=f"Prompt Threat Detected — {threat_level}",
        description=(
            f"Gateway blocked a {threat_level} prompt from {ip}. "
            f"Score: {score}/100. Preview: \"{prompt}{'...' if len(prompt) == 120 else ''}\""
        ),
        severity=severity,
        component="gateway",
        session_id=session_id,
        techniques=categories,
        metadata={
            "threat_score": score,
            "ip_address":   ip,
            "request_id":   response.get("request_id"),
            "action":       response.get("action"),
        },
    )