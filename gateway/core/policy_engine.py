"""
Corvus Mirage — Gateway
Policy Engine

Evaluates detection results against configurable rules.
Policies are evaluated in order — first match wins.
Configurable via YAML or dynamically via admin API.
"""
import yaml
import logging
from typing import Dict, List, Optional, Any
from pathlib import Path

from .models import Action, ThreatLevel, DetectionResult, PolicyMatch


logger = logging.getLogger("gateway.policy_engine")


class Policy:
    """Single policy rule"""

    def __init__(self, config: Dict[str, Any]):
        self.name        = config.get("name", "unnamed")
        self.enabled     = config.get("enabled", True)
        self.action      = Action(config.get("action", "log"))
        self.severity    = ThreatLevel(config.get("severity", "medium"))
        self.threshold   = config.get("threshold", 0.5)
        self.description = config.get("description", "")
        self.conditions  = config.get("conditions", {})

    def matches(self, detection: DetectionResult) -> bool:
        if not self.enabled:
            return False

        # Threshold check (detection score is 0-100, threshold is 0-1)
        if detection.threat_score / 100 < self.threshold:
            return False

        # Severity level check
        order = {
            ThreatLevel.SAFE:     0,
            ThreatLevel.LOW:      1,
            ThreatLevel.MEDIUM:   2,
            ThreatLevel.HIGH:     3,
            ThreatLevel.CRITICAL: 4,
        }
        if order[detection.threat_level] < order[self.severity]:
            return False

        # Category filter (optional)
        if "categories" in self.conditions:
            required = self.conditions["categories"]
            if not any(cat in detection.categories for cat in required):
                return False

        return True

    def to_match(self, detection: DetectionResult) -> PolicyMatch:
        return PolicyMatch(
            policy_name=self.name,
            action=self.action,
            severity=self.severity,
            reason=self.description or f"Matched policy: {self.name}",
            metadata={
                "threshold":       self.threshold,
                "detection_score": detection.threat_score,
            }
        )


class PolicyEngine:
    """
    Policy Engine — evaluates DetectionResults against ordered rules.
    """

    def __init__(self, config_path: Optional[str] = None):
        self.policies: List[Policy] = []

        if config_path and Path(config_path).exists():
            self.load_policies(config_path)
        else:
            self._load_defaults()

    def load_policies(self, config_path: str):
        try:
            with open(config_path, "r") as f:
                config = yaml.safe_load(f)
            self.policies = [Policy(p) for p in config.get("policies", [])]
            logger.info(f"[✓] Loaded {len(self.policies)} policies from {config_path}")
        except Exception as e:
            logger.warning(f"Failed to load policies from {config_path}: {e} — using defaults")
            self._load_defaults()

    def _load_defaults(self):
        defaults = [
            {
                "name":        "block_critical",
                "enabled":     True,
                "action":      "block",
                "severity":    "critical",
                "threshold":   0.75,
                "description": "Block critical threats immediately",
            },
            {
                "name":        "block_high_injection",
                "enabled":     True,
                "action":      "block",
                "severity":    "high",
                "threshold":   0.65,
                "description": "Block high-confidence prompt injection",
                "conditions":  {"categories": ["instruction_override", "jailbreak", "code_injection"]},
            },
            {
                "name":        "sanitize_high",
                "enabled":     True,
                "action":      "sanitize",
                "severity":    "high",
                "threshold":   0.60,
                "description": "Sanitize high-severity prompts",
            },
            {
                "name":        "log_medium",
                "enabled":     True,
                "action":      "log",
                "severity":    "medium",
                "threshold":   0.35,
                "description": "Log medium-severity threats for review",
            },
            {
                "name":        "allow_safe",
                "enabled":     True,
                "action":      "allow",
                "severity":    "safe",
                "threshold":   0.0,
                "description": "Allow clean prompts",
            },
        ]
        self.policies = [Policy(p) for p in defaults]
        logger.info(f"[✓] Loaded {len(self.policies)} default policies")

    def evaluate(self, detection: DetectionResult) -> PolicyMatch:
        for policy in self.policies:
            if policy.matches(detection):
                return policy.to_match(detection)

        # Fallback
        return PolicyMatch(
            policy_name="default_allow",
            action=Action.ALLOW,
            severity=ThreatLevel.SAFE,
            reason="No policy matched — default allow",
        )

    def add_policy(self, config: Dict[str, Any]) -> Policy:
        policy = Policy(config)
        self.policies.append(policy)
        logger.info(f"Policy added: {policy.name}")
        return policy

    def remove_policy(self, name: str) -> bool:
        before = len(self.policies)
        self.policies = [p for p in self.policies if p.name != name]
        removed = len(self.policies) < before
        if removed:
            logger.info(f"Policy removed: {name}")
        return removed

    def update_policy(self, name: str, config: Dict[str, Any]) -> bool:
        for i, p in enumerate(self.policies):
            if p.name == name:
                config["name"] = name
                self.policies[i] = Policy(config)
                logger.info(f"Policy updated: {name}")
                return True
        return False

    def list_policies(self) -> List[Dict[str, Any]]:
        return [
            {
                "name":        p.name,
                "enabled":     p.enabled,
                "action":      p.action.value,
                "severity":    p.severity.value,
                "threshold":   p.threshold,
                "description": p.description,
                "conditions":  p.conditions,
            }
            for p in self.policies
        ]


# Singleton
_policy_engine: Optional[PolicyEngine] = None

def get_policy_engine(config_path: Optional[str] = None) -> PolicyEngine:
    global _policy_engine
    if _policy_engine is None:
        _policy_engine = PolicyEngine(config_path=config_path)
    return _policy_engine
