"""
Corvus Mirage — Gateway
Data Models

Shared data structures across detection, policy, and API layers.
"""
from enum import Enum
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from datetime import datetime


class ThreatLevel(Enum):
    """Threat severity levels"""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Action(Enum):
    """Policy actions"""
    ALLOW = "allow"
    BLOCK = "block"
    SANITIZE = "sanitize"
    LOG = "log"
    ALERT = "alert"


@dataclass
class DetectionResult:
    """
    Unified detection result from the ensemble engine.
    Combines scores from rule-based, statistical, and semantic layers.
    """
    threat_score: float          # 0-100
    threat_level: ThreatLevel
    is_malicious: bool
    categories: List[str] = field(default_factory=list)
    confidence: float = 0.0
    method_scores: Dict[str, float] = field(default_factory=dict)
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "threat_score": self.threat_score,
            "threat_level": self.threat_level.value,
            "is_malicious": self.is_malicious,
            "categories": self.categories,
            "confidence": self.confidence,
            "method_scores": self.method_scores,
            "details": self.details
        }


@dataclass
class PolicyMatch:
    """Matched policy rule and its decision"""
    policy_name: str
    action: Action
    severity: ThreatLevel
    reason: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "policy_name": self.policy_name,
            "action": self.action.value,
            "severity": self.severity.value,
            "reason": self.reason,
            "metadata": self.metadata
        }


@dataclass
class GatewayRequest:
    """Incoming inspection request"""
    prompt: str
    model: Optional[str] = None        # Target model (claude, gpt, gemini, etc.)
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class GatewayResponse:
    """Gateway inspection decision"""
    action: Action
    allowed: bool
    original_prompt: str
    sanitized_prompt: Optional[str] = None
    threat_score: float = 0.0
    threat_level: ThreatLevel = ThreatLevel.SAFE
    detection: Optional[DetectionResult] = None
    policy_match: Optional[PolicyMatch] = None
    message: str = ""
    timestamp: datetime = field(default_factory=datetime.utcnow)
    processing_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action.value,
            "allowed": self.allowed,
            "original_prompt": self.original_prompt,
            "sanitized_prompt": self.sanitized_prompt,
            "threat_score": self.threat_score,
            "threat_level": self.threat_level.value,
            "detection": self.detection.to_dict() if self.detection else None,
            "policy_match": self.policy_match.to_dict() if self.policy_match else None,
            "message": self.message,
            "timestamp": self.timestamp.isoformat(),
            "processing_time_ms": self.processing_time_ms
        }


@dataclass
class AuditLog:
    """Audit log entry for every inspection"""
    request_id: str
    timestamp: datetime
    user_id: Optional[str]
    session_id: Optional[str]
    model: Optional[str]
    prompt: str
    action: Action
    threat_score: float
    threat_level: ThreatLevel
    policy_matched: Optional[str]
    processing_time_ms: float
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "timestamp": self.timestamp.isoformat(),
            "user_id": self.user_id,
            "session_id": self.session_id,
            "model": self.model,
            "prompt": self.prompt,
            "action": self.action.value,
            "threat_score": self.threat_score,
            "threat_level": self.threat_level.value,
            "policy_matched": self.policy_matched,
            "processing_time_ms": self.processing_time_ms,
            "metadata": self.metadata
        }
