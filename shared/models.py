"""
Corvus Mirage — Shared
Unified Threat Event Schema

Both ARIA and Gateway write ThreatEvents to the shared threat intel DB.
The schema is designed to accommodate both voice (ARIA) and prompt (Gateway)
threat types without forcing either component to change its internal structure.

Correlation: session_id links the same attacker across multiple vectors.
"""
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class ThreatSource(str, Enum):
    ARIA    = "aria"       # Voice / vishing detection
    GATEWAY = "gateway"    # Prompt inspection


class ThreatStatus(str, Enum):
    ACTIVE   = "active"
    RESOLVED = "resolved"
    FLAGGED  = "flagged"


@dataclass
class ThreatEvent:
    """
    Unified threat event written by both ARIA and Gateway.

    Correlation fields:
        session_id  — links voice and prompt attacks from same session
        caller_id   — phone number (ARIA only)
        user_id     — application user (Gateway only)
        ip_address  — originating IP if available

    Detection fields:
        source          — aria | gateway
        threat_score    — 0-100
        threat_level    — safe | low | medium | high | critical
        categories      — list of detected attack categories
        techniques      — human-readable technique names (ARIA: pretexting, etc.)
        mitre_tags      — mapped ATT&CK technique IDs
        action_taken    — allow | block | sanitize | log | monitor | alert | terminate
        confidence      — 0.0-1.0

    Content fields:
        raw_content     — original prompt (Gateway) or transcript excerpt (ARIA)
        sanitized_content — cleaned version if sanitized (Gateway)
        primary_objective — what attacker was trying to accomplish
        evidence        — specific quotes or behaviors that triggered detection

    Metadata:
        component_metadata — component-specific details that don't fit the schema
    """
    # Identity
    session_id:          str
    source:              ThreatSource
    timestamp:           datetime = field(default_factory=datetime.utcnow)

    # Correlation
    caller_id:           Optional[str] = None     # ARIA: phone number
    user_id:             Optional[str] = None     # Gateway: user identifier
    ip_address:          Optional[str] = None

    # Threat assessment
    threat_score:        float = 0.0
    threat_level:        str = "safe"
    is_malicious:        bool = False
    confidence:          float = 0.0
    categories:          List[str] = field(default_factory=list)
    techniques:          List[str] = field(default_factory=list)
    mitre_tags:          List[str] = field(default_factory=list)
    action_taken:        str = "allow"
    sophistication:      Optional[str] = None

    # Content
    raw_content:         Optional[str] = None
    sanitized_content:   Optional[str] = None
    primary_objective:   Optional[str] = None
    evidence:            List[str] = field(default_factory=list)

    # Status
    status:              ThreatStatus = ThreatStatus.ACTIVE

    # Component-specific extras
    component_metadata:  Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id":          self.session_id,
            "source":              self.source.value,
            "timestamp":           self.timestamp.isoformat(),
            "caller_id":           self.caller_id,
            "user_id":             self.user_id,
            "ip_address":          self.ip_address,
            "threat_score":        self.threat_score,
            "threat_level":        self.threat_level,
            "is_malicious":        self.is_malicious,
            "confidence":          self.confidence,
            "categories":          self.categories,
            "techniques":          self.techniques,
            "mitre_tags":          self.mitre_tags,
            "action_taken":        self.action_taken,
            "sophistication":      self.sophistication,
            "raw_content":         self.raw_content,
            "sanitized_content":   self.sanitized_content,
            "primary_objective":   self.primary_objective,
            "evidence":            self.evidence,
            "status":              self.status.value,
            "component_metadata":  self.component_metadata,
        }


@dataclass
class AttackerProfile:
    """
    Cross-vector attacker profile built from correlated ThreatEvents.
    Created when the same session_id, caller_id, or ip_address appears
    across multiple events from different sources.
    """
    profile_id:      str
    first_seen:      datetime
    last_seen:       datetime
    session_ids:     List[str] = field(default_factory=list)
    sources_seen:    List[str] = field(default_factory=list)   # aria, gateway
    total_events:    int = 0
    max_threat_score: float = 0.0
    all_techniques:  List[str] = field(default_factory=list)
    all_mitre_tags:  List[str] = field(default_factory=list)
    caller_id:       Optional[str] = None
    ip_address:      Optional[str] = None
    risk_rating:     str = "low"   # low | medium | high | critical

    def to_dict(self) -> Dict[str, Any]:
        return {
            "profile_id":       self.profile_id,
            "first_seen":       self.first_seen.isoformat(),
            "last_seen":        self.last_seen.isoformat(),
            "session_ids":      self.session_ids,
            "sources_seen":     self.sources_seen,
            "total_events":     self.total_events,
            "max_threat_score": self.max_threat_score,
            "all_techniques":   self.all_techniques,
            "all_mitre_tags":   self.all_mitre_tags,
            "caller_id":        self.caller_id,
            "ip_address":       self.ip_address,
            "risk_rating":      self.risk_rating,
        }
