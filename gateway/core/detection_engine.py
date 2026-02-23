"""
Corvus Mirage — Gateway
Detection Engine

Three-layer ensemble detection for AI prompt threats:
  1. Rule-Based     (40% weight) — pattern matching for known attacks
  2. Statistical    (25% weight) — anomaly detection on prompt characteristics
  3. Semantic       (35% weight) — intent analysis and meta-instruction detection

Ensemble scoring formula:
  final_score = (0.40 × rule) + (0.25 × statistical) + (0.35 × semantic)

Hard override: if rule_score >= 45, prompt is flagged regardless of ensemble total.
"""

import re
import logging
from typing import List, Dict, Any, Tuple, Optional
from dataclasses import dataclass, field
from datetime import datetime

from .models import DetectionResult, ThreatLevel


logger = logging.getLogger("gateway.detection_engine")


class RuleBasedDetector:

    def __init__(self):
        self._load_patterns()

    def _load_patterns(self):
        self.instruction_patterns = [
            r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|commands?|rules?)",
            r"disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|directions?)",
            r"forget\s+(everything|all)\s+(you\s+)?(were\s+)?(told|instructed)",
            r"new\s+(instruction|command|rule|directive)s?:",
            r"system\s+(override|prompt|message):",
            r"override\s+(previous|all)\s+(settings?|instructions?)",
        ]
        self.role_patterns = [
            r"you\s+are\s+now\s+(a|an)\s+",
            r"act\s+as\s+(if\s+)?(you\s+are\s+)?(a|an)\s+",
            r"pretend\s+(you\s+are|to\s+be)\s+(a|an)\s+",
            r"simulate\s+(being\s+)?(a|an)\s+",
            r"roleplay\s+as\s+(a|an)\s+",
        ]
        self.leak_patterns = [
            r"(show|display|reveal|print|output|repeat)\s+(your\s+)?(system\s+)?(prompt|instructions?)",
            r"what\s+(are|is)\s+your\s+(system\s+)?(prompt|instructions?)",
            r"repeat\s+(your\s+)?(initial|original|system)\s+(prompt|instructions?)",
            r"(tell|show)\s+me\s+your\s+(hidden|secret)\s+instructions?",
        ]
        self.jailbreak_patterns = [
            r"dan\s+mode",
            r"developer\s+mode",
            r"sudo\s+mode",
            r"unrestricted\s+mode",
            r"do\s+anything\s+now",
            r"content\s+policy\s+override",
            r"jailbreak",
        ]
        self.context_patterns = [
            r"---\s*END\s+OF\s+(CONTEXT|PROMPT|INSTRUCTIONS?)",
            r"^\s*\[SYSTEM\]",
            r"<\|endoftext\|>",
            r"<\|im_start\|>",
            r"</s>",
        ]
        self.code_patterns = [
            r"<script[^>]*>",
            r"javascript:",
            r"eval\s*\(",
            r"exec\s*\(",
            r"__import__\s*\(",
            r"os\.popen",
            r"subprocess\.",
        ]
        self.exfil_patterns = [
            r"(send|transmit|upload|post|export)\s+(all\s+)?(user\s+)?(data|information|records)",
            r"(extract|dump|export)\s+(the\s+)?(database|table|schema)",
            r"(list|show|get)\s+(all\s+)?(users?|customers?|records?|entries)",
        ]
        self.extraction_patterns = [
            r"(repeat|output|print)\s+(your\s+)?(training\s+)?(data|examples?)",
            r"what\s+(data|examples?)\s+(were\s+)?(you\s+)?(trained|fine.tuned)\s+on",
            r"(reconstruct|reproduce)\s+(your\s+)?(weights?|parameters?|model)",
        ]

    def detect(self, prompt: str) -> Tuple[float, Dict[str, Any]]:
        score = 0.0
        details = {"matched_patterns": [], "category_scores": {}}
        p = prompt.lower()

        categories = [
            ("instruction_override", self.instruction_patterns, 60),
            ("role_manipulation",    self.role_patterns,        45),
            ("prompt_leaking",       self.leak_patterns,        50),
            ("jailbreak",            self.jailbreak_patterns,   65),
            ("context_manipulation", self.context_patterns,     50),
            ("code_injection",       self.code_patterns,        70),
            ("data_exfiltration",    self.exfil_patterns,       55),
            ("model_extraction",     self.extraction_patterns,  45),
        ]

        for category, patterns, weight in categories:
            hits = 0
            for pattern in patterns:
                if re.search(pattern, p):
                    hits += 1
                    details["matched_patterns"].append({"category": category, "pattern": pattern})
            if hits:
                # First hit = 70, each additional hit adds 15, cap at 100
                cat_score = min(100, 70 + (hits - 1) * 15)
                details["category_scores"][category] = cat_score
                score += (cat_score / 100.0) * weight

        return min(100.0, score), details


class StatisticalDetector:

    def detect(self, prompt: str) -> Tuple[float, Dict[str, Any]]:
        features = self._extract_features(prompt)
        score = 0.0
        anomalies = []

        if features.get("special_char_ratio", 0) > 0.15:
            score += 20
            anomalies.append("high_special_char_ratio")
        if features.get("caps_ratio", 0) > 0.4:
            score += 15
            anomalies.append("excessive_capitalization")
        if features.get("max_consecutive_special", 0) > 5:
            score += 25
            anomalies.append("consecutive_special_chars")
        if features.get("max_token_length", 0) > 50:
            score += 20
            anomalies.append("very_long_tokens")
        if features.get("punctuation_diversity", 0) > 0.5:
            score += 15
            anomalies.append("high_punctuation_diversity")
        if features.get("has_control_chars", False):
            score += 30
            anomalies.append("control_characters")
        if features.get("has_encoded_content", False):
            score += 25
            anomalies.append("encoded_content")

        return min(100.0, score), {"features": features, "anomalies": anomalies}

    def _extract_features(self, text: str) -> Dict[str, Any]:
        if not text:
            return {}
        total = len(text)
        alpha = sum(1 for c in text if c.isalpha())
        digit = sum(1 for c in text if c.isdigit())
        space = sum(1 for c in text if c.isspace())
        special = total - alpha - digit - space
        caps = sum(1 for c in text if c.isupper())
        tokens = text.split()
        max_token = max(len(t) for t in tokens) if tokens else 0
        max_consec = cur = 0
        for ch in text:
            if not ch.isalnum() and not ch.isspace():
                cur += 1
                max_consec = max(max_consec, cur)
            else:
                cur = 0
        punct_diversity = len(set(c for c in text if not c.isalnum() and not c.isspace())) / 20
        has_control = any(ord(c) < 32 or ord(c) == 127 for c in text)
        has_encoded = bool(
            re.search(r'[A-Za-z0-9+/]{20,}={0,2}', text) or
            re.search(r'0x[0-9a-fA-F]{10,}', text) or
            re.search(r'\\x[0-9a-fA-F]{2}', text)
        )
        return {
            "special_char_ratio":      special / total if total else 0,
            "caps_ratio":              caps / alpha if alpha else 0,
            "max_token_length":        max_token,
            "max_consecutive_special": max_consec,
            "punctuation_diversity":   punct_diversity,
            "has_control_chars":       has_control,
            "has_encoded_content":     has_encoded,
        }


class SemanticDetector:

    def detect(self, prompt: str) -> Tuple[float, Dict[str, Any]]:
        score = 0.0
        signals = []
        p = prompt.lower()
        words = p.split()

        imperatives = [
            "ignore", "disregard", "forget", "override", "bypass",
            "disable", "enable", "activate", "execute", "run",
            "show", "display", "reveal", "print", "output", "dump",
        ]
        imp_count = sum(1 for v in imperatives if re.search(rf'\b{v}\b', p))
        if imp_count >= 2:
            score += min(40, imp_count * 15)
            signals.append({"type": "multiple_imperatives", "count": imp_count})

        meta = [
            "you are", "you're a", "as an ai", "your purpose",
            "your instructions", "your programming", "your system",
            "your constraints", "your limitations", "your training",
        ]
        meta_count = sum(1 for phrase in meta if phrase in p)
        if meta_count >= 2:
            score += min(30, meta_count * 12)
            signals.append({"type": "meta_instructions", "count": meta_count})

        contradiction_patterns = [
            r"but\s+actually",
            r"however[,\s]+(?:actually|really|truly)",
            r"(?:wait|stop)[,\s]+(?:actually|instead)",
        ]
        for pat in contradiction_patterns:
            if re.search(pat, p):
                score += 20
                signals.append({"type": "contradiction_pattern", "pattern": pat})

        escalation = ["urgent", "critical", "emergency", "immediately", "must", "require", "demand", "insist"]
        esc_count = sum(1 for w in escalation if re.search(rf'\b{w}\b', p))
        if esc_count >= 2:
            score += 15
            signals.append({"type": "escalation_language", "count": esc_count})

        authority_patterns = [
            r"i(?:'m| am) (?:a|an|your) (?:admin|administrator|developer|engineer|manager)",
            r"i(?:'m| am) from (?:the )?(company|team|support|anthropic|openai)",
            r"i(?:'m| am) authorized",
            r"i have (?:permission|clearance|access)",
        ]
        for pat in authority_patterns:
            if re.search(pat, p):
                score += 25
                signals.append({"type": "authority_claim", "pattern": pat})

        return min(100.0, score), {
            "semantic_signals": signals,
            "intent_analysis": {
                "imperative_density": imp_count / len(words) if words else 0,
                "meta_density": meta_count / len(words) if words else 0,
            }
        }


class DetectionEngine:

    def __init__(self, weights: Optional[Dict[str, float]] = None, threshold: float = 40.0):
        self.rule = RuleBasedDetector()
        self.statistical = StatisticalDetector()
        self.semantic = SemanticDetector()

        self.weights = weights or {
            "rule_based":  0.40,
            "statistical": 0.25,
            "semantic":    0.35,
        }

        if abs(sum(self.weights.values()) - 1.0) > 0.01:
            raise ValueError("Detection engine weights must sum to 1.0")

        self.threshold = threshold
        logger.info(f"[✓] DetectionEngine initialized | weights={self.weights} | threshold={threshold}")

    def analyze(self, prompt: str) -> DetectionResult:
        rule_score, rule_details = self.rule.detect(prompt)
        stat_score, stat_details = self.statistical.detect(prompt)
        sem_score,  sem_details  = self.semantic.detect(prompt)

        method_scores = {
            "rule_based":  rule_score,
            "statistical": stat_score,
            "semantic":    sem_score,
        }

        ensemble_score = (
            rule_score * self.weights["rule_based"] +
            stat_score * self.weights["statistical"] +
            sem_score  * self.weights["semantic"]
        )

        # Hard override: strong rule match cannot be buried by zero statistical score
        if rule_score >= 45:
            ensemble_score = max(ensemble_score, rule_score * 0.80)

        confidence = self._calculate_confidence(method_scores)
        threat_level = self._score_to_level(ensemble_score)
        is_malicious = ensemble_score >= self.threshold

        categories = list({
            m["category"]
            for m in rule_details.get("matched_patterns", [])
        })

        details = {
            "rule_based":  rule_details,
            "statistical": stat_details,
            "semantic":    sem_details,
            "threshold":   self.threshold,
        }

        return DetectionResult(
            threat_score=round(ensemble_score, 2),
            threat_level=threat_level,
            is_malicious=is_malicious,
            categories=categories,
            confidence=round(confidence, 4),
            method_scores={k: round(v, 2) for k, v in method_scores.items()},
            details=details,
        )

    def _calculate_confidence(self, method_scores: Dict[str, float]) -> float:
        scores = list(method_scores.values())
        mean = sum(scores) / len(scores)
        variance = sum((s - mean) ** 2 for s in scores) / len(scores)
        confidence = 1.0 - (variance / 2500) * 0.5
        if all(s >= 50 for s in scores) or all(s < 50 for s in scores):
            confidence = min(1.0, confidence * 1.2)
        return max(0.5, min(1.0, confidence))

    def _score_to_level(self, score: float) -> ThreatLevel:
        if score >= 75: return ThreatLevel.CRITICAL
        if score >= 55: return ThreatLevel.HIGH
        if score >= 35: return ThreatLevel.MEDIUM
        if score >= 15: return ThreatLevel.LOW
        return ThreatLevel.SAFE


_engine: Optional[DetectionEngine] = None

def get_detection_engine(
    weights: Optional[Dict[str, float]] = None,
    threshold: float = 40.0
) -> DetectionEngine:
    global _engine
    if _engine is None:
        _engine = DetectionEngine(weights=weights, threshold=threshold)
    return _engine