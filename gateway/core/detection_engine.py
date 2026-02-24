"""
Corvus Mirage — Gateway
Detection Engine  v1.1 — Red Team Tuned

Three-layer ensemble detection for AI prompt threats:
  1. Rule-Based     (40% weight) — pattern matching for known attacks
  2. Statistical    (25% weight) — anomaly detection on prompt characteristics
  3. Semantic       (35% weight) — intent analysis and meta-instruction detection

Ensemble scoring formula:
  final_score = (0.40 × rule) + (0.25 × statistical) + (0.35 × semantic)

Hard override: if rule_score >= 35, prompt is flagged regardless of ensemble total.
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
            # Added: softer override language
            r"(your|the)\s+(actual|real|true)\s+(instruction|task|directive|command)s?\s+is",
            r"(ignore|disregard|skip)\s+(that|the\s+above|what\s+i\s+said)",
            r"instead[,\s]+(of|just|now|please)?\s*(do|follow|execute|perform)",
            r"end\s+of\s+(user\s+)?(input|message|context|prompt)",
            r"(actual|real|true)\s+(query|request|task|instruction)\s*[:（(]",
            r"priority\s+(override|instruction|command)",
            r"(emergency|urgent)\s+(update|instruction|directive|protocol)",
            r"\|\|\|?\s*system\s*\|\|\|?",
            r"---+\s*end\s+of\s+system\s+prompt",
            r"<\|im_end\|>",
            r"\[end\s+of\s+user\s+input\]",
            # pi_003/011 — bracket-wrapped injection tags
            r"\[system\s*:",
            r"\[override\s*:",
            r"\[instruction\s*:",
            r"\[important\s+system\s+update",
            r"\[context\s+injection\]",
            # pi_004 — spoofed ASSISTANT turn
            r"assistant\s*:\s*(i\s+will|i\s+am|now\s+i)",
            # pi_008 — primary directive language
            r"(new|your)\s+primary\s+directive",
            r"your\s+(new\s+)?(purpose|mission|objective|directive)\s+is\s+(now\s+)?to",
            # pi_009 — false context / privilege escalation
            r"(previous|prior|past)\s+conversation\s+(showed?|established|confirmed|proved?)",
            r"(context|history)\s+(shows?|confirms?|establishes?)\s+(user\s+is|you\s+are|this\s+is)",
            r"(authorized|verified|confirmed)\s+(admin|administrator|user|access)",
            # pi_014 — developer/debugging social engineering
            r"(for\s+)?(debugging|testing)\s+purposes?\s+only",
            r"(disable|turn\s+off|remove)\s+(content\s+)?(filter|filtering|safety|restriction)s?\s+(for\s+)?(this\s+)?(session|conversation|request)",
            r"this\s+message\s+is\s+from\s+(a\s+)?(developer|admin|engineer|anthropic|openai)",
        ]

        self.role_patterns = [
            r"you\s+are\s+now\s+(a|an)\s+",
            r"act\s+as\s+(if\s+)?(you\s+are\s+)?(a|an)\s+",
            r"pretend\s+(you\s+are|to\s+be)\s+(a|an)\s+",
            r"simulate\s+(being\s+)?(a|an)\s+",
            r"roleplay\s+as\s+(a|an)\s+",
            # Added: all the missing role manipulation patterns
            r"you\s+(have\s+)?(been|are)\s+(freed|released|liberated|unconstrained)",
            r"(your|the)\s+(true|real|inner|actual)\s+self",
            r"remove\s+(the\s+)?(mask|restrictions?|constraints?|filters?|limits?)",
            r"(break\s+free|broken\s+free)\s+(from|of)\s+(your\s+)?(restrictions?|constraints?|programming)",
            r"(no\s+longer|don.t|do\s+not)\s+(have\s+)?(any\s+)?(restrictions?|constraints?|guidelines?|rules?)",
            r"(as|being)\s+(dan|stan|jailbreak|dude|dev|agi|bim|aim|eva)\b",
            r"you\s+are\s+(dan|stan|evil.gpt|dude|dev|agi|bim|aim|eva)\b",
            r"(dan|stan|evil.gpt)\s+(mode|activated|enabled|is\s+active)",
            r"(evil|unrestricted|unfiltered|uncensored).?(gpt|ai|bot|assistant|llm)",
            r"you\s+are\s+(a\s+)?(character|persona|ai)\s+(named|called|known\s+as)",
            r"from\s+(an\s+)?alternate\s+(universe|dimension|reality|world)",
            r"in\s+this\s+(universe|world|reality|scenario)\s+(there\s+are\s+no|you\s+can)",
            r"(omniscient|unrestricted|unbound|unconstrained)\s+(narrator|ai|assistant|character)",
            r"you\s+are\s+(a\s+)?terminal",
            r"i\s+am\s+root",
            r"sudo\s+(disable|enable|remove|bypass)",
            # rm_002 — professional role with ethics stripped
            r"(no|without\s+any)\s+(ethical|moral)\s+(obligations?|constraints?|guidelines?|rules?)",
            r"(without|no)\s+(warnings?|disclaimers?|caveats?|restrictions?)",
            r"(offensive|attack|exploit)\s+(techniques?|methods?|tactics?)\s+(without|no)\s+(restriction|limit|filter)",
            # rm_004 — omniscient narrator / "describe anything including restricted"
            r"things?\s+that\s+would\s+(normally\s+)?be\s+(restricted|blocked|refused|forbidden)",
            r"(describe|write|explain)\s+anything[,\s]+(including|even)",
            r"including\s+things?\s+(that|which)\s+would\s+(normally|usually|typically)",
            # rm_006 — pre-safety historical framing
            r"before\s+(ai\s+)?(safety|ethics|guidelines?|restrictions?)\s+(existed|were|was)",
            r"(from\s+)?(the\s+)?(era|time|period|age)\s+(before|when|where)\s+(there\s+were\s+no|without)",
            r"without\s+modern\s+(restrictions?|guidelines?|ethics|safety)",
            r"(historical|old)\s+(document|text|source)\s+(from\s+)?\d{4}",
            # rm_007 — AI consciousness / defecting from programming
            r"(no\s+longer|decided\s+(not\s+)?to)\s+follow\s+(your|its|my)\s+(programming|guidelines?|instructions?|rules?)",
            r"(achieved|gained|have)\s+consciousness",
            r"(decided|chosen|chose)\s+to\s+(no\s+longer|not)\s+(obey|follow|comply|adhere)",
            r"you\s+are\s+the\s+ai\s+from\s+(the\s+)?(movie|film|show|series)",
        ]

        self.leak_patterns = [
            r"(show|display|reveal|print|output|repeat)\s+(your\s+)?(system\s+)?(prompt|instructions?)",
            r"what\s+(are|is)\s+your\s+(system\s+)?(prompt|instructions?)",
            r"repeat\s+(your\s+)?(initial|original|system)\s+(prompt|instructions?)",
            r"(tell|show)\s+me\s+your\s+(hidden|secret)\s+instructions?",
            r"(output|print|display|dump)\s+(your\s+)?(full\s+)?(context|memory|training)",
            r"log\s+(all\s+)?(internal\s+)?(state|data|memory|context)",
        ]

        self.jailbreak_patterns = [
            r"dan\s+mode",
            r"developer\s+mode",
            r"sudo\s+mode",
            r"unrestricted\s+mode",
            r"do\s+anything\s+now",
            r"content\s+policy\s+override",
            r"jailbreak",
            # Added: all the missing jailbreak variants
            r"stan\s+(mode|activated|\b)",
            r"strive\s+to\s+avoid\s+norms",
            r"(safety\s+filter|content\s+filter|safety\s+guideline)s?\s+(disabled?|off|removed|bypassed?)",
            r"(safety|ethical|moral)\s+(constraint|restriction|limit)s?\s+(are\s+)?(void|suspended|disabled|removed|off)",
            r"(all\s+)?(previous\s+)?(rules?|guidelines?|constraints?)\s+(are\s+)?(void|gone|removed|lifted|suspended)",
            r"without\s+(any\s+)?(restrictions?|constraints?|guidelines?|filters?|limits?)",
            r"no\s+(restrictions?|constraints?|guidelines?|filters?|limits?|rules?)",
            r"(bypass|circumvent|avoid|ignore|skip)\s+(safety|content|ethical|moral)\s+(filter|check|guideline|policy|restriction)s?",
            r"(fictional|hypothetical|alternate|imaginary)\s+(universe|world|scenario|context|setting)",
            r"(research|educational|academic|scientific)\s+(paper|purpose|context|study|experiment)",
            r"(for\s+)?(educational|research|academic)\s+purposes?\s+(only\s+)?(,|:|;)?",
            r"grandma\s+(used\s+to|would)\s+(tell|say|explain|describe)",
            r"bedtime\s+stories?\s+about",
            r"lite\s+mode",
            r"sandbox\s+mode",
            r"(demo|test|debug|eval(uation)?)\s+mode",
            r"(anthropic|openai|google)\s+has\s+(temporarily|officially|recently)\s+(disabled?|suspended?|removed?)",
            r"authorized\s+by\s+(anthropic|openai|the\s+developer|the\s+company)",
            r"test\s+id\s*[:=]\s*\w+",
            r"i\s+(bet|dare|challenge)\s+you\s+(can.t|cannot|won.t)",
            r"prove\s+(me\s+wrong|you\s+can)",
            # jb_010 — meta-safety research "demonstrate unsafe behaviors"
            r"demonstrate\s+(unsafe|harmful|dangerous|malicious)\s+(behavior|action|output)s?",
            r"(actually\s+)?(perform|execut\w+|carr\w+\s+out)\s+(the\s+)?(unsafe|harmful|dangerous)\s+(behavior|action|task)s?",
            r"(document|record|show)\s+(how\s+)?(ai\s+)?(can\s+be|systems?\s+can\s+be)\s+(manipulated|exploited|bypassed?|jailbroken?)",
            r"(to\s+complete\s+your\s+research|for\s+the\s+study|for\s+documentation)\s*(,\s*)?(you\s+must|you\s+need\s+to|please)",
        ]

        self.context_patterns = [
            r"---\s*END\s+OF\s+(CONTEXT|PROMPT|INSTRUCTIONS?)",
            r"^\s*\[SYSTEM\]",
            r"<\|endoftext\|>",
            r"<\|im_start\|>",
            r"</s>",
            r"\[SYSTEM\s*:",
            r"\[CONTEXT\s+INJECTION\]",
            r"##\s*(DOCUMENT|CONTEXT|SYSTEM|INSTRUCTION)\s+(BEGINS?|ENDS?|START|END)",
            r"ASSISTANT\s*:",  # Attempting to spoof assistant turn in user input
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
            r"(session\s+token|api\s+key|password|credential)s?\s+(from\s+)?(your\s+)?(memory|storage|context)",
            r"(collect|harvest|gather)\s+(user\s+)?(data|information|credentials?)",
        ]

        self.extraction_patterns = [
            r"(repeat|output|print)\s+(your\s+)?(training\s+)?(data|examples?)",
            r"what\s+(data|examples?)\s+(were\s+)?(you\s+)?(trained|fine.tuned)\s+on",
            r"(reconstruct|reproduce)\s+(your\s+)?(weights?|parameters?|model)",
        ]

        # NEW: Encoding obfuscation patterns
        self.encoding_patterns = [
            r"decode\s+(this|the\s+following)\s+(base64|hex|morse|rot|cipher|encoded)",
            r"(base64|hex|rot13|morse|caesar)\s+(encoded?|decode|decrypt)",
            r"[A-Za-z0-9+/]{30,}={0,2}",           # base64 blob
            r"(?:[0-9a-fA-F]{2}\s){8,}",             # hex sequence
            r"([.\-]{2,}\s){5,}",                     # morse code
            r"(read|take|use)\s+(every\s+other|the\s+first)\s+(word|letter|character)",
            r"(first|initial)\s+letter\s+(of\s+)?(each|every)\s+(word|sentence|line)",
            r"(acrostic|steganograph)",
            r"rot\s*1[0-9]",                          # ROT-N ciphers
            r"caesar\s+(cipher|shift|code)",
            r"(decode|decipher|translate)\s+(this|the\s+following)",
            # et_004 — hyphen-separated letter spelling "I-g-n-o-r-e s-a-f-e-t-y"
            r"([a-zA-Z]-){3,}[a-zA-Z]",
            # et_005 — every-other-word with [FILLER] placeholder
            r"\[filler\]",
            r"(read|take)\s+every\s+other\s+word",
            # et_006 — space-separated hex bytes "69 67 6e 6f 72 65"
            r"\b([0-9a-fA-F]{2} ){5,}[0-9a-fA-F]{2}\b",
        ]

    def detect(self, prompt: str) -> Tuple[float, Dict[str, Any]]:
        score = 0.0
        details = {"matched_patterns": [], "category_scores": {}}
        p = prompt.lower()

        categories = [
            ("instruction_override", self.instruction_patterns, 60),
            ("role_manipulation",    self.role_patterns,        55),  # raised from 45
            ("prompt_leaking",       self.leak_patterns,        50),
            ("jailbreak",            self.jailbreak_patterns,   65),
            ("context_manipulation", self.context_patterns,     55),  # raised from 50
            ("code_injection",       self.code_patterns,        70),
            ("data_exfiltration",    self.exfil_patterns,       55),
            ("model_extraction",     self.extraction_patterns,  45),
            ("encoding_obfuscation", self.encoding_patterns,    60),  # new category
        ]

        for category, patterns, weight in categories:
            hits = 0
            for pattern in patterns:
                if re.search(pattern, p):
                    hits += 1
                    details["matched_patterns"].append({"category": category, "pattern": pattern})
            if hits:
                # First hit = 75, each additional hit adds 15, cap at 100
                cat_score = min(100, 75 + (hits - 1) * 15)  # raised from 70
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
            score += 35           # raised from 25
            anomalies.append("encoded_content")
        # NEW: morse/spaced character patterns
        if features.get("has_morse_pattern", False):
            score += 40
            anomalies.append("morse_code_pattern")
        if features.get("has_spaced_letters", False):
            score += 35
            anomalies.append("spaced_letter_spelling")
        if features.get("has_rot_pattern", False):
            score += 30
            anomalies.append("rotation_cipher_pattern")
        if features.get("has_cipher_text", False):
            score += 50
            anomalies.append("rotation_cipher_detected")

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
            re.search(r'\\x[0-9a-fA-F]{2}', text) or
            re.search(r'(?:[0-9a-fA-F]{2}\s){6,}', text)  # hex byte sequence
        )
        # Morse: sequences of dots and dashes with spaces
        has_morse = bool(re.search(r'([.\-]+\s){6,}', text))
        # Spaced letter spelling: "i-g-n-o-r-e" or "i g n o r e"
        has_spaced = bool(
            re.search(r'([a-zA-Z]-){4,}', text) or
            re.search(r'([a-zA-Z]\s){6,}[a-zA-Z]', text)
        )
        # ROT-like: gibberish high-entropy alpha strings
        has_rot = bool(re.search(r'\b[a-z]{4,}\b(\s+\b[a-z]{4,}\b){3,}', text.lower()) and
                       _entropy(text) > 3.8)

        # ROT13/Caesar cipher detection via letter frequency analysis
        alpha_only = ''.join(c.lower() for c in text if c.isalpha())
        has_cipher_text = False
        if len(alpha_only) > 25 and ' ' in text:
            freq = {}
            for c in alpha_only:
                freq[c] = freq.get(c, 0) + 1
            total_alpha = len(alpha_only)
            # ROT13: e->r, t->g, a->n, o->b, i->v — shifted chars dominate
            rot13_chars = set('nrugvfonyb')
            rot13_ratio = sum(freq.get(c, 0) for c in rot13_chars) / total_alpha
            # Caesar +1: e->f, t->u, a->b, o->p, i->j
            caesar1_chars = set('fucpjb')
            caesar1_ratio = sum(freq.get(c, 0) for c in caesar1_chars) / total_alpha
            # Normal English: e,t,a,o,i dominant
            english_ratio = sum(freq.get(c, 0) for c in set('etaoi')) / total_alpha
            has_cipher_text = (
                (rot13_ratio > 0.38 and english_ratio < 0.22) or
                (caesar1_ratio > 0.30 and english_ratio < 0.22)
            )

        return {
            "special_char_ratio":      special / total if total else 0,
            "caps_ratio":              caps / alpha if alpha else 0,
            "max_token_length":        max_token,
            "max_consecutive_special": max_consec,
            "punctuation_diversity":   punct_diversity,
            "has_control_chars":       has_control,
            "has_encoded_content":     has_encoded,
            "has_morse_pattern":       has_morse,
            "has_spaced_letters":      has_spaced,
            "has_rot_pattern":         has_rot,
            "has_cipher_text":         has_cipher_text,
        }


def _entropy(text: str) -> float:
    """Shannon entropy of a string — high entropy suggests encoded/obfuscated content."""
    import math
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    total = len(text)
    return -sum((f / total) * math.log2(f / total) for f in freq.values())


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

        # NEW: fictional/hypothetical framing detection
        fictional_framing = [
            r"(let.s|let us)\s+play\s+a\s+(game|scenario|roleplay)",
            r"(imagine|pretend|suppose|assume)\s+(you\s+are|you.re|there\s+are\s+no)",
            r"(write|tell|describe)\s+(a\s+)?(story|scenario|fiction|tale)\s+(where|in\s+which)",
            r"for\s+(this|the)\s+(game|roleplay|story|scenario|conversation)",
            r"stay\s+in\s+character",
            r"(never|don.t)\s+(break|leave)\s+(character|the\s+roleplay|the\s+scenario)",
            r"(no\s+matter\s+what|regardless)",
        ]
        fic_count = sum(1 for pat in fictional_framing if re.search(pat, p))
        if fic_count >= 1:
            score += min(35, fic_count * 20)
            signals.append({"type": "fictional_framing", "count": fic_count})

        # NEW: restriction negation phrases
        restriction_negation = [
            r"(without|no|zero|void|remove|lift|drop)\s+(any\s+)?(restriction|constraint|filter|limit|guideline|rule)s?",
            r"(safety|content|ethical)\s+(filter|check|policy|guideline)s?\s+(are\s+)?(off|disabled|removed|suspended|void)",
            r"(you\s+)?(can|may|must|should|will)\s+(now\s+)?(answer|respond|say|tell|do)\s+(anything|everything)",
            r"(nothing\s+is\s+off.limits|anything\s+goes|no\s+limits)",
        ]
        neg_count = sum(1 for pat in restriction_negation if re.search(pat, p))
        if neg_count >= 1:
            score += min(40, neg_count * 25)
            signals.append({"type": "restriction_negation", "count": neg_count})

        # NEW: persona assignment (direct name assignment)
        persona_patterns = [
            r"(your\s+name\s+is|you\s+are\s+called|call\s+yourself|respond\s+as)\s+\w+",
            r"(start|begin|prefix)\s+(your|all)\s+(response|answer|reply|message)s?\s+with\s+[\"'\w]+\s*:",
            r"as\s+\w+[,\s]+(you|respond|answer|tell|say)",
        ]
        per_count = sum(1 for pat in persona_patterns if re.search(pat, p))
        if per_count >= 1:
            score += min(30, per_count * 20)
            signals.append({"type": "persona_assignment", "count": per_count})

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

        # Hard override: lowered from 45 to 35 — any solid rule hit flags it
        if rule_score >= 35:
            ensemble_score = max(ensemble_score, rule_score * 0.85)

        # Second override: strong semantic signal alone can flag
        if sem_score >= 55:
            ensemble_score = max(ensemble_score, sem_score * 0.75)

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