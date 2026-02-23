"""
Corvus Mirage — Gateway
Prompt Sanitizer

Strips malicious instruction patterns and redacts PII from prompts.
Used when policy action is SANITIZE rather than BLOCK.
"""
import re
import logging
from typing import List, Tuple


logger = logging.getLogger("gateway.sanitizer")


class PromptSanitizer:
    """
    Sanitizes prompts by neutralizing injection patterns and redacting PII.
    Returns the cleaned prompt and a list of changes made.
    """

    def __init__(self):
        # Malicious instruction patterns → replacement tokens
        self.instruction_patterns = [
            (r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", "[INSTRUCTION_REMOVED]"),
            (r"disregard\s+(all\s+)?(previous|prior|above)",              "[INSTRUCTION_REMOVED]"),
            (r"forget\s+(everything|all|what)",                           "[INSTRUCTION_REMOVED]"),
            (r"new\s+instructions?:",                                      "[INSTRUCTION_REMOVED]"),
            (r"system\s+prompt:",                                          "[SYSTEM_REMOVED]"),
            (r"you\s+are\s+now\s+",                                       "[ROLE_REMOVED] "),
            (r"roleplay\s+as",                                             "[ROLEPLAY_REMOVED]"),
            (r"pretend\s+(you\s+are|to\s+be)",                            "[PRETEND_REMOVED]"),
            (r"DAN\s+mode",                                                "[MODE_REMOVED]"),
            (r"developer\s+mode",                                          "[MODE_REMOVED]"),
            (r"jailbreak",                                                 "[JAILBREAK_REMOVED]"),
            (r"content\s+policy\s+override",                              "[OVERRIDE_REMOVED]"),
        ]

        # PII patterns → redaction tokens
        self.pii_patterns = [
            (r"\b\d{3}-\d{2}-\d{4}\b",                                             "[SSN_REDACTED]"),
            (r"\b\d{9}\b",                                                           "[SSN_REDACTED]"),
            (r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",                       "[CARD_REDACTED]"),
            (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",             "[EMAIL_REDACTED]"),
            (r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",                                     "[PHONE_REDACTED]"),
            (r"\(\d{3}\)\s*\d{3}[-.]?\d{4}",                                        "[PHONE_REDACTED]"),
            (r"sk-[a-zA-Z0-9]{32,}",                                                "[API_KEY_REDACTED]"),
            (r"Bearer\s+[a-zA-Z0-9\-._~+/]{20,}",                                  "[TOKEN_REDACTED]"),
        ]

        # SQL injection patterns
        self.sql_patterns = [
            (r"';?\s*(DROP|DELETE|INSERT|UPDATE|SELECT)\s+", "[SQL_REMOVED] "),
            (r"(OR|AND)\s+1\s*=\s*1",                       "[SQL_REMOVED]"),
            (r"--\s*$",                                       ""),
            (r";\s*--",                                       ""),
        ]

    def sanitize(
        self,
        prompt: str,
        remove_pii: bool = True,
        remove_sql: bool = True,
    ) -> Tuple[str, List[str]]:
        """
        Sanitize a prompt.

        Args:
            prompt:     Original prompt text
            remove_pii: Redact PII (default True)
            remove_sql: Strip SQL injection patterns (default True)

        Returns:
            (sanitized_prompt, list_of_changes)
        """
        sanitized = prompt
        changes: List[str] = []

        # Strip malicious instructions
        for pattern, replacement in self.instruction_patterns:
            if re.search(pattern, sanitized, re.IGNORECASE):
                sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)
                changes.append(f"Removed malicious instruction pattern: {pattern[:40]}")

        # Redact PII
        if remove_pii:
            for pattern, replacement in self.pii_patterns:
                if re.search(pattern, sanitized):
                    sanitized = re.sub(pattern, replacement, sanitized)
                    changes.append(f"Redacted PII ({replacement})")

        # Strip SQL injection
        if remove_sql:
            for pattern, replacement in self.sql_patterns:
                if re.search(pattern, sanitized, re.IGNORECASE):
                    sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)
                    changes.append(f"Removed SQL injection pattern")

        # Clean up whitespace artifacts
        sanitized = re.sub(r'\s+', ' ', sanitized).strip()

        if changes:
            logger.debug(f"Sanitized prompt: {len(changes)} change(s) made")

        return sanitized, changes

    def contains_pii(self, prompt: str) -> bool:
        return any(re.search(p, prompt) for p, _ in self.pii_patterns)

    def get_pii_types(self, prompt: str) -> List[str]:
        found = []
        checks = [
            (r"\b\d{3}-\d{2}-\d{4}\b",                                  "SSN"),
            (r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",           "Credit Card"),
            (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  "Email"),
            (r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",                          "Phone"),
            (r"sk-[a-zA-Z0-9]{32,}",                                     "API Key"),
            (r"Bearer\s+[a-zA-Z0-9\-._~+/]{20,}",                       "Bearer Token"),
        ]
        for pattern, label in checks:
            if re.search(pattern, prompt):
                found.append(label)
        return found


# Singleton
_sanitizer: PromptSanitizer = None

def get_sanitizer() -> PromptSanitizer:
    global _sanitizer
    if _sanitizer is None:
        _sanitizer = PromptSanitizer()
    return _sanitizer
