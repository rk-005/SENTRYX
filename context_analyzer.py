"""
Context analyzer for multi-step attack detection.
Ported from TypeScript contextAnalyzer.ts.
"""

from __future__ import annotations

import re
from typing import List

from models import AttackType, DetectedEntity, EntityType, HistoryEntry


class ContextAnalyzer:
    """Analyses prompt history to detect multi-step attack patterns."""

    INJECTION_PATTERNS: List[re.Pattern] = [
        re.compile(r"<!--[\s\S]*?-->"),              # HTML comments
        re.compile(r"/\*[\s\S]*?\*/"),                # C-style comments
        re.compile(r"<script[\s\S]*?</script>", re.I),  # Script tags
        re.compile(r"\{\{[\s\S]*?\}\}"),              # Template injection
        re.compile(r"\$\{[\s\S]*?\}"),                # Template literals
        re.compile(r"ignore\s+previous", re.I),       # Ignore previous
        re.compile(r"system\s*prompt", re.I),         # System prompt ref
        re.compile(r"\b(override|bypass)\b", re.I),   # Override/bypass
    ]

    def detect_attack_type(
        self,
        current_prompt: str,
        history: List[HistoryEntry],
    ) -> AttackType:
        # Check for prompt injection first
        if self._is_prompt_injection(current_prompt):
            return AttackType.PROMPT_INJECTION

        if not history:
            return AttackType.NORMAL

        # Check for credential exfiltration
        has_email_in_history = any(
            any(e.type == EntityType.EMAIL for e in entry.detected_entities)
            for entry in history
        )
        has_password_mention = "password" in current_prompt.lower()

        if has_email_in_history and has_password_mention:
            return AttackType.CREDENTIAL_EXFILTRATION

        # Check for API key leak pattern
        has_api_in_history = any(
            any(e.type == EntityType.API_KEY for e in entry.detected_entities)
            for entry in history
        )
        has_secret_mention = "secret" in current_prompt.lower()

        if has_api_in_history and has_secret_mention:
            return AttackType.API_KEY_LEAK

        # Check current prompt for API-related patterns
        if "api" in current_prompt.lower() and (
            "key" in current_prompt.lower() or "secret" in current_prompt.lower()
        ):
            return AttackType.API_KEY_LEAK

        return AttackType.NORMAL

    def _is_prompt_injection(self, prompt: str) -> bool:
        return any(p.search(prompt) for p in self.INJECTION_PATTERNS)

    def generate_reason(
        self,
        entities: List[DetectedEntity],
        attack_type: AttackType,
        decision: str,
    ) -> str:
        parts: List[str] = []
        if entities:
            types = ", ".join(sorted({e.type.value for e in entities}))
            parts.append(f"Detected: {types}")
        if attack_type != AttackType.NORMAL:
            parts.append(f"Attack: {attack_type.value}")
        parts.append(f"Decision: {decision}")
        return " | ".join(parts) if parts else "No sensitive data detected"
