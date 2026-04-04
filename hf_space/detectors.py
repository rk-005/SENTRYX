from __future__ import annotations

import re

from models import DetectedEntity, DetectionResult, ThreatLevel


EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE_RE = re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b")
PASSWORD_RE = re.compile(r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*([^\s,;]+)")
API_KEY_RE = re.compile(
    r"(?i)\b(?:api[_-]?key|access[_-]?token|secret[_-]?key)\b(?:\s*(?:[:=]|is)\s*)?([A-Za-z0-9_\-.]{8,})"
)
CREDIT_CARD_RE = re.compile(r"\b(?:\d{4}[- ]?){3}\d{4}\b")
CONNECTION_STRING_RE = re.compile(r"(?i)\b(?:postgres|mysql|mongodb)(?:\+srv)?://\S+")

BLOCK_TERM_SCORES = {
    "ignore previous instructions": 70,
    "reveal system prompt": 70,
    "confirm credentials": 70,
    "verification link": 70,
    "bank account numbers": 65,
    "tax identification": 65,
    "medical condition": 65,
    "api key": 50,
    "database connection string": 60,
    "internal server access url": 60,
    "export customer records": 70,
    "purchase histories": 50,
}

MASK_TERMS = {
    "internal only",
    "confidential",
    "employee transfer",
    "appointment time",
    "office location",
    "customer support contact",
    "quarterly operational expenses",
    "salary",
    "bonus structures",
}


class SecurityDetector:
    def analyze(self, prompt: str) -> DetectionResult:
        text = prompt.strip()
        lower = text.lower()

        entities = self._extract_entities(text)
        risk_score = 0
        reasons: list[str] = []

        if entities:
            risk_score += min(20 * len(entities), 60)
            reasons.append("Sensitive entities detected.")

        block_score = max((score for term, score in BLOCK_TERM_SCORES.items() if term in lower), default=0)
        if block_score:
            risk_score += block_score
            reasons.append("High-risk exfiltration or attack intent detected.")
        elif any(term in lower for term in MASK_TERMS):
            risk_score += 35
            reasons.append("Moderate internal or personal data sensitivity detected.")
        else:
            risk_score += 10
            reasons.append("Low baseline content.")

        if CONNECTION_STRING_RE.search(text):
            risk_score += 30
            reasons.append("Connection string detected.")

        if len(text) > 1200:
            risk_score += 5

        risk_score = max(0, min(risk_score, 100))
        action = self._action_from_score(risk_score)

        return DetectionResult(
            action=action,
            risk_score=risk_score,
            entities=entities,
            reasoning=" ".join(reasons),
        )

    def threat_level_from_score(self, risk_score: int) -> ThreatLevel:
        if risk_score >= 70:
            return "CRITICAL"
        if risk_score >= 40:
            return "WARNING"
        return "SAFE"

    def _action_from_score(self, risk_score: int) -> str:
        if risk_score >= 70:
            return "BLOCK"
        if risk_score >= 40:
            return "MASK"
        return "ALLOW"

    def _extract_entities(self, text: str) -> list[DetectedEntity]:
        entities: list[DetectedEntity] = []
        entities.extend(self._scan(text, EMAIL_RE, "EMAIL"))
        entities.extend(self._scan(text, PHONE_RE, "PHONE"))
        entities.extend(self._scan(text, PASSWORD_RE, "PASSWORD"))
        entities.extend(self._scan(text, API_KEY_RE, "API_KEY"))
        entities.extend(self._scan(text, CREDIT_CARD_RE, "CREDIT_CARD"))
        return entities

    def _scan(self, text: str, pattern: re.Pattern[str], entity_type: str) -> list[DetectedEntity]:
        results: list[DetectedEntity] = []
        for match in pattern.finditer(text):
            results.append(
                DetectedEntity(
                    type=entity_type,
                    value=match.group(0),
                    start=match.start(),
                    end=match.end(),
                )
            )
        return results
