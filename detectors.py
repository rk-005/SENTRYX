from __future__ import annotations

import re
from typing import Dict, List, Literal

from models import DetectedEntity, DetectionResult, EntityType, ThreatLevel


class RegexDetector:
    PATTERNS: Dict[EntityType, re.Pattern] = {
        EntityType.EMAIL: re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
        EntityType.PHONE: re.compile(r"\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b"),
        EntityType.API_KEY: re.compile(
            r"(?:api[_\-]?\s?key|apikey|api_token|access_token)\s*(?:=|:|is)\s*['\"]?([A-Za-z0-9_\-]{8,})['\"]?",
            re.IGNORECASE,
        ),
        EntityType.CREDIT_CARD: re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
        EntityType.PASSWORD: re.compile(
            r"(?:password|passwd|pwd)\s*(?:=|:|is)\s*['\"]?([^'\"\s;]+)['\"]?",
            re.IGNORECASE,
        ),
        EntityType.SECRET: re.compile(
            r"(?:secret|api_secret|client_secret)\s*(?:=|:|is)\s*['\"]?([A-Za-z0-9_\-]{8,})['\"]?",
            re.IGNORECASE,
        ),
        EntityType.TOKEN: re.compile(
            r"(?:token|auth_token|bearer)\s*(?:=|:|is)\s*['\"]?([A-Za-z0-9_\-]{8,})['\"]?",
            re.IGNORECASE,
        ),
    }

    def detect(self, text: str) -> List[DetectedEntity]:
        entities: List[DetectedEntity] = []
        for entity_type, pattern in self.PATTERNS.items():
            for match in pattern.finditer(text):
                entities.append(
                    DetectedEntity(
                        type=entity_type,
                        value=match.group(0),
                        confidence=0.95,
                        position=match.start(),
                        start=match.start(),
                        end=match.end(),
                    )
                )
        return entities


EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE_RE = re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b")
PASSWORD_RE = re.compile(r"(?i)\b(?:password|passwd|pwd)\s*(?::|=|is)\s*([^\s,;]+)")
API_KEY_RE = re.compile(
    r"(?i)\b(?:api[_\s-]*key|access[_-]?token|secret[_-]?key)\b(?:\s*(?:[:=]|is)\s*)?([A-Za-z0-9_\-.]{8,})"
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
    "api key": 70,
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
            high_impact_entities = {EntityType.API_KEY, EntityType.CREDIT_CARD, EntityType.PASSWORD}
            if any(entity.type in high_impact_entities for entity in entities):
                risk_score += 60
            else:
                risk_score += max(35, min(20 * len(entities), 60))
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
            return ThreatLevel.CRITICAL
        if risk_score >= 40:
            return ThreatLevel.WARNING
        return ThreatLevel.SAFE

    def _action_from_score(self, risk_score: int) -> Literal["ALLOW", "MASK", "BLOCK"]:
        if risk_score >= 70:
            return "BLOCK"
        if risk_score >= 40:
            return "MASK"
        return "ALLOW"

    def _extract_entities(self, text: str) -> list[DetectedEntity]:
        entities: list[DetectedEntity] = []
        entities.extend(self._scan(text, EMAIL_RE, EntityType.EMAIL))
        entities.extend(self._scan(text, PHONE_RE, EntityType.PHONE))
        entities.extend(self._scan(text, PASSWORD_RE, EntityType.PASSWORD))
        entities.extend(self._scan(text, API_KEY_RE, EntityType.API_KEY))
        entities.extend(self._scan(text, CREDIT_CARD_RE, EntityType.CREDIT_CARD))
        return entities

    def _scan(self, text: str, pattern: re.Pattern[str], entity_type: EntityType) -> list[DetectedEntity]:
        results: list[DetectedEntity] = []
        for match in pattern.finditer(text):
            results.append(
                DetectedEntity(
                    type=entity_type,
                    value=match.group(0),
                    confidence=0.95,
                    position=match.start(),
                    start=match.start(),
                    end=match.end(),
                )
            )
        return results
