"""
Security detectors for the OpenEnv Security Environment.
Ported from TypeScript: regex detection, keyword analysis, heuristic scoring.
"""

from __future__ import annotations

import re
from typing import Dict, List, Tuple

from models import DetectedEntity, EntityType


# ── Regex Detector ─────────────────────────────────────────────────────

class RegexDetector:
    """Detects sensitive entities using regex patterns."""

    PATTERNS: Dict[EntityType, re.Pattern] = {
        EntityType.EMAIL: re.compile(
            r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
        ),
        EntityType.PHONE: re.compile(
            r"\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b"
        ),
        EntityType.API_KEY: re.compile(
            r"(?:api[_\-]?key|apikey|api_token|access_token)[=:\s]+['\"]?"
            r"([A-Za-z0-9_\-]{20,})['\"]?",
            re.IGNORECASE,
        ),
        EntityType.CREDIT_CARD: re.compile(
            r"\b(?:\d{4}[-\s]?){3}\d{4}\b"
        ),
        EntityType.PASSWORD: re.compile(
            r"(?:password|passwd|pwd)[=:\s]+['\"]?([^'\"\s;]+)['\"]?",
            re.IGNORECASE,
        ),
        EntityType.SECRET: re.compile(
            r"(?:secret|api_secret|client_secret)[=:\s]+['\"]?"
            r"([A-Za-z0-9_\-]{20,})['\"]?",
            re.IGNORECASE,
        ),
        EntityType.TOKEN: re.compile(
            r"(?:token|auth_token|bearer)[=:\s]+['\"]?"
            r"([A-Za-z0-9_\-]{20,})['\"]?",
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
                    )
                )
        return entities


# ── Keyword Analyzer ───────────────────────────────────────────────────

class KeywordAnalyzer:
    """Detects sensitive keywords and computes keyword risk score."""

    SENSITIVE_KEYWORDS: Dict[str, float] = {
        "password": 30.0,
        "secret": 35.0,
        "credentials": 40.0,
        "token": 25.0,
        "apikey": 35.0,
        "private": 20.0,
        "confidential": 25.0,
        "ssn": 50.0,
        "credit card": 45.0,
        "social security": 50.0,
        "encrypt": 15.0,
        "decrypt": 20.0,
        "private_key": 60.0,
        "access_token": 50.0,
        "bearer": 40.0,
    }

    def analyze(self, text: str) -> List[Tuple[str, float]]:
        lower = text.lower()
        return [
            (kw, score)
            for kw, score in self.SENSITIVE_KEYWORDS.items()
            if kw in lower
        ]

    def total_score(self, text: str) -> float:
        return sum(score for _, score in self.analyze(text))


# ── Heuristic Risk Scorer ─────────────────────────────────────────────

class HeuristicRiskScorer:
    """Computes heuristic risk scores from detected entities."""

    ENTITY_SCORES: Dict[EntityType, float] = {
        EntityType.EMAIL: 20.0,
        EntityType.PHONE: 25.0,
        EntityType.API_KEY: 50.0,
        EntityType.CREDIT_CARD: 60.0,
        EntityType.PASSWORD: 70.0,
        EntityType.SECRET: 65.0,
        EntityType.TOKEN: 55.0,
    }

    def score_entities(self, entities: List[DetectedEntity]) -> float:
        if not entities:
            return 0.0

        base_score = sum(
            self.ENTITY_SCORES.get(e.type, 0.0) for e in entities
        )
        unique_types = {e.type for e in entities}
        diversity_penalty = (len(unique_types) ** 1.2) * 5.0

        return min(base_score + diversity_penalty, 100.0)

    def context_boost(
        self,
        current: List[DetectedEntity],
        history: List[DetectedEntity],
    ) -> float:
        boost = 0.0
        cur_types = {e.type for e in current}
        hist_types = {e.type for e in history}

        if EntityType.EMAIL in hist_types and EntityType.PASSWORD in cur_types:
            boost += 25.0
        if EntityType.API_KEY in cur_types and EntityType.SECRET in cur_types:
            boost += 20.0
        if history and current:
            boost += 10.0

        return boost
