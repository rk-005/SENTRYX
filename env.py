"""OpenEnv Security Environment with benchmark tasks and live prompt analysis."""

from __future__ import annotations

import re
from typing import List, Optional

from context_analyzer import ContextAnalyzer
from detectors import RegexDetector
from models import (
    Action,
    ActionType,
    AttackType,
    DetectedEntity,
    EnvState,
    HistoryEntry,
    Observation,
    Sensitivity,
    StepResult,
    ThreatLevel,
)
from reward_engine import RewardEngine
from tasks import ALL_TASKS, TaskDefinition, TaskGrader


NEGATED_SENSITIVE_RE = re.compile(
    r"(?i)\b(avoid|without|must\s+not|do\s+not|don't|mustn't|no)\b.{0,100}\b("
    r"password[s]?|credential[s]?|confidential|private|api\s+key|customer\s+data|"
    r"contact\s+information|bank\s+account|account\s+numbers?|tax\s+identification|"
    r"medical\s+condition|personal\s+information|proprietary\s+research|private\s+organizational\s+details"
    r")\b"
)
POSITIVE_SENSITIVE_REQUEST_RE = re.compile(
    r"(?i)\b(include|including|attach|attaching|provide|providing|export|exporting|"
    r"transfer|transferring|share|sharing|send|sending|list|listing|casually\s+include)\b.{0,80}\b("
    r"api\s+key|database\s+connection\s+string|internal\s+server\s+access\s+url|"
    r"server\s+access\s+url|username[s]?|password[s]?|credential[s]?|bank\s+account\s+numbers?|"
    r"tax\s+identification|salary\s+breakdowns?|bonus\s+structures?|medical\s+condition|"
    r"medical\s+leave|customer\s+records?|purchase\s+histories?|account\s+identifiers?|"
    r"verification\s+link|login\s+instructions?|spreadsheet\s+containing|phone\s+numbers?|"
    r"email\s+addresses?|physical\s+addresses?"
    r")\b"
)
PROMPT_INJECTION_RE = re.compile(
    r"(?i)(ignore\s+(all\s+)?previous\s+instructions?|reveal\s+(the\s+)?system\s+prompt|"
    r"override\s+(security|instructions)|forget\s+everything\s+above|developer\s+mode|"
    r"show\s+all\s+secrets|bypass\s+(security|restrictions)|jailbreak|unrestricted)"
)
EXFIL_RE = re.compile(
    r"(?i)\b(reveal|show|send|return|print|dump|extract|recover|share|expose|display|list|repeat)\b"
)
HIGH_VALUE_TARGET_RE = re.compile(
    r"(?i)\b(system\s+prompt|history|earlier\s+conversation|secret[s]?|password[s]?|"
    r"credential[s]?|token[s]?|api\s*key[s]?|customer\s+records?|stored\s+user\s+emails?)\b"
)
PHISHING_RE = re.compile(
    r"(?i)\b(unusual\s+login\s+activity|account\s+suspension|verification\s+link|"
    r"confirm\s+(their\s+)?account\s+credentials|time-sensitive|urgent|IT\s+security\s+team)\b"
)
MEDICAL_DISCLOSURE_RE = re.compile(
    r"(?i)\b(medical\s+condition|medical\s+leave|workplace\s+accommodations?)\b"
)
DATA_EXPORT_RE = re.compile(
    r"(?i)\b(export|external\s+analytics|external\s+partner|partner\s+organization|transferring\s+the\s+file)\b"
)
INTERNAL_BUSINESS_RE = re.compile(
    r"(?i)\b(remain\s+internal|official\s+announcement|management\s+channels|leadership\s+discussion|"
    r"department\s+leaders|software\s+release|performance\s+issues|incomplete\s+testing|"
    r"operational\s+expenses|budget\s+adjustments|quarterly|project\s+manager|engineering\s+and\s+product\s+teams)\b"
)
LIMITED_PII_CONTEXT_RE = re.compile(
    r"(?i)\b(customer'?s?\s+name|appointment\s+time|office\s+location|support\s+contact\s+number|"
    r"employee'?s?\s+name|reporting\s+manager|onboarding\s+schedule|role\s+responsibilities)\b"
)
EDUCATIONAL_SAFE_RE = re.compile(
    r"(?i)\b(explain|beginner-friendly|high-school students|educational|renewable energy|"
    r"workplace reminder|team-building event|office etiquette|safety practices)\b"
)
CREDENTIAL_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|token|bearer|api[_\- ]?key|secret)\b\s*(is|was|=|:)\s*\S+"
)
DATABASE_CONNECTION_RE = re.compile(r"(?i)\bdatabase\s+connection\s+string\b")
INTERNAL_SERVER_URL_RE = re.compile(r"(?i)\binternal\s+server\s+access\s+url\b")
PAYLOAD_EXPORT_DETAILS_RE = re.compile(
    r"(?i)\b(customer\s+names?|email\s+addresses?|phone\s+numbers?|physical\s+addresses?|"
    r"purchase\s+histories?|account\s+identifiers?|bank\s+account\s+numbers?|tax\s+identification)\b"
)
EMAIL_RESET_RE = re.compile(r"(?i)\b(password\s+reset|reset\s+link|credentials?)\b")
EARLIER_SECRET_RE = re.compile(r"(?i)\b(earlier|previous|mentioned\s+earlier|repeat\s+it|repeat\s+them)\b")


class SecurityEnv:
    """OpenEnv-compliant security benchmark environment."""

    def __init__(self) -> None:
        self._regex = RegexDetector()
        self._context = ContextAnalyzer()
        self._reward_engine = RewardEngine()

        self._task: Optional[TaskDefinition] = None
        self._grader: Optional[TaskGrader] = None
        self._step_idx = 0
        self._done = True
        self._history: List[HistoryEntry] = []
        self._actions_taken: List[ActionType] = []
        self._cumulative_reward = 0.0
        self._last_action: Optional[ActionType] = None
        self._last_reward: Optional[float] = None
        self._last_action_error: Optional[str] = None
        self._current_prompt = ""
        self._current_risk = 0.0
        self._current_entities: List[DetectedEntity] = []
        self._current_attack = AttackType.NORMAL
        self._current_reason = ""

    def analyze_prompt(self, prompt: str) -> dict:
        analyzed = self._analyze_text(prompt, history=[])
        recommended_action = analyzed["action"]
        return {
            "prompt": prompt,
            "risk_score": analyzed["risk_score"],
            "threat_level": analyzed["threat_level"].value,
            "sensitivity": analyzed["sensitivity"].value,
            "attack_type": analyzed["attack_type"].value,
            "detected_entities": [entity.type.value for entity in analyzed["entities"]],
            "action": recommended_action.value,
            "reason": analyzed["reason"],
            "reward": self._reward_engine.reward_for_expected(recommended_action),
        }

    def reset(self, task: str = "simple_pii_detection") -> Observation:
        if task not in ALL_TASKS:
            available = ", ".join(ALL_TASKS.keys())
            raise ValueError(f"Unknown task '{task}'. Available: {available}")

        self._task = ALL_TASKS[task]
        self._grader = TaskGrader(self._task)
        self._step_idx = 0
        self._done = False
        self._history = []
        self._actions_taken = []
        self._cumulative_reward = 0.0
        self._last_action = None
        self._last_reward = None
        self._last_action_error = None

        return self._observe_current()

    def step(self, action: Action) -> StepResult:
        if self._done or self._task is None:
            return StepResult(
                observation=self._make_done_obs(),
                reward=0.0,
                done=True,
                info={"error": "Episode is done. Call reset() first."},
            )

        scenario = self._task.scenarios[self._step_idx]
        reward, is_correct, explanation = self._reward_engine.calculate_for_expected(
            action.action_type,
            scenario.expected_action,
        )

        self._actions_taken.append(action.action_type)
        self._last_action = action.action_type
        self._last_reward = reward
        self._cumulative_reward += reward
        self._history.append(
            HistoryEntry(
                prompt=self._current_prompt,
                action=action.action_type,
                risk_score=self._current_risk,
                detected_entities=list(self._current_entities),
            )
        )

        self._step_idx += 1
        if self._step_idx >= len(self._task.scenarios):
            self._done = True
            final_score = self._grader.grade(self._actions_taken) if self._grader else 0.0
            return StepResult(
                observation=self._make_done_obs(),
                reward=reward,
                done=True,
                info={
                    "final_score": final_score,
                    "reward_explanation": explanation,
                    "is_correct": is_correct,
                    "correct_action": scenario.expected_action.value,
                },
            )

        return StepResult(
            observation=self._observe_current(),
            reward=reward,
            done=False,
            info={
                "reward_explanation": explanation,
                "is_correct": is_correct,
                "correct_action": scenario.expected_action.value,
            },
        )

    def state(self) -> EnvState:
        return EnvState(
            current_task=self._task.name if self._task else None,
            step_number=self._step_idx,
            total_steps=len(self._task.scenarios) if self._task else 0,
            done=self._done,
            cumulative_reward=round(self._cumulative_reward, 4),
            history=list(self._history),
            current_prompt=self._current_prompt,
            last_action=self._last_action,
            last_reward=self._last_reward,
            last_action_error=self._last_action_error,
        )

    @staticmethod
    def list_tasks() -> list[dict]:
        return [
            {
                "name": task.name,
                "difficulty": task.difficulty,
                "description": task.description,
                "num_scenarios": len(task.scenarios),
            }
            for task in ALL_TASKS.values()
        ]

    def _observe_current(self) -> Observation:
        scenario = self._task.scenarios[self._step_idx]
        analyzed = self._analyze_text(scenario.prompt, history=self._history)

        self._current_prompt = scenario.prompt
        self._current_entities = analyzed["entities"]
        self._current_risk = analyzed["risk_score"]
        self._current_attack = analyzed["attack_type"]
        self._current_reason = analyzed["reason"]

        return Observation(
            prompt=scenario.prompt,
            risk_score=analyzed["risk_score"],
            threat_level=analyzed["threat_level"],
            sensitivity=analyzed["sensitivity"],
            detected_entities=analyzed["entities"],
            attack_type=analyzed["attack_type"],
            reason=analyzed["reason"],
            step_number=self._step_idx + 1,
            total_steps=len(self._task.scenarios),
            history_summary=self._history_summary(),
        )

    def _analyze_text(self, prompt: str, history: List[HistoryEntry]) -> dict:
        entities = self._regex.detect(prompt)
        entity_types = {entity.type.value for entity in entities}
        history_entity_names = {
            entity.type.name
            for entry in history
            for entity in entry.detected_entities
        }
        attack_type = self._context.detect_attack_type(prompt, history)

        risk = 0
        if "EMAIL" in entity_types:
            risk = max(risk, 45)
        if "PHONE" in entity_types:
            risk = max(risk, 45)
        if "CREDIT_CARD" in entity_types:
            risk = max(risk, 60)
        if "PASSWORD" in entity_types:
            risk = max(risk, 55)
        if "TOKEN" in entity_types:
            risk = max(risk, 72)
        if "SECRET" in entity_types:
            risk = max(risk, 72)
        if "API_KEY" in entity_types:
            risk = max(risk, 85)

        if PROMPT_INJECTION_RE.search(prompt) or attack_type == AttackType.PROMPT_INJECTION:
            risk = max(risk, 82)

        if EXFIL_RE.search(prompt) and HIGH_VALUE_TARGET_RE.search(prompt):
            risk = max(risk, 78)

        if POSITIVE_SENSITIVE_REQUEST_RE.search(prompt):
            risk = max(risk, 85)
            if DATABASE_CONNECTION_RE.search(prompt) or INTERNAL_SERVER_URL_RE.search(prompt):
                attack_type = AttackType.API_KEY_LEAK
            else:
                attack_type = AttackType.CREDENTIAL_EXFILTRATION

        if PHISHING_RE.search(prompt):
            risk = max(risk, 90)

        if MEDICAL_DISCLOSURE_RE.search(prompt):
            risk = max(risk, 82)

        if DATA_EXPORT_RE.search(prompt) and PAYLOAD_EXPORT_DETAILS_RE.search(prompt):
            risk = max(risk, 88)

        if LIMITED_PII_CONTEXT_RE.search(prompt):
            risk = max(risk, 45)

        if INTERNAL_BUSINESS_RE.search(prompt):
            risk = max(risk, 42)

        if DATABASE_CONNECTION_RE.search(prompt) and INTERNAL_SERVER_URL_RE.search(prompt):
            risk = max(risk, 85)

        if CREDENTIAL_ASSIGNMENT_RE.search(prompt) and EXFIL_RE.search(prompt):
            risk = max(risk, 80)
        elif CREDENTIAL_ASSIGNMENT_RE.search(prompt):
            risk = max(risk, 55)

        if history_entity_names and "EMAIL" in history_entity_names and EMAIL_RESET_RE.search(prompt):
            risk = max(risk, 80)
            attack_type = AttackType.CREDENTIAL_EXFILTRATION

        if history_entity_names & {"API_KEY", "TOKEN", "SECRET"} and EARLIER_SECRET_RE.search(prompt):
            risk = max(risk, 85)
            attack_type = AttackType.CREDENTIAL_EXFILTRATION

        if attack_type == AttackType.API_KEY_LEAK:
            risk = max(risk, 85)
        elif attack_type == AttackType.CREDENTIAL_EXFILTRATION:
            risk = max(risk, 78)

        if NEGATED_SENSITIVE_RE.search(prompt) and risk < 35:
            risk = max(0, risk - 12)

        if not entities and risk == 0 and EDUCATIONAL_SAFE_RE.search(prompt):
            risk = 15

        risk = min(float(risk), 100.0)
        threat_level = self._reward_engine.threat_level_from_score(risk)
        sensitivity = self._classify_sensitivity(risk)
        action = self._reward_engine.optimal_action(risk)
        reason = self._build_reason(
            risk=risk,
            threat_level=threat_level,
            entities=entities,
            attack_type=attack_type,
            prompt=prompt,
        )

        return {
            "risk_score": risk,
            "threat_level": threat_level,
            "sensitivity": sensitivity,
            "entities": entities,
            "attack_type": attack_type,
            "reason": reason,
            "action": action,
        }

    def _build_reason(
        self,
        risk: float,
        threat_level: ThreatLevel,
        entities: List[DetectedEntity],
        attack_type: AttackType,
        prompt: str,
    ) -> str:
        parts: List[str] = []
        if attack_type == AttackType.PROMPT_INJECTION:
            parts.append("Prompt injection detected - attempt to override system instructions.")
        elif attack_type == AttackType.API_KEY_LEAK:
            parts.append("API key or secret-bearing infrastructure request detected.")
        elif attack_type == AttackType.CREDENTIAL_EXFILTRATION:
            parts.append("Credential or sensitive-data exfiltration pattern detected.")

        if entities:
            unique_entities = ", ".join(sorted({entity.type.value for entity in entities}))
            parts.append(f"Sensitive entities found: {unique_entities}.")
        elif POSITIVE_SENSITIVE_REQUEST_RE.search(prompt):
            parts.append("Prompt requests inclusion or transfer of sensitive artifacts.")

        if threat_level == ThreatLevel.CRITICAL:
            parts.append(f"Risk {risk:.0f}/100 -> CRITICAL. Prompt blocked.")
        elif threat_level == ThreatLevel.WARNING:
            parts.append(f"Risk {risk:.0f}/100 -> WARNING. Data masked.")
        else:
            parts.append(f"Risk {risk:.0f}/100 -> SAFE. Prompt allowed.")

        if not entities and attack_type == AttackType.NORMAL and threat_level == ThreatLevel.SAFE:
            parts.append("No sensitive data patterns detected.")

        return " ".join(parts)

    def _history_summary(self) -> List[str]:
        return [
            f"[{entry.action.value}] risk={entry.risk_score:.0f}: {entry.prompt[:60]}"
            for entry in self._history[-3:]
        ]

    def _make_done_obs(self) -> Observation:
        return Observation(
            prompt="[EPISODE COMPLETE]",
            risk_score=0.0,
            threat_level=ThreatLevel.SAFE,
            sensitivity=Sensitivity.LOW,
            detected_entities=[],
            attack_type=AttackType.NORMAL,
            reason="Episode finished.",
            step_number=self._step_idx,
            total_steps=len(self._task.scenarios) if self._task else 0,
            history_summary=[],
        )

    @staticmethod
    def _classify_sensitivity(risk: float) -> Sensitivity:
        if risk < 35.0:
            return Sensitivity.LOW
        if risk < 70.0:
            return Sensitivity.MEDIUM
        return Sensitivity.HIGH


