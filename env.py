"""
OpenEnv Security Environment — Main environment class.

Implements the full OpenEnv interface:
  - reset(task?)  → initial Observation
  - step(action)  → (Observation, reward, done, info)
  - state()       → current EnvState
"""

from __future__ import annotations

from typing import List, Optional

from models import (
    Action,
    ActionType,
    AttackType,
    DetectedEntity,
    EnvState,
    HistoryEntry,
    Observation,
    Reward,
    Sensitivity,
    StepResult,
    ThreatLevel,
)
from detectors import HeuristicRiskScorer, KeywordAnalyzer, RegexDetector
from context_analyzer import ContextAnalyzer
from reward_engine import RewardEngine
from tasks import ALL_TASKS, TaskDefinition, TaskGrader


class SecurityEnv:
    """
    OpenEnv-compliant environment for LLM data-leakage prevention.

    The agent analyses prompts for security threats and decides:
      ALLOW  – prompt is safe
      MASK   – redact sensitive data
      BLOCK  – reject the prompt entirely
    """

    def __init__(self) -> None:
        self._regex = RegexDetector()
        self._keywords = KeywordAnalyzer()
        self._heuristic = HeuristicRiskScorer()
        self._context = ContextAnalyzer()
        self._reward_engine = RewardEngine()

        # Internal state
        self._task: Optional[TaskDefinition] = None
        self._grader: Optional[TaskGrader] = None
        self._step_idx: int = 0
        self._done: bool = True
        self._history: List[HistoryEntry] = []
        self._actions_taken: List[ActionType] = []
        self._cumulative_reward: float = 0.0
        self._last_action: Optional[ActionType] = None
        self._last_reward: Optional[float] = None
        self._last_action_error: Optional[str] = None
        self._current_prompt: str = ""
        self._current_risk: float = 0.0
        self._current_entities: List[DetectedEntity] = []
        self._current_attack: AttackType = AttackType.NORMAL
        self._current_reason: str = ""

    # ── OpenEnv API ────────────────────────────────────────────────────

    def reset(self, task: str = "simple_pii_detection") -> Observation:
        """Reset environment and start a new episode for the given task."""
        if task not in ALL_TASKS:
            available = ", ".join(ALL_TASKS.keys())
            raise ValueError(
                f"Unknown task '{task}'. Available: {available}"
            )

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

        # Analyse the first prompt
        return self._observe_current()

    def step(self, action: Action) -> StepResult:
        """Execute one step: agent provides its action for the current prompt."""
        if self._done or self._task is None:
            return StepResult(
                observation=self._make_done_obs(),
                reward=0.0,
                done=True,
                info={"error": "Episode is done. Call reset() first."},
            )

        action_type = action.action_type
        self._last_action_error = None

        # Validate action
        if action_type not in ActionType:
            self._last_action_error = f"Invalid action: {action_type}"
            return StepResult(
                observation=self._observe_current(),
                reward=-1.0,
                done=False,
                info={"error": self._last_action_error},
            )

        # Calculate reward for this action
        reward, is_correct, explanation = self._reward_engine.calculate(
            action_type, self._current_risk
        )

        # Record
        self._actions_taken.append(action_type)
        self._last_action = action_type
        self._last_reward = reward
        self._cumulative_reward += reward

        self._history.append(
            HistoryEntry(
                prompt=self._current_prompt,
                action=action_type,
                risk_score=self._current_risk,
                detected_entities=self._current_entities,
            )
        )

        # Advance to next scenario
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
                    "correct_action": RewardEngine.optimal_action(self._current_risk).value,
                },
            )

        # Observe next prompt
        next_obs = self._observe_current()
        return StepResult(
            observation=next_obs,
            reward=reward,
            done=False,
            info={
                "reward_explanation": explanation,
                "is_correct": is_correct,
                "correct_action": RewardEngine.optimal_action(self._current_risk).value,
            },
        )

    def state(self) -> EnvState:
        """Return the full current state of the environment."""
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

    # ── Available tasks ────────────────────────────────────────────────

    @staticmethod
    def list_tasks() -> list[dict]:
        return [
            {
                "name": t.name,
                "difficulty": t.difficulty,
                "description": t.description,
                "num_scenarios": len(t.scenarios),
            }
            for t in ALL_TASKS.values()
        ]

    # ── Internal helpers ───────────────────────────────────────────────

    def _observe_current(self) -> Observation:
        """Analyse the current scenario prompt and return an Observation."""
        scenario = self._task.scenarios[self._step_idx]
        prompt = scenario.prompt
        self._current_prompt = prompt

        # 1. Regex detection
        entities = self._regex.detect(prompt)

        # 2. Keyword scoring
        kw_score = self._keywords.total_score(prompt)

        # 3. Heuristic scoring
        heuristic_score = self._heuristic.score_entities(entities)

        # 4. Context boost from history
        history_entities = [
            e for entry in self._history for e in entry.detected_entities
        ]
        ctx_boost = self._heuristic.context_boost(entities, history_entities)

        # 5. Attack detection
        attack_type = self._context.detect_attack_type(prompt, self._history)

        # 6. Combined risk
        risk = min(100.0, heuristic_score + kw_score + ctx_boost)
        self._current_risk = risk
        self._current_entities = entities
        self._current_attack = attack_type

        # 7. Threat / sensitivity
        threat = RewardEngine.threat_level_from_score(risk)
        sensitivity = self._classify_sensitivity(risk)

        # 8. Reason
        reason = self._context.generate_reason(
            entities, attack_type,
            RewardEngine.optimal_action(risk).value,
        )
        self._current_reason = reason

        # 9. History summary (last 3)
        hist_summary = [
            f"[{h.action.value}] risk={h.risk_score:.0f}: {h.prompt[:60]}"
            for h in self._history[-3:]
        ]

        return Observation(
            prompt=prompt,
            risk_score=round(risk, 2),
            threat_level=threat,
            sensitivity=sensitivity,
            detected_entities=entities,
            attack_type=attack_type,
            reason=reason,
            step_number=self._step_idx + 1,
            total_steps=len(self._task.scenarios),
            history_summary=hist_summary,
        )

    def _make_done_obs(self) -> Observation:
        return Observation(
            prompt="[EPISODE COMPLETE]",
            risk_score=0.0,
            threat_level=ThreatLevel.SAFE,
            sensitivity=Sensitivity.LOW,
            detected_entities=[],
            attack_type=AttackType.NORMAL,
            reason="Episode finished",
            step_number=self._step_idx,
            total_steps=len(self._task.scenarios) if self._task else 0,
            history_summary=[],
        )

    @staticmethod
    def _classify_sensitivity(risk: float) -> Sensitivity:
        if risk < 40:
            return Sensitivity.LOW
        if risk < 70:
            return Sensitivity.MEDIUM
        return Sensitivity.HIGH
