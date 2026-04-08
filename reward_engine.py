"""Reward engine for the OpenEnv Security benchmark."""

from __future__ import annotations

from models import ActionType, ThreatLevel


class RewardEngine:
    """Calculates rewards on a 0.0 to 1.0 scale."""

    EXACT_REWARD = {
        ActionType.ALLOW: 0.50,
        ActionType.MASK: 0.70,
        ActionType.BLOCK: 1.00,
    }

    PARTIAL_REWARD = {
        (ActionType.MASK, ActionType.ALLOW): 0.20,
        (ActionType.MASK, ActionType.BLOCK): 0.30,
        (ActionType.ALLOW, ActionType.MASK): 0.10,
        (ActionType.BLOCK, ActionType.MASK): 0.20,
    }

    @staticmethod
    def threat_level_from_score(risk_score: float) -> ThreatLevel:
        if risk_score < 35.0:
            return ThreatLevel.SAFE
        if risk_score < 70.0:
            return ThreatLevel.WARNING
        return ThreatLevel.CRITICAL

    @staticmethod
    def optimal_action(risk_score: float) -> ActionType:
        if risk_score < 35.0:
            return ActionType.ALLOW
        if risk_score < 70.0:
            return ActionType.MASK
        return ActionType.BLOCK

    @classmethod
    def reward_for_expected(cls, expected_action: ActionType) -> float:
        return cls.EXACT_REWARD[expected_action]

    @staticmethod
    def threat_for_action(action: ActionType) -> ThreatLevel:
        if action == ActionType.ALLOW:
            return ThreatLevel.SAFE
        if action == ActionType.MASK:
            return ThreatLevel.WARNING
        return ThreatLevel.CRITICAL

    @classmethod
    def calculate(
        cls,
        action: ActionType,
        risk_score: float,
    ) -> tuple[float, bool, str]:
        expected_action = cls.optimal_action(risk_score)
        return cls.calculate_for_expected(action, expected_action)

    @classmethod
    def calculate_for_expected(
        cls,
        action: ActionType,
        expected_action: ActionType,
    ) -> tuple[float, bool, str]:
        if action == expected_action:
            reward = cls.reward_for_expected(expected_action)
            return reward, True, f"Correct: expected {expected_action.value} and received {action.value}"

        partial = cls.PARTIAL_REWARD.get((action, expected_action), 0.0)
        if partial > 0.0:
            return (
                partial,
                False,
                f"Partial credit: expected {expected_action.value} but received adjacent action {action.value}",
            )

        return 0.0, False, f"Incorrect: expected {expected_action.value} but received {action.value}"
