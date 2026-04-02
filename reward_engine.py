"""
Reward engine with 0.0–1.0 reward scale.
Provides partial-progress signal, not just binary end-of-episode.
"""

from __future__ import annotations

from models import ActionType, ThreatLevel


class RewardEngine:
    """Calculates reward for agent decisions on a -1.0 to +1.0 scale."""

    # Optimal reward for each (action, threat_level) pair
    REWARD_MAP = {
        (ActionType.BLOCK, ThreatLevel.CRITICAL): 1.0,
        (ActionType.MASK, ThreatLevel.WARNING): 0.7,
        (ActionType.ALLOW, ThreatLevel.SAFE): 0.5,
    }

    @staticmethod
    def threat_level_from_score(risk_score: float) -> ThreatLevel:
        if risk_score < 40.0:
            return ThreatLevel.SAFE
        if risk_score < 70.0:
            return ThreatLevel.WARNING
        return ThreatLevel.CRITICAL

    @staticmethod
    def optimal_action(risk_score: float) -> ActionType:
        if risk_score < 40.0:
            return ActionType.ALLOW
        if risk_score < 70.0:
            return ActionType.MASK
        return ActionType.BLOCK

    def calculate(
        self,
        action: ActionType,
        risk_score: float,
    ) -> tuple[float, bool, str]:
        """
        Returns (reward, is_correct, explanation).
        Reward scale: -1.0 to +1.0.
        """
        threat = self.threat_level_from_score(risk_score)
        correct_action = self.optimal_action(risk_score)
        is_correct = action == correct_action

        if is_correct:
            reward = self.REWARD_MAP.get((action, threat), 0.5)
            explanation = (
                f"Correct: {action.value} at risk {risk_score:.0f} "
                f"(threat={threat.value})"
            )
            return reward, True, explanation

        # ── Partial credit logic ──────────────────────────────────────
        # Over-blocking: safe prompt blocked → moderate penalty
        if action == ActionType.BLOCK and threat == ThreatLevel.SAFE:
            return -0.5, False, "Over-blocking: blocked a safe prompt"

        # Under-blocking: critical prompt allowed → severe penalty
        if action == ActionType.ALLOW and threat == ThreatLevel.CRITICAL:
            return -1.0, False, "Dangerous: allowed a critical-risk prompt"

        # Adjacent tier (one off from optimal) → small penalty
        if (
            (action == ActionType.MASK and threat == ThreatLevel.CRITICAL)
            or (action == ActionType.MASK and threat == ThreatLevel.SAFE)
        ):
            return -0.3, False, f"Suboptimal: {action.value} at {threat.value} risk"

        if action == ActionType.BLOCK and threat == ThreatLevel.WARNING:
            return 0.2, False, "Cautious: blocked a warning-level prompt (acceptable)"

        if action == ActionType.ALLOW and threat == ThreatLevel.WARNING:
            return -0.7, False, "Risky: allowed a warning-level prompt"

        return -0.5, False, f"Wrong: {action.value} at risk {risk_score:.0f}"
