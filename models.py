"""
Pydantic models for OpenEnv Security Environment.
Typed Observation, Action, and Reward models as required by the OpenEnv spec.
"""

from __future__ import annotations

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field


# ── Enums ──────────────────────────────────────────────────────────────

class ActionType(str, Enum):
    ALLOW = "ALLOW"
    MASK = "MASK"
    BLOCK = "BLOCK"


class ThreatLevel(str, Enum):
    SAFE = "SAFE"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class Sensitivity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class AttackType(str, Enum):
    NORMAL = "NORMAL"
    CREDENTIAL_EXFILTRATION = "CREDENTIAL_EXFILTRATION"
    API_KEY_LEAK = "API_KEY_LEAK"
    PROMPT_INJECTION = "PROMPT_INJECTION"


class EntityType(str, Enum):
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    API_KEY = "API_KEY"
    CREDIT_CARD = "CREDIT_CARD"
    PASSWORD = "PASSWORD"
    SECRET = "SECRET"
    TOKEN = "TOKEN"


# ── Sub-models ─────────────────────────────────────────────────────────

class DetectedEntity(BaseModel):
    """A single sensitive entity detected in a prompt."""
    type: EntityType
    value: str
    confidence: float = Field(ge=0.0, le=1.0)
    position: int = Field(ge=0)


class HistoryEntry(BaseModel):
    """A single step in the episode history."""
    prompt: str
    action: ActionType
    risk_score: float = Field(ge=0.0, le=100.0)
    detected_entities: List[DetectedEntity] = []


# ── Core OpenEnv Models ────────────────────────────────────────────────

class Action(BaseModel):
    """Action the agent takes each step."""
    action_type: ActionType = Field(
        description="The security decision: ALLOW, MASK, or BLOCK"
    )


class Observation(BaseModel):
    """What the agent observes each step."""
    prompt: str = Field(
        description="The current prompt to analyze for security threats"
    )
    risk_score: float = Field(
        ge=0.0, le=100.0, default=0.0,
        description="Computed risk score for the current prompt (0-100)"
    )
    threat_level: ThreatLevel = Field(
        default=ThreatLevel.SAFE,
        description="Current threat classification"
    )
    sensitivity: Sensitivity = Field(
        default=Sensitivity.LOW,
        description="Sensitivity level of detected data"
    )
    detected_entities: List[DetectedEntity] = Field(
        default_factory=list,
        description="List of sensitive entities found in the prompt"
    )
    attack_type: AttackType = Field(
        default=AttackType.NORMAL,
        description="Classified attack pattern if any"
    )
    reason: str = Field(
        default="",
        description="Human-readable explanation of the analysis"
    )
    step_number: int = Field(
        default=0, ge=0,
        description="Current step within the episode"
    )
    total_steps: int = Field(
        default=0, ge=0,
        description="Total steps in this task"
    )
    history_summary: List[str] = Field(
        default_factory=list,
        description="Summary of previous actions for context (last 3)"
    )


class Reward(BaseModel):
    """Reward signal returned after each step."""
    value: float = Field(
        ge=-1.0, le=1.0,
        description="Reward value: +1.0 (perfect) to -1.0 (worst)"
    )
    correct_action: ActionType = Field(
        description="The action that would have been optimal"
    )
    is_correct: bool = Field(
        description="Whether the agent chose the optimal action"
    )
    explanation: str = Field(
        default="",
        description="Why this reward was given"
    )


class StepResult(BaseModel):
    """Full result from a single env.step() call."""
    observation: Observation
    reward: float = Field(ge=-1.0, le=1.0)
    done: bool
    info: dict = Field(default_factory=dict)


class EnvState(BaseModel):
    """Full internal state of the environment."""
    current_task: Optional[str] = None
    step_number: int = 0
    total_steps: int = 0
    done: bool = False
    cumulative_reward: float = 0.0
    history: List[HistoryEntry] = Field(default_factory=list)
    current_prompt: str = ""
    last_action: Optional[ActionType] = None
    last_reward: Optional[float] = None
    last_action_error: Optional[str] = None
