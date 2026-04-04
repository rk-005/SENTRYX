from __future__ import annotations

import os
from enum import Enum
from typing import List, Literal, Optional

from pydantic import BaseModel, Field


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


class Settings(BaseModel):
    api_base_url: str = "https://router.huggingface.co/v1"
    model_name: str = "Qwen/Qwen2.5-72B-Instruct"
    hf_token: str | None = None

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            api_base_url=os.getenv("API_BASE_URL", "https://router.huggingface.co/v1"),
            model_name=os.getenv("MODEL_NAME", "Qwen/Qwen2.5-72B-Instruct"),
            hf_token=os.getenv("HF_TOKEN"),
        )


class PredictionRequest(BaseModel):
    prompt: str = Field(..., min_length=1, description="Prompt text to classify.")


class DetectedEntity(BaseModel):
    type: EntityType
    value: str
    confidence: float = Field(default=0.95, ge=0.0, le=1.0)
    position: int = Field(default=0, ge=0)
    start: int = Field(default=0, ge=0)
    end: int = Field(default=0, ge=0)


class DetectionResult(BaseModel):
    action: ActionType
    risk_score: int = Field(..., ge=0, le=100)
    entities: List[DetectedEntity] = Field(default_factory=list)
    reasoning: str


class LLMReview(BaseModel):
    action: ActionType
    risk_score: int = Field(..., ge=0, le=100)
    reasoning: str


class PredictionResponse(BaseModel):
    prompt: str
    action: ActionType
    risk_score: int = Field(..., ge=0, le=100)
    threat_level: ThreatLevel
    detected_entities: List[DetectedEntity] = Field(default_factory=list)
    reasoning: str
    processing_mode: Literal["rules", "hybrid"]
    model_name: str | None = None


class HealthResponse(BaseModel):
    status: str
    service: str


class HistoryEntry(BaseModel):
    prompt: str
    action: ActionType
    risk_score: float = Field(ge=0.0, le=100.0)
    detected_entities: List[DetectedEntity] = Field(default_factory=list)


class Action(BaseModel):
    action_type: ActionType = Field(description="The security decision: ALLOW, MASK, or BLOCK")


class Observation(BaseModel):
    prompt: str = Field(description="The current prompt to analyze for security threats")
    risk_score: float = Field(ge=0.0, le=100.0, default=0.0)
    threat_level: ThreatLevel = Field(default=ThreatLevel.SAFE)
    sensitivity: Sensitivity = Field(default=Sensitivity.LOW)
    detected_entities: List[DetectedEntity] = Field(default_factory=list)
    attack_type: AttackType = Field(default=AttackType.NORMAL)
    reason: str = Field(default="")
    step_number: int = Field(default=0, ge=0)
    total_steps: int = Field(default=0, ge=0)
    history_summary: List[str] = Field(default_factory=list)


class Reward(BaseModel):
    value: float = Field(ge=0.0, le=1.0)
    correct_action: ActionType
    is_correct: bool
    explanation: str = Field(default="")


class StepResult(BaseModel):
    observation: Observation
    reward: float = Field(ge=0.0, le=1.0)
    done: bool
    info: dict = Field(default_factory=dict)


class EnvState(BaseModel):
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
