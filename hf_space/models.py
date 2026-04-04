from __future__ import annotations

import os
from typing import Literal

from pydantic import BaseModel, Field


ThreatLevel = Literal["SAFE", "WARNING", "CRITICAL"]
ActionType = Literal["ALLOW", "MASK", "BLOCK"]
ProcessingMode = Literal["rules", "hybrid"]


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
    type: str
    value: str
    start: int = Field(..., ge=0)
    end: int = Field(..., ge=0)


class DetectionResult(BaseModel):
    action: ActionType
    risk_score: int = Field(..., ge=0, le=100)
    entities: list[DetectedEntity] = Field(default_factory=list)
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
    detected_entities: list[DetectedEntity] = Field(default_factory=list)
    reasoning: str
    processing_mode: ProcessingMode
    model_name: str | None = None


class HealthResponse(BaseModel):
    status: str
    service: str
