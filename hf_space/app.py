from __future__ import annotations

from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from env import SecurityEnv
from models import Action, ActionType, HealthResponse


class ResetRequest(BaseModel):
    task: str = "simple_pii_detection"


class StepRequest(BaseModel):
    action_type: str


class AnalyzeRequest(BaseModel):
    prompt: str
    task: str = "general"


app = FastAPI(
    title="SENTRYX OpenEnv Security",
    description="OpenEnv benchmark server and local analysis API for LLM data leakage prevention.",
    version="1.2.0",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_env = SecurityEnv()


@app.get("/", response_model=HealthResponse)
def root() -> HealthResponse:
    return HealthResponse(status="online", service="openenv-security")


@app.get("/tasks")
def list_tasks() -> dict:
    return {"tasks": _env.list_tasks()}


@app.get("/validate")
def validate() -> dict:
    tasks = _env.list_tasks()
    checks = {
        "min_3_tasks": len(tasks) >= 3,
        "all_tasks_have_graders": all(bool(task.get("grader")) for task in tasks),
        "reset_endpoint": True,
        "step_endpoint": True,
        "state_endpoint": True,
        "reward_range": [0.0, 1.0],
    }
    return {
        "valid": all(checks.values()),
        "checks": checks,
        "tasks": tasks,
        "env_name": "openenv-security",
        "version": "1.1.0",
    }


@app.post("/reset")
def reset(req: Optional[ResetRequest] = None) -> dict:
    task_name = req.task if req and req.task else "simple_pii_detection"
    try:
        return _env.reset(task=task_name).model_dump(mode="json")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/step")
def step(req: StepRequest) -> dict:
    try:
        action_type = ActionType(req.action_type.upper())
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid action '{req.action_type}'. Must be ALLOW, MASK, or BLOCK.",
        ) from exc

    result = _env.step(Action(action_type=action_type))
    return result.model_dump(mode="json")


@app.get("/state")
def state() -> dict:
    return _env.state().model_dump(mode="json")


@app.post("/analyze")
def analyze(req: AnalyzeRequest) -> dict:
    if not req.prompt or not req.prompt.strip():
        raise HTTPException(status_code=422, detail="prompt cannot be empty")
    return _env.analyze_prompt(req.prompt.strip())


@app.post("/predict")
def predict(req: AnalyzeRequest) -> dict:
    if not req.prompt or not req.prompt.strip():
        raise HTTPException(status_code=422, detail="prompt cannot be empty")
    return _env.analyze_prompt(req.prompt.strip())
