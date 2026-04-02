"""
FastAPI HTTP server for the OpenEnv Security Environment.
Exposes /reset, /step, /state endpoints as required by the OpenEnv spec.
"""

from __future__ import annotations

from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from env import SecurityEnv
from models import Action, ActionType

app = FastAPI(
    title="OpenEnv Security — LLM Data Leakage Prevention",
    description=(
        "An OpenEnv environment for training AI agents to detect and prevent "
        "sensitive data leakage in LLM systems."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global environment instance
_env = SecurityEnv()


# ── Request / Response schemas ─────────────────────────────────────────

class ResetRequest(BaseModel):
    task: str = "simple_pii_detection"


class StepRequest(BaseModel):
    action_type: str  # "ALLOW", "MASK", or "BLOCK"


# ── Health check ───────────────────────────────────────────────────────

@app.get("/")
def root():
    return {
        "environment": "openenv-security",
        "description": "LLM Data Leakage Prevention Environment",
        "version": "1.0.0",
        "endpoints": ["/reset", "/step", "/state", "/tasks"],
    }


# ── /tasks — list available tasks ──────────────────────────────────────

@app.get("/tasks")
def list_tasks():
    return {"tasks": _env.list_tasks()}


# ── /reset — initialize a new episode ─────────────────────────────────

@app.post("/reset")
def reset(req: Optional[ResetRequest] = None):
    task_name = req.task if req and req.task else "simple_pii_detection"
    try:
        obs = _env.reset(task=task_name)
        return obs.model_dump()
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ── /step — take one action ───────────────────────────────────────────

@app.post("/step")
def step(req: StepRequest):
    try:
        action_type = ActionType(req.action_type.upper())
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid action '{req.action_type}'. Must be ALLOW, MASK, or BLOCK.",
        )

    action = Action(action_type=action_type)
    result = _env.step(action)
    return result.model_dump()


# ── /state — get current state ────────────────────────────────────────

@app.get("/state")
def get_state():
    return _env.state().model_dump()


# ── Main entry point ──────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=7860)
