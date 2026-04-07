"""FastAPI application exposing the SOC environment as a REST API.

This module re-exports the app from the root app.py and provides
the start_server entry point expected by OpenEnv.
"""

from __future__ import annotations

import sys
import os
from typing import Any, Dict

import uvicorn
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

# Ensure project root is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from env.environment import SOCEnvironment
from env.models import Action, ActionType
from env.tasks import TaskRegistry

# ---------------------------------------------------------------------------
# App & shared state
# ---------------------------------------------------------------------------

app = FastAPI(
    title="SOC OpenEnv API",
    description="OpenEnv-compatible Security Operations Center training environment",
    version="1.0.0",
)

_env = SOCEnvironment()


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

class ResetRequest(BaseModel):
    task: str = "phishing_detection"


class StepRequest(BaseModel):
    action: str
    parameters: Dict[str, Any] = {}


class StepResponse(BaseModel):
    observation: Dict[str, Any]
    reward: Dict[str, Any]
    done: bool
    info: Dict[str, Any]


class ResetResponse(BaseModel):
    observation: Dict[str, Any]


class StateResponse(BaseModel):
    state: Dict[str, Any]


class TaskListResponse(BaseModel):
    tasks: list


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/", tags=["health"])
def health_check():
    """Health-check endpoint."""
    return {"status": "ok", "service": "soc-openenv"}


@app.get("/tasks", response_model=TaskListResponse, tags=["environment"])
def list_tasks():
    """List available tasks."""
    defs = TaskRegistry.list_definitions()
    return TaskListResponse(
        tasks=[
            {
                "name": d.name,
                "difficulty": d.difficulty,
                "description": d.description,
                "max_steps": d.max_steps,
                "num_alerts": len(d.alerts),
            }
            for d in defs
        ]
    )


@app.get("/reset", response_model=ResetResponse, tags=["environment"])
def reset_get(task: str = Query(default="phishing_detection", description="Task name")):
    """Reset the environment to the given task (GET)."""
    return _do_reset(task)


@app.post("/reset", response_model=ResetResponse, tags=["environment"])
def reset_post(request: ResetRequest):
    """Reset the environment to the given task (POST)."""
    return _do_reset(request.task)


def _do_reset(task_name: str) -> ResetResponse:
    """Shared reset logic."""
    try:
        obs = _env.reset(task_name=task_name)
    except KeyError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return ResetResponse(observation=obs.model_dump())


@app.post("/step", response_model=StepResponse, tags=["environment"])
def step(request: StepRequest):
    """Execute one action in the environment."""
    try:
        action_type = ActionType(request.action)
    except ValueError:
        valid = [a.value for a in ActionType]
        raise HTTPException(
            status_code=400,
            detail=f"Invalid action '{request.action}'. Valid: {valid}",
        )

    action = Action(action_type=action_type, parameters=request.parameters)

    try:
        obs, reward, done, info = _env.step(action)
    except RuntimeError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return StepResponse(
        observation=obs.model_dump(),
        reward=reward.model_dump(),
        done=done,
        info=info,
    )


@app.get("/state", response_model=StateResponse, tags=["environment"])
def get_state():
    """Return the current environment state."""
    return StateResponse(state=_env.state())


# ---------------------------------------------------------------------------
# Entry point for [project.scripts]
# ---------------------------------------------------------------------------

def main():
    """Entry point for the soc-server script."""
    uvicorn.run("server.app:app", host="0.0.0.0", port=7860, reload=False)


if __name__ == "__main__":
    main()
