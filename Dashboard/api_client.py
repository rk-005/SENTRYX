"""SENTRYX dashboard API client."""

from __future__ import annotations

from typing import Any

import requests

API_BASE = "http://localhost:7860"
TIMEOUT = 10


class APIError(Exception):
    """Raised on any backend communication failure."""

    def __init__(self, message: str, status_code: int = 0):
        super().__init__(message)
        self.status_code = status_code


def _post(endpoint: str, payload: dict) -> dict:
    try:
        response = requests.post(f"{API_BASE}{endpoint}", json=payload, timeout=TIMEOUT)
        response.raise_for_status()
        return response.json()
    except requests.ConnectionError as exc:
        raise APIError(
            "Cannot connect to the SENTRYX backend at localhost:7860. "
            "Start it with: py -3.12 server.py"
        ) from exc
    except requests.Timeout as exc:
        raise APIError(f"Request to {endpoint} timed out after {TIMEOUT}s.") from exc
    except requests.HTTPError as exc:
        detail = ""
        try:
            detail = exc.response.json().get("detail", exc.response.text)
        except Exception:
            detail = exc.response.text
        raise APIError(
            f"HTTP {exc.response.status_code} from {endpoint}: {detail}",
            status_code=exc.response.status_code,
        ) from exc


def _get(endpoint: str) -> dict:
    try:
        response = requests.get(f"{API_BASE}{endpoint}", timeout=TIMEOUT)
        response.raise_for_status()
        return response.json()
    except requests.ConnectionError as exc:
        raise APIError("Cannot connect to the SENTRYX backend at localhost:7860.") from exc
    except requests.Timeout as exc:
        raise APIError(f"GET {endpoint} timed out.") from exc
    except requests.HTTPError as exc:
        raise APIError(f"HTTP {exc.response.status_code} from {endpoint}") from exc


def health_check() -> bool:
    try:
        data = _get("/")
        return data.get("status") == "online"
    except APIError:
        return False


def analyze(prompt: str, task: str = "general") -> dict[str, Any]:
    return _post("/analyze", {"prompt": prompt, "task": task})


def get_tasks() -> list[dict]:
    return _get("/tasks").get("tasks", [])


def reset(task: str) -> dict:
    return _post("/reset", {"task": task})


def step(action_type: str) -> dict:
    return _post("/step", {"action_type": action_type})


def get_state() -> dict:
    return _get("/state")
