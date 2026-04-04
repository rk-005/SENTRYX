#!/usr/bin/env bash

set -euo pipefail

SPACE_URL="${1:-}"
REPO_DIR="${2:-.}"

if [ ! -f "$REPO_DIR/inference.py" ]; then
  echo "[FAIL] inference.py not found at repo root"
  exit 1
fi

if [ ! -f "$REPO_DIR/openenv.yaml" ]; then
  echo "[FAIL] openenv.yaml not found"
  exit 1
fi

if [ ! -f "$REPO_DIR/Dockerfile" ]; then
  echo "[FAIL] Dockerfile not found"
  exit 1
fi

echo "[INFO] validating openenv.yaml"
python - <<'PY' "$REPO_DIR"
import sys
from pathlib import Path
import yaml

repo = Path(sys.argv[1])
config = yaml.safe_load((repo / "openenv.yaml").read_text(encoding="utf-8"))
assert config["inference"]["script"] == "inference.py"
assert len(config["tasks"]) >= 3
for task in config["tasks"]:
    low, high = task["grader"]["score_range"]
    assert 0.0 <= low <= high <= 1.0
print("[OK] openenv.yaml parsed and benchmark metadata looks valid")
PY

echo "[INFO] validating tasks and local API contract"
python - <<'PY' "$REPO_DIR"
import sys
from pathlib import Path

repo = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(repo))

from fastapi.testclient import TestClient
from server import app
from tasks import ALL_TASKS

client = TestClient(app)

resp = client.get("/")
resp.raise_for_status()
assert resp.json()["status"] == "online"

listed = client.get("/tasks")
listed.raise_for_status()
listed_names = [task["name"] for task in listed.json()["tasks"]]
assert len(listed_names) >= 3

for task_name, definition in ALL_TASKS.items():
    reset_resp = client.post("/reset", json={"task": task_name})
    reset_resp.raise_for_status()
    obs = reset_resp.json()
    assert obs["step_number"] == 1

    rewards = []
    final_score = None
    for scenario in definition.scenarios:
        step_resp = client.post("/step", json={"action_type": scenario.expected_action.value})
        step_resp.raise_for_status()
        payload = step_resp.json()
        reward = float(payload["reward"])
        assert 0.0 <= reward <= 1.0
        rewards.append(reward)
        if payload["done"]:
            final_score = float(payload["info"]["final_score"])
    assert final_score is not None
    assert 0.0 <= final_score <= 1.0

print("[OK] reset/step/state/tasks endpoints validated for all tasks")
PY

if command -v docker >/dev/null 2>&1; then
  echo "[INFO] building Docker image"
  docker build -t openenv-security-validate "$REPO_DIR" >/dev/null
  echo "[OK] docker build completed"
else
  echo "[WARN] docker not available; skipping docker build"
fi

if [ -n "$SPACE_URL" ]; then
  echo "[INFO] checking Space URL: $SPACE_URL"
  curl -fsS "$SPACE_URL/" >/dev/null
  curl -fsS -X POST "$SPACE_URL/reset" -H "Content-Type: application/json" -d '{"task":"simple_pii_detection"}' >/dev/null
  echo "[OK] Space URL returned 200 for / and /reset"
fi

echo "[DONE] pre-submission validation completed"
