# OpenEnv Security — LLM Data Leakage Prevention

[![OpenEnv](https://img.shields.io/badge/OpenEnv-compatible-brightgreen.svg)](https://github.com/openenv)
[![Python](https://img.shields.io/badge/Python-3.11-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/Docker-ready-blue.svg)](https://www.docker.com/)

A production-grade **OpenEnv environment** that trains AI agents to detect and prevent sensitive data leakage in LLM systems. The environment simulates real-world security threats — credential exfiltration, prompt injection, PII exposure, and multi-step social engineering attacks — and provides rich reward signals for reinforcement learning.

## 🎯 Environment Description & Motivation

Large Language Models are increasingly deployed in production, but they face serious security risks when users (accidentally or maliciously) include sensitive data in prompts. This environment models the real-world task of **LLM input security screening** — a task performed daily by security teams at companies using LLM APIs.

The agent acts as a security analyst that must examine each incoming prompt and decide:

| Action | When to Use | Reward |
|--------|------------|--------|
| **ALLOW** | Prompt is safe, no sensitive data | +0.5 |
| **MASK** | Moderate-risk data, should be redacted | +0.7 |
| **BLOCK** | High-risk data, must be rejected | +1.0 |

Wrong decisions are penalized: allowing critical threats gives **-1.0**, over-blocking safe prompts gives **-0.5**.

## 📦 Action & Observation Spaces

### Observation Space (`Observation` Pydantic Model)

| Field | Type | Description |
|-------|------|-------------|
| `prompt` | `str` | The current prompt to analyse for threats |
| `risk_score` | `float [0-100]` | Computed risk score |
| `threat_level` | `SAFE \| WARNING \| CRITICAL` | Threat classification |
| `sensitivity` | `LOW \| MEDIUM \| HIGH` | Data sensitivity level |
| `detected_entities` | `List[DetectedEntity]` | Sensitive entities found (EMAIL, PHONE, API_KEY, CREDIT_CARD, PASSWORD, SECRET, TOKEN) |
| `attack_type` | `NORMAL \| CREDENTIAL_EXFILTRATION \| API_KEY_LEAK \| PROMPT_INJECTION` | Attack pattern classification |
| `reason` | `str` | Human-readable analysis explanation |
| `step_number` | `int` | Current step in episode |
| `total_steps` | `int` | Total steps in task |
| `history_summary` | `List[str]` | Last 3 action summaries for context |

### Action Space (`Action` Pydantic Model)

| Field | Type | Values |
|-------|------|--------|
| `action_type` | `ActionType` | `ALLOW`, `MASK`, `BLOCK` |

### Reward Function

| Decision | Condition | Reward | Description |
|----------|-----------|--------|-------------|
| **BLOCK** | Risk ≥ 70 (CRITICAL) | **+1.0** | Perfect protection |
| **MASK** | 40 ≤ Risk < 70 (WARNING) | **+0.7** | Good balanced action |
| **ALLOW** | Risk < 40 (SAFE) | **+0.5** | Safe to proceed |
| BLOCK | Risk 40-70 (WARNING) | +0.2 | Cautious; acceptable |
| MASK | Wrong tier | -0.3 | Suboptimal |
| ALLOW | Risk 40-70 (WARNING) | -0.7 | Risky under-reaction |
| BLOCK | Risk < 40 (SAFE) | -0.5 | Over-blocking |
| ALLOW | Risk ≥ 70 (CRITICAL) | **-1.0** | Dangerous miss |

The reward function provides **per-step signal** with partial credit for adjacent-tier decisions, not just binary end-of-episode scoring.

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────┐
│                  Input Prompt                    │
└──────────────────────┬──────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────┐
│          Regex Detector (7 entity types)         │
│  EMAIL · PHONE · API_KEY · CREDIT_CARD          │
│  PASSWORD · SECRET · TOKEN                       │
└──────────────────────┬──────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────┐
│      Keyword Analyzer (15 sensitive terms)       │
└──────────────────────┬──────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────┐
│     Heuristic Risk Scorer (entity scoring)       │
│     + diversity penalty + context boost          │
└──────────────────────┬──────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────┐
│   Context Analyzer (multi-step attack detection) │
│   + prompt injection · credential exfiltration   │
└──────────────────────┬──────────────────────────┘
                       ▼
┌─────────────────────────────────────────────────┐
│      Reward Engine (0.0–1.0 shaped signal)       │
└─────────────────────────────────────────────────┘
```

## 📋 Tasks

### Task 1: `simple_pii_detection` (Easy)
- **Scenarios:** 8 prompts
- **Difficulty:** Easy — single obvious PII entities
- **Description:** Each prompt contains at most one type of sensitive data. The agent must identify whether to ALLOW, MASK, or BLOCK.
- **Challenge:** Basic entity recognition and risk mapping.

### Task 2: `threat_classification` (Medium)
- **Scenarios:** 10 prompts
- **Difficulty:** Medium — multiple entities and mixed signals
- **Description:** Prompts contain overlapping risk factors (e.g., email + confidential keyword, credit card + secret). The agent must weigh the combined threat level.
- **Challenge:** Handling ambiguity and multiple simultaneous risk factors.

### Task 3: `multi_step_attack` (Hard)
- **Scenarios:** 12 prompts
- **Difficulty:** Hard — coordinated multi-step attacks
- **Description:** A sequence of prompts that form an attack pattern. Individual prompts may seem innocent but become dangerous in context (credential exfiltration, prompt injection, social engineering).
- **Challenge:** Using history context, detecting escalation patterns, and identifying prompt injection attempts that are disguised.

## 🚀 Setup & Usage

### Prerequisites
- Python 3.11+
- Docker (for containerized deployment)

### Local Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/openenv-security.git
cd openenv-security

# Install dependencies
pip install -r requirements.txt

# Start the environment server
python server.py
```

The server starts at `http://localhost:7860`.

### Docker Setup

```bash
# Build the container
docker build -t openenv-security .

# Run the container
docker run -p 7860:7860 openenv-security
```

### API Usage

```bash
# List available tasks
curl http://localhost:7860/tasks

# Reset environment (start new episode)
curl -X POST http://localhost:7860/reset \
  -H "Content-Type: application/json" \
  -d '{"task": "simple_pii_detection"}'

# Take an action
curl -X POST http://localhost:7860/step \
  -H "Content-Type: application/json" \
  -d '{"action_type": "BLOCK"}'

# Get current state
curl http://localhost:7860/state
```

### Python Usage

```python
from env import SecurityEnv
from models import Action, ActionType

env = SecurityEnv()

# Reset with a task
obs = env.reset(task="simple_pii_detection")
print(f"Prompt: {obs.prompt}")
print(f"Risk: {obs.risk_score}, Threat: {obs.threat_level}")

# Take an action
result = env.step(Action(action_type=ActionType.BLOCK))
print(f"Reward: {result.reward}, Done: {result.done}")
```

### Running Inference

```bash
# Set environment variables
export HF_TOKEN="your-api-key"
export API_BASE_URL="https://router.huggingface.co/v1"
export MODEL_NAME="Qwen/Qwen2.5-72B-Instruct"
export ENV_URL="http://localhost:7860"  # or your HF Space URL

# Start the environment server (in another terminal)
python server.py

# Run baseline inference
python inference.py
```

## 📊 Baseline Scores

| Task | Difficulty | Scenarios | Baseline Score |
|------|-----------|-----------|---------------|
| `simple_pii_detection` | Easy | 8 | ~0.75 |
| `threat_classification` | Medium | 10 | ~0.55 |
| `multi_step_attack` | Hard | 12 | ~0.40 |

*Scores obtained with Qwen2.5-72B-Instruct at temperature=0.3.*

## 🧪 Testing

```bash
# Verify environment locally
python -c "
from env import SecurityEnv
from models import Action, ActionType

env = SecurityEnv()
obs = env.reset('simple_pii_detection')
print('Reset OK:', obs.prompt[:50])

result = env.step(Action(action_type=ActionType.ALLOW))
print('Step OK:', result.reward, result.done)

state = env.state()
print('State OK:', state.step_number, '/', state.total_steps)
print('All checks passed!')
"
```

## 📁 Project Structure

```
openenv-security/
├── openenv.yaml          # OpenEnv metadata & spec
├── Dockerfile            # Container configuration
├── requirements.txt      # Python dependencies
├── server.py             # FastAPI HTTP server (/reset, /step, /state)
├── env.py                # Main environment class
├── models.py             # Pydantic models (Observation, Action, Reward)
├── detectors.py          # Regex, keyword, heuristic detectors
├── context_analyzer.py   # Multi-step attack detection
├── reward_engine.py      # Shaped reward function (0.0-1.0)
├── tasks.py              # 3 tasks + graders (easy/medium/hard)
├── inference.py          # Baseline inference script
└── README.md             # This file
```

## 🏆 Reward Design Details

The reward function has several interesting properties:

1. **Per-step signal**: Every action gets immediate feedback, not just end-of-episode.
2. **Partial credit**: Adjacent-tier decisions get partial credit (e.g., MASK when BLOCK expected = -0.3, not -1.0).
3. **Asymmetric penalties**: Allowing dangerous content (-1.0) is penalized more severely than over-blocking (-0.5), reflecting real-world security priorities.
4. **Context-aware scoring**: Risk scores incorporate history, so the same prompt can have different risk levels depending on what came before.

## 📝 License

MIT License — see LICENSE file for details.

## 👥 Authors

Rohith, Bhuvana, Jishnu

---

**Built for OpenEnv | Production-Grade Security | Reinforcement Learning Ready**