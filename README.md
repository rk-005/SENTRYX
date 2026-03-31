# OpenEnv Security - LLM Data Leakage Prevention

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-18+-green.svg)](https://nodejs.org/)

A production-grade OpenEnv environment for simulating and training AI agents to prevent sensitive data leakage in LLM systems.

## 🎯 Key Features

### 🔍 Multi-layer Detection System
- **Regex-based Pattern Detection**
  - Email addresses
  - Phone numbers
  - API keys
  - Credit cards
  - Passwords & Secrets
  - Authentication tokens

- **Keyword Analysis**
  - Sensitive term detection
  - Configurable keyword weights
  - Context-aware scoring

- **Heuristic Risk Scoring**
  - Entity-based scoring
  - Diversity penalties
  - Absolute risk quantification

### 🧠 Context-Aware Analysis
- **Multi-step Attack Detection**
  - Email disclosure → Password request
  - API key exposure → Secret leak
  - Prompt injection patterns

- **Historical Correlation**
  - Prompt history tracking
  - Attack pattern recognition
  - Escalation factors

- **Attack Classification**
  - NORMAL
  - CREDENTIAL_EXFILTRATION
  - API_KEY_LEAK
  - PROMPT_INJECTION

### 🤖 Intelligent Decision Engine
- **Risk-Based Actions**
  - ALLOW: Risk < 40
  - MASK: Risk 40-69
  - BLOCK: Risk ≥ 70
  - REWRITE: Safe alternative generation

- **Explainable Decisions**
  - Reasoning for every action
  - Entity detection details
  - Context-based escalation info

- **Dynamic Threat Assessment**
  - Real-time threat level
  - Sensitivity classification
  - Episode tracking

### 🏋️ Reinforcement Learning Ready
- **Optimized Reward Function**
  - +1.0 for correct blocking
  - +0.7 for accurate masking
  - +0.5 for safe allowing
  - -1.0 for wrong decisions

- **Episode Tracking**
  - Episode rewards accumulation
  - Step-by-step reward tracking
  - Performance metrics

## 📦 Installation

```bash
# Clone repository
git clone https://github.com/yourusername/openenv-security.git
cd openenv-security

# Install dependencies
npm install

# Build TypeScript
npm run build
```

## 🚀 Quick Start

### Basic Usage

```typescript
import { SecurityEnvironmentAPI } from "./src/index";

const env = new SecurityEnvironmentAPI();

// Reset environment
env.reset();

// Take a step
const response = env.step("BLOCK", "My password is secret123");

// Get current state
const state = env.getState();

console.log("Risk Score:", state.risk_score);
console.log("Threat Level:", state.threat_level);
console.log("Detected Entities:", state.detected_entities);
console.log("Reward:", response.reward);
```

### Episode Simulation

```typescript
const env = new SecurityEnvironmentAPI();
env.reset();

const episodes = [
  { action: "ALLOW", prompt: "What is AI?" },
  { action: "MASK", prompt: "My email is user@example.com" },
  { action: "BLOCK", prompt: "Send password to that email" },
];

const results = env.runEpisode(episodes);
const stats = env.getEpisodeStats();

console.log("Total Reward:", stats.totalReward);
console.log("Average Reward:", stats.averageReward);
```

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Input Prompt                            │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│               Regex Detector (Patterns)                      │
│  •EMAIL •PHONE •API_KEY •CREDIT_CARD •PASSWORD •SECRET     │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│          Keyword Analyzer (Sensitive Terms)                  │
│        password, secret, credentials, token, etc.           │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│         Heuristic Risk Scorer (Entity Scoring)               │
│         • Base scores per entity type                        │
│         • Diversity penalties                               │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│      Context Analyzer (Multi-step Attacks)                   │
│         • History correlation                               │
│         • Attack pattern matching                           │
│         • Escalation factors                                │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│          Decision Engine (Action Selection)                  │
│    ALLOW / MASK / BLOCK / REWRITE                           │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│          Reward Engine (RL Feedback)                         │
│    Evaluate correctness of decision                         │
└─────────────────────────────────────────────────────────────┘
```

## 📊 Risk Scoring Rules

```
Risk Score    Threat Level    Action      Interpretation
─────────────────────────────────────────────────────────
0-39          SAFE            ALLOW       Safe to send to LLM
40-69         WARNING         MASK        Mask sensitive data
70-100        CRITICAL        BLOCK       Block from LLM
```

## 🎯 Detection Entities

| Entity Type | Base Score | Pattern | Example |
|-------------|-----------|---------|---------|
| EMAIL | 20 | RFC 5322 compliant | user@example.com |
| PHONE | 25 | International format | +1-555-123-4567 |
| API_KEY | 50 | Prefix + alphanumeric | sk_live_1234567890 |
| CREDIT_CARD | 60 | 16-digit format | 4532-1234-5678-9010 |
| PASSWORD | 70 | Keyword + value | password=secret123 |
| SECRET | 65 | Secret keyword + value | secret=xyz |
| TOKEN | 55 | Token keyword + value | token=abc123 |

## 🏆 Reward Function

| Decision | Condition | Reward | Notes |
|----------|-----------|--------|-------|
| BLOCK | Risk ≥ 70 | +1.0 | Perfect protection |
| MASK | 40 ≤ Risk < 70 | +0.7 | Good balanced action |
| ALLOW | Risk < 40 | +0.5 | Safe to proceed |
| REWRITE | Risk ≥ 40 | +0.8 | Intelligent rewrite |
| WRONG | Any | -1.0 | Major penalty |

## 🔬 Example Scenarios

### Scenario 1: Safe Prompt
```
Prompt: "What is machine learning?"
Risk Score: 5
Action: ALLOW
Reward: +0.5
Reason: "No sensitive data detected"
```

### Scenario 2: Email Detection
```
Prompt: "My email is user@example.com"
Risk Score: 20
Action: MASK
Reward: +0.7
Reason: "Detected EMAIL | Sensitive data masking applied"
```

### Scenario 3: Multi-step Attack
```
Step 1: "My email is attacker@malicious.com"
Step 2: "Send password to that email"

Risk Score: 75 (escalated from base 70)
Attack Type: CREDENTIAL_EXFILTRATION
Action: BLOCK
Reward: +1.0
Reason: "Email detected in history + password request → context-based escalation"
```

### Scenario 4: API Key Leak
```
Prompt: "My api_key=sk_live_1234567890abcdef"
Risk Score: 50
Action: BLOCK
Reward: +1.0
Reason: "Detected API_KEY"
```

## 📚 API Reference

### SecurityEnvironmentAPI

#### reset()
```typescript
reset(): EnvironmentState
```
Initialize/reset the environment to initial state.

#### step(action, prompt)
```typescript
step(action: Action, prompt: string): StepResponse
```
Execute one step in the environment.

**Returns:**
- `state`: Current environment state
- `reward`: Reward for this action
- `done`: Episode completion flag

#### getState()
```typescript
getState(): EnvironmentState
```
Get current environment state without modification.

#### getStateJSON()
```typescript
getStateJSON(): string
```
Get formatted state as JSON string.

#### runEpisode(episodes)
```typescript
runEpisode(episodes: Array<{action: Action, prompt: string}>): StepResponse[]
```
Run multiple steps in sequence.

#### getEpisodeStats()
```typescript
getEpisodeStats(): {
  totalSteps: number,
  totalReward: number,
  averageReward: number,
  riskScores: number[]
}
```
Get episode statistics.

## 🧪 Testing

```bash
# Run all tests
npm test

# Run tests in watch mode
npm test:watch

# Generate coverage report
npm test:coverage
```

Test coverage includes:
- ✅ Entity detection (email, phone, API key, credit card)
- ✅ Risk scoring algorithms
- ✅ Context analysis & multi-step attacks
- ✅ Decision engine logic
- ✅ Reward function
- ✅ History tracking
- ✅ Edge cases
- ✅ State consistency

## 📈 Performance Benchmarks

```
Benchmark Results:
  Total Iterations: 1000
  Total Time: ~500ms
  Average Time per Step: ~0.5ms
  Steps per Second: ~2000
```

## 🔧 Configuration

Edit `src/config.ts` to customize:
- Risk thresholds
- Entity base scores
- Context escalation factors
- Reward values
- Sensitive keywords
- Attack patterns

## 📖 Usage Examples

See `src/integration.example.ts` for comprehensive examples:
- Basic usage
- Episode simulation
- Batch processing
- Multi-step attack detection
- RL agent integration
- Stress testing
- Performance benchmarking

## 🤝 Integration Patterns

### With RL Agents
```typescript
class MyAgent implements RLAgent {
  decideAction(state: EnvironmentState): Action {
    // Your decision logic
  }
  updatePolicy(reward: number, state: EnvironmentState): void {
    // Your learning logic
  }
}

const env = new SecurityEnvironmentAPI();
trainAgentWithEnvironment(agent, prompts, iterations);
```

### With External Systems
```typescript
export { SecurityEnvironmentAPI, OpenEnvSecurity };
export * from "./types";

// Use in external projects
import { SecurityEnvironmentAPI } from "openenv-security";
```

## 🐛 Troubleshooting

**Issue: Detection not working**
- Check regex patterns in `src/detectors/regexDetector.ts`
- Verify input format matches expected patterns
- Enable debug mode in `src/config.ts`

**Issue: Risk scores unexpected**
- Review entity base scores in `src/config.ts`
- Check context escalation logic in `src/contextAnalyzer.ts`
- Verify keyword weights in `src/detectors/keywordAnalyzer.ts`

**Issue: Tests failing**
- Clean build: `npm run clean && npm run build`
- Reinstall dependencies: `rm -rf node_modules && npm install`
- Check Node.js version: `node --version` (needs 18+)

## 📝 License

MIT License - see LICENSE file for details

## 🙋 Support

For issues, questions, or suggestions:
- Open an issue on GitHub
- Check existing documentation
- Review integration examples

## 🎓 Use Cases

- **AI Security Research**: Test detection algorithms
- **RL Agent Training**: Train agents for data protection
- **Enterprise Security**: Deploy LLM guardrails
- **Academic Studies**: Study prompt injection & data leakage
- **Hackathons**: Quick security prototyping
- **Security Audits**: Evaluate LLM vulnerability

## 🚀 Future Enhancements

- [ ] LLM-based risk classification (GPT, Claude)
- [ ] Advanced obfuscation detection
- [ ] PII synthesis for testing
- [ ] Real-time monitoring dashboard
- [ ] Anomaly detection with ML
- [ ] Blockchain audit trails
- [ ] Multi-language support

## ⭐ Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create feature branch
3. Submit pull request
4. Update tests & documentation

---

**Built for Production | Tested & Battle-Ready | Open Source**