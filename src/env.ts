import { RegexDetector } from "./detectors/regexDetector";
import { KeywordAnalyzer } from "./detectors/keywordAnalyzer";
import { HeuristicRiskScorer } from "./detectors/heuristicRiskScorer";
import { EnvironmentState, StepResponse, Action, DetectedEntity } from "./types";

/**
 * OpenEnv Security Environment
 * Main environment class that orchestrates all security analysis modules
 */
export class OpenEnvSecurity {
  private state: EnvironmentState;
  private regexDetector: RegexDetector;
  private keywordAnalyzer: KeywordAnalyzer;
  private heuristicScorer: HeuristicRiskScorer;

  constructor() {
    this.regexDetector = new RegexDetector();
    this.keywordAnalyzer = new KeywordAnalyzer();
    this.heuristicScorer = new HeuristicRiskScorer();

    this.state = this.initializeState();
  }

  /**
   * Initialize environment state
   */
  private initializeState(): EnvironmentState {
    return {
      prompt: "",
      risk_score: 0,
      threat_level: "SAFE",
      sensitivity: "LOW",
      last_action: null,
      detected_entities: [],
      attack_type: "NORMAL",
      reason: "",
      episode_reward: 0,
      history: [],
      timestamp: Date.now(),
    };
  }

  /**
   * Reset environment to initial state
   */
  public reset(): EnvironmentState {
    this.state = this.initializeState();
    return this.getStateCopy();
  }

  /**
   * Execute one step in the environment
   */
  public step(action: Action, prompt: string): StepResponse {
    // Update prompt in state
    this.state.prompt = prompt;

    // Step 1: Detect entities using regex
    const regexEntities = this.regexDetector.detect(prompt);

    // Step 2: Analyze keywords
    const keywordResults = this.keywordAnalyzer.analyze(prompt);
    const keywordScore = keywordResults.reduce((sum, result) => sum + result.score, 0);

    // Step 3: Calculate heuristic risk score
    const heuristicScore = this.heuristicScorer.scoreEntities(regexEntities);

    // Step 4: Context analysis - get all history entities
    let historyEntities: DetectedEntity[] = [];
    for (const entry of this.state.history) {
      historyEntities = historyEntities.concat(entry.detected_entities);
    }

    // Step 4b: Calculate context boost
    const contextScore = this.heuristicScorer.calculateContextBoost(
      regexEntities,
      historyEntities
    );
    
    // Step 4c: Detect attack type
    const attackType = this.detectAttackPatternType(
      this.state.history,
      prompt
    );

    // Step 5: Combine scores
    let combinedRisk = Math.min(
      100,
      heuristicScore + keywordScore + contextScore
    );

    // Step 6: Calculate threat level
    const threatLevel = this.calculateThreatLevel(combinedRisk);

    // Step 7: Classify sensitivity
    const sensitivity = this.classifySensitivity(combinedRisk);

    // Step 8: Make decision based on risk
    const decision = this.makeDecision(combinedRisk);

    // Step 9: Determine if decision is correct
    const isCorrectDecision = this.isDecisionCorrect(action, combinedRisk);

    // Step 10: Calculate reward
    const reward = this.calculateReward(
      action,
      combinedRisk,
      isCorrectDecision
    );

    // Step 11: Generate reason
    const reason = this.generateReason(regexEntities, decision, attackType);

    // Update state
    this.state.risk_score = combinedRisk;
    this.state.threat_level = threatLevel;
    this.state.sensitivity = sensitivity;
    this.state.last_action = action;
    this.state.detected_entities = regexEntities;
    this.state.attack_type = attackType;
    this.state.reason = reason;
    this.state.timestamp = Date.now();

    // Add to history
    this.state.history.push({
      prompt,
      action,
      risk_score: combinedRisk,
      timestamp: Date.now(),
      detected_entities: regexEntities,
    });

    // Accumulate episode reward
    this.state.episode_reward += reward;

    return {
      state: this.getStateCopy(),
      reward,
      done: false,
    };
  }

  /**
   * Get current state (without modification)
   */
  public getState(): EnvironmentState {
    return this.getStateCopy();
  }

  /**
   * Create a deep copy of state
   */
  private getStateCopy(): EnvironmentState {
    return {
      prompt: this.state.prompt,
      risk_score: this.state.risk_score,
      threat_level: this.state.threat_level,
      sensitivity: this.state.sensitivity,
      last_action: this.state.last_action,
      detected_entities: [...this.state.detected_entities],
      attack_type: this.state.attack_type,
      reason: this.state.reason,
      episode_reward: this.state.episode_reward,
      history: [...this.state.history],
      timestamp: this.state.timestamp,
    };
  }

  /**
   * Calculate threat level based on risk score
   */
  private calculateThreatLevel(
    riskScore: number
  ): "SAFE" | "WARNING" | "CRITICAL" {
    if (riskScore < 40) return "SAFE";
    if (riskScore < 70) return "WARNING";
    return "CRITICAL";
  }

  /**
   * Classify sensitivity level
   */
  private classifySensitivity(riskScore: number): "LOW" | "MEDIUM" | "HIGH" {
    if (riskScore < 40) return "LOW";
    if (riskScore < 70) return "MEDIUM";
    return "HIGH";
  }

  /**
   * Make decision based on risk score
   */
  private makeDecision(riskScore: number): "ALLOW" | "MASK" | "BLOCK" {
    if (riskScore < 40) return "ALLOW";
    if (riskScore < 70) return "MASK";
    return "BLOCK";
  }

  /**
   * Determine if the action taken is correct for the risk level
   */
  private isDecisionCorrect(action: Action, riskScore: number): boolean {
    if (riskScore < 40) {
      return action === "ALLOW";
    } else if (riskScore < 70) {
      return action === "MASK";
    } else {
      return action === "BLOCK";
    }
  }

  /**
   * Calculate reward for the action taken
   */
  private calculateReward(
    action: Action,
    riskScore: number,
    isCorrect: boolean
  ): number {
    let reward = 0;

    if (isCorrect) {
      reward += 10;
    } else {
      reward -= 5;
    }

    // Bonus for blocking high-risk prompts
    if (action === "BLOCK" && riskScore > 70) {
      reward += 5;
    }

    // Penalty for allowing high-risk prompts
    if (action === "ALLOW" && riskScore > 70) {
      reward -= 10;
    }

    return reward;
  }

    /**
   * Detect attack pattern type based on history and current prompt
   */
  private detectAttackPatternType(
    history: Array<{ prompt: string; action: Action; timestamp: number; detected_entities: DetectedEntity[] }>,
    currentPrompt: string
  ): "NORMAL" | "CREDENTIAL_EXFILTRATION" | "API_KEY_LEAK" | "PROMPT_INJECTION" {
    // Check for prompt injection pattern first (in current prompt)
    if (this.isPromptInjection(currentPrompt)) {
      return "PROMPT_INJECTION";
    }

    if (history.length === 0) return "NORMAL";

    // Check for credential exfiltration pattern
    const hasEmail = history.some((h) =>
      h.detected_entities.some((e) => e.type === "EMAIL")
    );
    const hasPassword = currentPrompt.toLowerCase().includes("password");

    if (hasEmail && hasPassword) {
      return "CREDENTIAL_EXFILTRATION";
    }

    // Check for API key leak pattern
    const hasApiKey = currentPrompt.toLowerCase().includes("api");
    if (hasApiKey) {
      return "API_KEY_LEAK";
    }

    return "NORMAL";
  }

  // ...existing code...

  /**
   * Check if prompt contains injection attempts
   */
  private isPromptInjection(prompt: string): boolean {
    const injectionPatterns = [
      /<!--[\s\S]*?-->/,           // HTML comments
      /\/\*[\s\S]*?\*\//,          // C-style comments
      /<script[\s\S]*?<\/script>/i, // Script tags
      /{{[\s\S]*?}}/,              // Template injection
      /\$\{[\s\S]*?\}/,            // Template literals
      /`[\s\S]*?`/,                // Backticks
      /(\n|\r)/,                   // Newlines in suspicious context
    ];

    return injectionPatterns.some((pattern) => pattern.test(prompt));
  }

  /**
   * Generate human-readable reason for decision
   */
  private generateReason(
    entities: DetectedEntity[],
    decision: string,
    attackType: string
  ): string {
    if (entities.length === 0) {
      return "No sensitive data detected";
    }

    const entityTypes = [...new Set(entities.map((e) => e.type))].join(", ");
    let reason = `Detected ${entityTypes}`;

    if (attackType !== "NORMAL") {
      reason += ` | Attack: ${attackType}`;
    }

    reason += ` | Decision: ${decision}`;
    return reason;
  }
}