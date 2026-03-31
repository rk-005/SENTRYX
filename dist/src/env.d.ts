import { EnvironmentState, StepResponse, Action } from "./types";
/**
 * OpenEnv Security Environment
 * Main environment class that orchestrates all security analysis modules
 */
export declare class OpenEnvSecurity {
    private state;
    private regexDetector;
    private keywordAnalyzer;
    private heuristicScorer;
    constructor();
    /**
     * Initialize environment state
     */
    private initializeState;
    /**
     * Reset environment to initial state
     */
    reset(): EnvironmentState;
    /**
     * Execute one step in the environment
     */
    step(action: Action, prompt: string): StepResponse;
    /**
     * Get current state (without modification)
     */
    getState(): EnvironmentState;
    /**
     * Create a deep copy of state
     */
    private getStateCopy;
    /**
     * Calculate threat level based on risk score
     */
    private calculateThreatLevel;
    /**
     * Classify sensitivity level
     */
    private classifySensitivity;
    /**
     * Make decision based on risk score
     */
    private makeDecision;
    /**
     * Determine if the action taken is correct for the risk level
     */
    private isDecisionCorrect;
    /**
     * Calculate reward for the action taken
     */
    private calculateReward;
    /**
   * Detect attack pattern type based on history and current prompt
   */
    private detectAttackPatternType;
    /**
     * Check if prompt contains injection attempts
     */
    private isPromptInjection;
    /**
     * Generate human-readable reason for decision
     */
    private generateReason;
}
//# sourceMappingURL=env.d.ts.map