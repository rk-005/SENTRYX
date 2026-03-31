import { OpenEnvSecurity } from "./env";
import { Action, EnvironmentState, StepResponse } from "./types";
/**
 * Main entry point for OpenEnv Security environment
 * Provides clean API for integration with RL agents or external systems
 */
declare class SecurityEnvironmentAPI {
    private environment;
    constructor();
    /**
     * Initialize/Reset the environment to initial state
     */
    reset(): EnvironmentState;
    /**
     * Execute one step in the environment
     * @param action - Decision action (ALLOW, MASK, BLOCK, REWRITE)
     * @param prompt - Input prompt to analyze
     * @returns Step response with state, reward, and done flag
     */
    step(action: Action, prompt: string): StepResponse;
    /**
     * Get current environment state
     */
    getState(): EnvironmentState;
    /**
     * Get formatted state as JSON string
     */
    getStateJSON(): string;
    /**
     * Run multiple steps in sequence
     */
    runEpisode(episodes: Array<{
        action: Action;
        prompt: string;
    }>): StepResponse[];
    /**
     * Get episode statistics
     */
    getEpisodeStats(): {
        totalSteps: number;
        totalReward: number;
        averageReward: number;
        riskScores: number[];
    };
}
export { SecurityEnvironmentAPI, OpenEnvSecurity };
export type { Action, EnvironmentState, StepResponse };
export * from "./types";
export declare const securityEnv: SecurityEnvironmentAPI;
//# sourceMappingURL=index.d.ts.map