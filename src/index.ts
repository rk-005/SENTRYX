import { OpenEnvSecurity } from "./env";
import { Action, EnvironmentState, StepResponse } from "./types";

/**
 * Main entry point for OpenEnv Security environment
 * Provides clean API for integration with RL agents or external systems
 */

class SecurityEnvironmentAPI {
  private environment: OpenEnvSecurity;

  constructor() {
    this.environment = new OpenEnvSecurity();
  }

  /**
   * Initialize/Reset the environment to initial state
   */
  public reset(): EnvironmentState {
    return this.environment.reset();
  }

  /**
   * Execute one step in the environment
   * @param action - Decision action (ALLOW, MASK, BLOCK, REWRITE)
   * @param prompt - Input prompt to analyze
   * @returns Step response with state, reward, and done flag
   */
  public step(action: Action, prompt: string): StepResponse {
    return this.environment.step(action, prompt);
  }

  /**
   * Get current environment state
   */
  public getState(): EnvironmentState {
    return this.environment.getState();
  }

  /**
   * Get formatted state as JSON string
   */
  public getStateJSON(): string {
    return JSON.stringify(this.environment.getState(), null, 2);
  }

  /**
   * Run multiple steps in sequence
   */
  public runEpisode(episodes: Array<{ action: Action; prompt: string }>): StepResponse[] {
    const results: StepResponse[] = [];
    for (const episode of episodes) {
      results.push(this.step(episode.action, episode.prompt));
    }
    return results;
  }

  /**
   * Get episode statistics
   */
  public getEpisodeStats(): {
    totalSteps: number;
    totalReward: number;
    averageReward: number;
    riskScores: number[];
  } {
    const state = this.getState();
    const riskScores = state.history.map(() => state.risk_score);
    
    return {
      totalSteps: state.history.length,
      totalReward: state.episode_reward,
      averageReward: state.history.length > 0 ? state.episode_reward / state.history.length : 0,
      riskScores,
    };
  }
}

// Export for external use
export { SecurityEnvironmentAPI, OpenEnvSecurity };
export type { Action, EnvironmentState, StepResponse };
export * from "./types";

// Create and export singleton instance
export const securityEnv = new SecurityEnvironmentAPI();