/**
 * Integration examples showing how to use OpenEnv Security
 * This file demonstrates proper usage patterns
 * NOT part of the core library - for reference only
 */
import type { Action, EnvironmentState } from "./types";
/**
 * Example 1: Basic single-step usage
 */
export declare function basicUsage(): void;
/**
 * Example 2: Episode simulation with multiple steps
 */
export declare function episodeSimulation(): void;
/**
 * Example 3: Batch processing multiple prompts
 */
export declare function batchProcessing(): void;
/**
 * Example 4: Multi-step attack detection
 */
export declare function multiStepAttackDetection(): void;
/**
 * Example 5: Custom RL Agent Integration
 */
interface RLAgent {
    decideAction(state: EnvironmentState): Action;
    updatePolicy(reward: number, state: EnvironmentState): void;
}
export declare function trainAgentWithEnvironment(agent: RLAgent, prompts: string[], iterations: number): number;
/**
 * Example 6: Stress testing with edge cases
 */
export declare function stressTestingEdgeCases(): void;
/**
 * Example 7: Performance benchmarking
 */
export declare function performanceBenchmark(): void;
export declare function runAllExamples(): void;
export {};
//# sourceMappingURL=integration.example.d.ts.map