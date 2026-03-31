"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.securityEnv = exports.OpenEnvSecurity = exports.SecurityEnvironmentAPI = void 0;
const env_1 = require("./env");
Object.defineProperty(exports, "OpenEnvSecurity", { enumerable: true, get: function () { return env_1.OpenEnvSecurity; } });
/**
 * Main entry point for OpenEnv Security environment
 * Provides clean API for integration with RL agents or external systems
 */
class SecurityEnvironmentAPI {
    constructor() {
        this.environment = new env_1.OpenEnvSecurity();
    }
    /**
     * Initialize/Reset the environment to initial state
     */
    reset() {
        return this.environment.reset();
    }
    /**
     * Execute one step in the environment
     * @param action - Decision action (ALLOW, MASK, BLOCK, REWRITE)
     * @param prompt - Input prompt to analyze
     * @returns Step response with state, reward, and done flag
     */
    step(action, prompt) {
        return this.environment.step(action, prompt);
    }
    /**
     * Get current environment state
     */
    getState() {
        return this.environment.getState();
    }
    /**
     * Get formatted state as JSON string
     */
    getStateJSON() {
        return JSON.stringify(this.environment.getState(), null, 2);
    }
    /**
     * Run multiple steps in sequence
     */
    runEpisode(episodes) {
        const results = [];
        for (const episode of episodes) {
            results.push(this.step(episode.action, episode.prompt));
        }
        return results;
    }
    /**
     * Get episode statistics
     */
    getEpisodeStats() {
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
exports.SecurityEnvironmentAPI = SecurityEnvironmentAPI;
__exportStar(require("./types"), exports);
// Create and export singleton instance
exports.securityEnv = new SecurityEnvironmentAPI();
//# sourceMappingURL=index.js.map