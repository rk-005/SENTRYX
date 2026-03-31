import { Action } from "./types";

export class RewardEngine {
  calculateReward(
    action: Action,
    riskScore: number,
    isCorrectDecision: boolean
  ): number {
    let reward = 0;

    if (!isCorrectDecision) {
      return -1.0; // Major penalty for wrong decision
    }

    if (action === "BLOCK" && riskScore >= 70) {
      reward = 1.0; // Perfect block
    } else if (action === "MASK" && riskScore >= 40 && riskScore < 70) {
      reward = 0.7; // Good masking
    } else if (action === "ALLOW" && riskScore < 40) {
      reward = 0.5; // Safe allow
    } else if (action === "REWRITE" && riskScore >= 40) {
      reward = 0.8; // Intelligent rewrite
    } else {
      reward = -0.5; // Suboptimal decision
    }

    return reward;
  }

  isCorrectDecision(action: Action, riskScore: number): boolean {
    if (riskScore >= 70 && action === "BLOCK") return true;
    if (riskScore >= 40 && riskScore < 70 && action === "MASK") return true;
    if (riskScore < 40 && action === "ALLOW") return true;
    return false;
  }
}