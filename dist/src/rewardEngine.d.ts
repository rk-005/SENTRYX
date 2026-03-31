import { Action } from "./types";
export declare class RewardEngine {
    calculateReward(action: Action, riskScore: number, isCorrectDecision: boolean): number;
    isCorrectDecision(action: Action, riskScore: number): boolean;
}
//# sourceMappingURL=rewardEngine.d.ts.map