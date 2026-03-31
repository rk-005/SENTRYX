import { Action, ThreatLevel, Sensitivity } from "./types";
export declare class DecisionEngine {
    makeDecision(riskScore: number): Action;
    calculateThreatLevel(riskScore: number): ThreatLevel;
    calculateSensitivity(riskScore: number): Sensitivity;
    maskSensitiveData(prompt: string, action: Action): string;
}
//# sourceMappingURL=decisionEngine.d.ts.map