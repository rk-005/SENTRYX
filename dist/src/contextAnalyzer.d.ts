import { DetectedEntity, AttackType } from "./types";
export declare class ContextAnalyzer {
    analyzeMultiStepAttacks(currentPrompt: string, history: Array<{
        prompt: string;
        entities: DetectedEntity[];
    }>): {
        attackType: AttackType;
        escalationFactor: number;
    };
    generateReason(detectedEntities: DetectedEntity[], keywordFindings: {
        keyword: string;
        score: number;
    }[], contextAttackType: AttackType, escalationFactor: number): string;
}
//# sourceMappingURL=contextAnalyzer.d.ts.map