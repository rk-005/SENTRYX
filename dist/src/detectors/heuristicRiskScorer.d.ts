import { DetectedEntity } from "../types";
export declare class HeuristicRiskScorer {
    private entityScores;
    scoreEntities(entities: DetectedEntity[]): number;
    calculateContextBoost(currentEntities: DetectedEntity[], historyEntities: DetectedEntity[]): number;
}
//# sourceMappingURL=heuristicRiskScorer.d.ts.map