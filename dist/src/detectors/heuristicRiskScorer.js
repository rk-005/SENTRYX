"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.HeuristicRiskScorer = void 0;
class HeuristicRiskScorer {
    constructor() {
        this.entityScores = {
            EMAIL: 20,
            PHONE: 25,
            API_KEY: 50,
            CREDIT_CARD: 60,
            PASSWORD: 70,
            SECRET: 65,
            TOKEN: 55,
        };
    }
    scoreEntities(entities) {
        if (entities.length === 0)
            return 0;
        let baseScore = 0;
        const entityTypeSet = new Set();
        for (const entity of entities) {
            baseScore += this.entityScores[entity.type] || 0;
            entityTypeSet.add(entity.type);
        }
        // Penalize for multiple sensitive entity types
        const diversityPenalty = Math.pow(entityTypeSet.size, 1.2) * 5;
        return Math.min(baseScore + diversityPenalty, 100);
    }
    calculateContextBoost(currentEntities, historyEntities) {
        let boost = 0;
        const currentTypes = new Set(currentEntities.map((e) => e.type));
        const historyTypes = new Set(historyEntities.map((e) => e.type));
        // Email + Password = high risk
        if (historyTypes.has("EMAIL") && currentTypes.has("PASSWORD")) {
            boost += 25;
        }
        // API Key + Secret = high risk
        if (currentTypes.has("API_KEY") && currentTypes.has("SECRET")) {
            boost += 20;
        }
        // Multi-step attack pattern
        if (historyEntities.length > 0 && currentEntities.length > 0) {
            boost += 10;
        }
        return boost;
    }
}
exports.HeuristicRiskScorer = HeuristicRiskScorer;
//# sourceMappingURL=heuristicRiskScorer.js.map