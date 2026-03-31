"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.LLMRiskClassifier = void 0;
class LLMRiskClassifier {
    classify(prompt, detectedEntities, context) {
        let riskScore = 0;
        let attackType = "NORMAL";
        // Example scoring logic based on detected entities
        if (detectedEntities.includes("PASSWORD")) {
            riskScore += 30;
            attackType = "CREDENTIAL_EXFILTRATION";
        }
        if (detectedEntities.includes("API_KEY")) {
            riskScore += 50;
            attackType = "API_KEY_LEAK";
        }
        if (context.includes("send password") && detectedEntities.includes("EMAIL")) {
            riskScore += 40;
            attackType = "CREDENTIAL_EXFILTRATION";
        }
        // Additional complex logic can be added here
        return { riskScore, attackType };
    }
}
exports.LLMRiskClassifier = LLMRiskClassifier;
//# sourceMappingURL=llmRiskClassifier.js.map