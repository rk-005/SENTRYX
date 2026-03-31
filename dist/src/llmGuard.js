"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.llmGuard = exports.LLMGuard = void 0;
const index_1 = require("./index");
/**
 * LLM Guard: Prevents unsafe prompts from reaching the LLM
 */
class LLMGuard {
    /**
     * Check if prompt is safe before sending to LLM
     */
    async checkPrompt(prompt) {
        // Step the environment to analyze the prompt
        const response = index_1.securityEnv.step("ALLOW", prompt);
        const state = response.state;
        return {
            isSafe: state.threat_level === "SAFE",
            decision: state.last_action || "ALLOW",
            state,
            reason: state.reason,
            riskScore: state.risk_score,
        };
    }
    /**
     * Process prompt based on risk level
     */
    async processPrompt(prompt) {
        const analysis = await this.checkPrompt(prompt);
        switch (analysis.state.threat_level) {
            case "SAFE":
                // Allow prompt to reach LLM
                return {
                    processedPrompt: prompt,
                    isAllowed: true,
                    action: "ALLOW",
                    reason: "Prompt is safe to process",
                };
            case "WARNING":
                // Mask sensitive data before sending to LLM
                const maskedPrompt = this.maskSensitiveData(prompt, analysis.state.detected_entities);
                return {
                    processedPrompt: maskedPrompt,
                    isAllowed: true,
                    action: "MASK",
                    reason: `Sensitive data masked: ${analysis.reason}`,
                };
            case "CRITICAL":
                // Block prompt completely
                return {
                    processedPrompt: null,
                    isAllowed: false,
                    action: "BLOCK",
                    reason: `High-risk prompt blocked: ${analysis.reason}`,
                };
            default:
                return {
                    processedPrompt: prompt,
                    isAllowed: true,
                    action: "ALLOW",
                    reason: "Default allow",
                };
        }
    }
    /**
     * Mask sensitive data in prompt
     */
    maskSensitiveData(prompt, entities) {
        let maskedPrompt = prompt;
        for (const entity of entities) {
            const placeholder = `[${entity.type}]`;
            maskedPrompt = maskedPrompt.replace(entity.value, placeholder);
        }
        return maskedPrompt;
    }
}
exports.LLMGuard = LLMGuard;
// Export singleton instance
exports.llmGuard = new LLMGuard();
//# sourceMappingURL=llmGuard.js.map