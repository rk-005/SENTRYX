import { securityEnv } from "./index";
import { EnvironmentState, Action } from "./types";

/**
 * LLM Guard: Prevents unsafe prompts from reaching the LLM
 */
export class LLMGuard {
  /**
   * Check if prompt is safe before sending to LLM
   */
  public async checkPrompt(prompt: string): Promise<{
    isSafe: boolean;
    decision: Action;
    state: EnvironmentState;
    reason: string;
    riskScore: number;
  }> {
    // Step the environment to analyze the prompt
    const response = securityEnv.step("ALLOW", prompt);
    const state = response.state;

    return {
      isSafe: state.threat_level === "SAFE",
      decision: (state.last_action as Action) || "ALLOW",
      state,
      reason: state.reason,
      riskScore: state.risk_score,
    };
  }

  /**
   * Process prompt based on risk level
   */
  public async processPrompt(prompt: string): Promise<{
    processedPrompt: string | null;
    isAllowed: boolean;
    action: Action;
    reason: string;
  }> {
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
  private maskSensitiveData(prompt: string, entities: any[]): string {
    let maskedPrompt = prompt;

    for (const entity of entities) {
      const placeholder = `[${entity.type}]`;
      maskedPrompt = maskedPrompt.replace(entity.value, placeholder);
    }

    return maskedPrompt;
  }
}

// Export singleton instance
export const llmGuard = new LLMGuard();