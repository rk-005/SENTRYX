import { EnvironmentState, Action } from "./types";
/**
 * LLM Guard: Prevents unsafe prompts from reaching the LLM
 */
export declare class LLMGuard {
    /**
     * Check if prompt is safe before sending to LLM
     */
    checkPrompt(prompt: string): Promise<{
        isSafe: boolean;
        decision: Action;
        state: EnvironmentState;
        reason: string;
        riskScore: number;
    }>;
    /**
     * Process prompt based on risk level
     */
    processPrompt(prompt: string): Promise<{
        processedPrompt: string | null;
        isAllowed: boolean;
        action: Action;
        reason: string;
    }>;
    /**
     * Mask sensitive data in prompt
     */
    private maskSensitiveData;
}
export declare const llmGuard: LLMGuard;
//# sourceMappingURL=llmGuard.d.ts.map