/**
 * Secure LLM Client
 * Intercepts prompts and filters dangerous content before sending to LLM
 */
export declare class SecureLLMClient {
    /**
     * Send prompt to LLM (with security check)
     */
    sendPrompt(userPrompt: string): Promise<{
        success: boolean;
        response: string | null;
        blocked: boolean;
        reason: string;
    }>;
    /**
     * Call the LLM API
     */
    private callLLM;
}
export declare const secureLLM: SecureLLMClient;
//# sourceMappingURL=secureLLMClient.d.ts.map