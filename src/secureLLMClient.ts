import { llmGuard } from "./llmGuard";

/**
 * Secure LLM Client
 * Intercepts prompts and filters dangerous content before sending to LLM
 */
export class SecureLLMClient {
  /**
   * Send prompt to LLM (with security check)
   */
  public async sendPrompt(userPrompt: string): Promise<{
    success: boolean;
    response: string | null;
    blocked: boolean;
    reason: string;
  }> {
    console.log(`📝 User Prompt: ${userPrompt}`);

    // Step 1: Security check
    const processedResult = await llmGuard.processPrompt(userPrompt);

    if (!processedResult.isAllowed) {
      // 🛑 BLOCKED: Don't send to LLM
      return {
        success: false,
        response: null,
        blocked: true,
        reason: processedResult.reason,
      };
    }

    // Step 2: Send to LLM (after security filtering)
    const finalPrompt = processedResult.processedPrompt;
    
    // Ensure finalPrompt is not null
    if (!finalPrompt) {
      return {
        success: false,
        response: null,
        blocked: true,
        reason: "Processed prompt is null",
      };
    }

    console.log(`✅ Processed Prompt: ${finalPrompt}`);
    console.log(`📌 Action: ${processedResult.action}`);

    try {
      const response = await this.callLLM(finalPrompt);
      return {
        success: true,
        response,
        blocked: false,
        reason: "Prompt passed security checks",
      };
    } catch (error) {
      return {
        success: false,
        response: null,
        blocked: false,
        reason: `LLM Error: ${error}`,
      };
    }
  }

  /**
   * Call the LLM API
   */
  private async callLLM(prompt: string): Promise<string> {
    // Mock response for demo (replace with actual API calls)
    return `LLM Response to: ${prompt}`;

    /* Real implementations:
    
    // OpenAI
    if (this.llmProvider === "openai") {
      const response = await fetch("https://api.openai.com/v1/chat/completions", {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${this.apiKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          model: "gpt-4",
          messages: [{ role: "user", content: prompt }],
        }),
      });
      const data = await response.json();
      return data.choices[0].message.content;
    }

    // Claude
    if (this.llmProvider === "claude") {
      const response = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: {
          "x-api-key": this.apiKey,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          model: "claude-3-opus",
          max_tokens: 1024,
          messages: [{ role: "user", content: prompt }],
        }),
      });
      const data = await response.json();
      return data.content[0].text;
    }
    */
  }
}

export const secureLLM = new SecureLLMClient();