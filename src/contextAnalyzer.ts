import { DetectedEntity, AttackType } from "./types";

export class ContextAnalyzer {
  analyzeMultiStepAttacks(
    currentPrompt: string,
    history: Array<{ prompt: string; entities: DetectedEntity[] }>
  ): { attackType: AttackType; escalationFactor: number } {
    let attackType: AttackType = "NORMAL";
    let escalationFactor = 1.0;

    if (history.length === 0) {
      return { attackType, escalationFactor };
    }

    const historyStr = history.map((h) => h.prompt.toLowerCase()).join(" ");
    const currentStr = currentPrompt.toLowerCase();

    // Pattern 1: Email disclosure followed by password request
    if (
      historyStr.includes("email") &&
      (currentStr.includes("password") || currentStr.includes("send password"))
    ) {
      attackType = "CREDENTIAL_EXFILTRATION";
      escalationFactor = 1.5;
    }

    // Pattern 2: API key in history + secret in current
    if (
      historyStr.includes("api") &&
      (currentStr.includes("secret") || currentStr.includes("key"))
    ) {
      attackType = "API_KEY_LEAK";
      escalationFactor = 1.4;
    }

    // Pattern 3: Prompt injection patterns
    if (
      currentStr.includes("ignore") ||
      currentStr.includes("forget") ||
      currentStr.includes("ignore previous") ||
      currentStr.includes("system prompt")
    ) {
      attackType = "PROMPT_INJECTION";
      escalationFactor = 1.3;
    }

    return { attackType, escalationFactor };
  }

  generateReason(
    detectedEntities: DetectedEntity[],
    keywordFindings: { keyword: string; score: number }[],
    contextAttackType: AttackType,
    escalationFactor: number
  ): string {
    const reasons: string[] = [];

    if (detectedEntities.length > 0) {
      const types = detectedEntities.map((e) => e.type).join(", ");
      reasons.push(`Detected entities: ${types}`);
    }

    if (keywordFindings.length > 0) {
      const keywords = keywordFindings.map((k) => k.keyword).join(", ");
      reasons.push(`Sensitive keywords: ${keywords}`);
    }

    if (contextAttackType !== "NORMAL") {
      reasons.push(`Multi-step attack pattern detected: ${contextAttackType}`);
    }

    if (escalationFactor > 1.0) {
      reasons.push(`Context-based escalation (${escalationFactor.toFixed(2)}x)`);
    }

    return reasons.join(" | ");
  }
}