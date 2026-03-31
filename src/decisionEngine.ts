import { Action, ThreatLevel, Sensitivity } from "./types";

export class DecisionEngine {
  makeDecision(riskScore: number): Action {
    if (riskScore < 40) return "ALLOW";
    if (riskScore < 70) return "MASK";
    return "BLOCK";
  }

  calculateThreatLevel(riskScore: number): ThreatLevel {
    if (riskScore < 40) return "SAFE";
    if (riskScore < 70) return "WARNING";
    return "CRITICAL";
  }

  calculateSensitivity(riskScore: number): Sensitivity {
    if (riskScore < 35) return "LOW";
    if (riskScore < 70) return "MEDIUM";
    return "HIGH";
  }

  maskSensitiveData(prompt: string, action: Action): string {
    if (action !== "MASK") return prompt;

    let masked = prompt;
    // Simple masking: replace detected patterns with [REDACTED]
    masked = masked.replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, "[EMAIL]");
    masked = masked.replace(/\b(?:\d{4}[-\s]?){3}\d{4}\b/g, "[CREDIT_CARD]");
    masked = masked.replace(/(?:password|passwd)[=:\s]+[^\s;]+/gi, "password=[REDACTED]");

    return masked;
  }
}