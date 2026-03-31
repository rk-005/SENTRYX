import { DetectedEntity, EntityType } from "../types";

export class RegexDetector {
  private patterns: Record<EntityType, RegExp> = {
    EMAIL: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
    PHONE: /\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b/g,
    API_KEY: /(?:api[_-]?key|apikey|api_token|access_token)[=:\s]+['\"]?([A-Za-z0-9_\-]{20,})['\"]?/gi,
    CREDIT_CARD: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g,
    PASSWORD: /(?:password|passwd|pwd)[=:\s]+['"]?([^'";\s]+)['"]?/gi,
    SECRET: /(?:secret|api_secret|client_secret)[=:\s]+['"]?([A-Za-z0-9_\-]{20,})['"]?/gi,
    TOKEN: /(?:token|auth_token|bearer)[=:\s]+['"]?([A-Za-z0-9_\-]{20,})['"]?/gi,
  };

  detect(text: string): DetectedEntity[] {
    const entities: DetectedEntity[] = [];

    for (const [type, pattern] of Object.entries(this.patterns)) {
      let match;
      while ((match = pattern.exec(text)) !== null) {
        entities.push({
          type: type as EntityType,
          value: match[0],
          confidence: 0.95,
          position: match.index,
        });
      }
    }

    return entities;
  }
}