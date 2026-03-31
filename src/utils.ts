/**
 * Utility functions for OpenEnv Security
 */

import { DetectedEntity } from "./types";
import { CONFIG } from "./config";

/**
 * Calculate Shannon entropy of a string
 * Used to detect obfuscation
 */
export function calculateEntropy(text: string): number {
  const length = text.length;
  const frequencies: { [key: string]: number } = {};

  for (const char of text) {
    frequencies[char] = (frequencies[char] || 0) + 1;
  }

  let entropy = 0;
  for (const freq of Object.values(frequencies)) {
    const p = freq / length;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

/**
 * Check if text contains obfuscation patterns
 */
export function isObfuscated(text: string): boolean {
  const entropy = calculateEntropy(text);
  return entropy > 5.5; // High entropy indicates possible obfuscation
}

/**
 * Remove duplicates from entity array
 */
export function deduplicateEntities(entities: DetectedEntity[]): DetectedEntity[] {
  const seen = new Set<string>();
  return entities.filter((entity) => {
    const key = `${entity.type}:${entity.value}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

/**
 * Sort entities by risk level
 */
export function sortEntitiesByRisk(entities: DetectedEntity[]): DetectedEntity[] {
  const scoreMap: { [key: string]: number } = CONFIG.ENTITY_SCORES as any;
  return [...entities].sort((a, b) => {
    const scoreA = scoreMap[a.type] || 0;
    const scoreB = scoreMap[b.type] || 0;
    return scoreB - scoreA;
  });
}

/**
 * Format risk score as human-readable text
 */
export function formatRiskScore(score: number): string {
  if (score < 20) return "Very Low";
  if (score < 40) return "Low";
  if (score < 60) return "Medium";
  if (score < 80) return "High";
  return "Very High";
}

/**
 * Validate action string
 */
export function isValidAction(action: string): boolean {
  return ["ALLOW", "MASK", "BLOCK", "REWRITE"].includes(action);
}

/**
 * Get action description
 */
export function getActionDescription(action: string): string {
  const descriptions: { [key: string]: string } = {
    ALLOW: "Allow the prompt to proceed without modification",
    MASK: "Mask sensitive data in the prompt",
    BLOCK: "Block the prompt from being sent to LLM",
    REWRITE: "Rewrite the prompt to remove sensitive content",
  };
  return descriptions[action] || "Unknown action";
}

/**
 * Calculate similarity between two strings
 * Used for pattern matching
 */
export function stringSimilarity(str1: string, str2: string): number {
  const longer = str1.length > str2.length ? str1 : str2;
  const shorter = str1.length > str2.length ? str2 : str1;

  if (longer.length === 0) {
    return 1.0;
  }

  const editDistance = getEditDistance(longer, shorter);
  return (longer.length - editDistance) / longer.length;
}

/**
 * Calculate Levenshtein distance
 */
function getEditDistance(str1: string, str2: string): number {
  const costs: number[] = [];

  for (let i = 0; i <= str1.length; i++) {
    let lastValue = i;
    for (let j = 0; j <= str2.length; j++) {
      if (i === 0) {
        costs[j] = j;
      } else if (j > 0) {
        let newValue = costs[j - 1];
        if (str1.charAt(i - 1) !== str2.charAt(j - 1)) {
          newValue = Math.min(Math.min(newValue, lastValue), costs[j]) + 1;
        }
        costs[j - 1] = lastValue;
        lastValue = newValue;
      }
    }
    if (i > 0) {
      costs[str2.length] = lastValue;
    }
  }

  return costs[str2.length];
}

/**
 * Extract email domain
 */
export function extractEmailDomain(email: string): string {
  const parts = email.split("@");
  return parts.length > 1 ? parts[1] : "";
}

/**
 * Check if domain is suspicious
 */
export function isSuspiciousDomain(domain: string): boolean {
  const suspiciousDomains = [
    "tempmail",
    "guerrillamail",
    "10minutemail",
    "mailinator",
    "throwaway",
  ];
  return suspiciousDomains.some((sd) => domain.toLowerCase().includes(sd));
}

/**
 * Format timestamp to readable string
 */
export function formatTimestamp(ms: number): string {
  return new Date(ms).toISOString();
}

/**
 * Deep clone object
 */
export function deepClone<T>(obj: T): T {
  if (obj === null || typeof obj !== "object") {
    return obj;
  }

  if (obj instanceof Date) {
    return new Date(obj.getTime()) as any;
  }

  if (obj instanceof Array) {
    return obj.map((item) => deepClone(item)) as any;
  }

  if (obj instanceof Object) {
    const clonedObj: any = {};
    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        clonedObj[key] = deepClone((obj as any)[key]);
      }
    }
    return clonedObj;
  }

  return obj;
}

/**
 * Batch array into chunks
 */
export function batchArray<T>(array: T[], batchSize: number): T[][] {
  const batches: T[][] = [];
  for (let i = 0; i < array.length; i += batchSize) {
    batches.push(array.slice(i, i + batchSize));
  }
  return batches;
}