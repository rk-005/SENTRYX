/**
 * Utility functions for OpenEnv Security
 */
import { DetectedEntity } from "./types";
/**
 * Calculate Shannon entropy of a string
 * Used to detect obfuscation
 */
export declare function calculateEntropy(text: string): number;
/**
 * Check if text contains obfuscation patterns
 */
export declare function isObfuscated(text: string): boolean;
/**
 * Remove duplicates from entity array
 */
export declare function deduplicateEntities(entities: DetectedEntity[]): DetectedEntity[];
/**
 * Sort entities by risk level
 */
export declare function sortEntitiesByRisk(entities: DetectedEntity[]): DetectedEntity[];
/**
 * Format risk score as human-readable text
 */
export declare function formatRiskScore(score: number): string;
/**
 * Validate action string
 */
export declare function isValidAction(action: string): boolean;
/**
 * Get action description
 */
export declare function getActionDescription(action: string): string;
/**
 * Calculate similarity between two strings
 * Used for pattern matching
 */
export declare function stringSimilarity(str1: string, str2: string): number;
/**
 * Extract email domain
 */
export declare function extractEmailDomain(email: string): string;
/**
 * Check if domain is suspicious
 */
export declare function isSuspiciousDomain(domain: string): boolean;
/**
 * Format timestamp to readable string
 */
export declare function formatTimestamp(ms: number): string;
/**
 * Deep clone object
 */
export declare function deepClone<T>(obj: T): T;
/**
 * Batch array into chunks
 */
export declare function batchArray<T>(array: T[], batchSize: number): T[][];
//# sourceMappingURL=utils.d.ts.map