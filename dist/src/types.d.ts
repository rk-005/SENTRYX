/**
 * Type definitions for OpenEnv Security
 */
export type Sensitivity = "LOW" | "MEDIUM" | "HIGH";
export type ThreatLevel = "SAFE" | "WARNING" | "CRITICAL";
export type Action = "ALLOW" | "MASK" | "BLOCK" | "REWRITE";
export type AttackType = "NORMAL" | "CREDENTIAL_EXFILTRATION" | "API_KEY_LEAK" | "PROMPT_INJECTION";
export type EntityType = "EMAIL" | "PHONE" | "API_KEY" | "CREDIT_CARD" | "PASSWORD" | "SECRET" | "TOKEN";
/**
 * Detected entity in a prompt
 */
export interface DetectedEntity {
    type: EntityType;
    value: string;
    confidence: number;
    position: number;
}
/**
 * History entry for each step
 */
export interface HistoryEntry {
    prompt: string;
    action: Action;
    risk_score: number;
    timestamp: number;
    detected_entities: DetectedEntity[];
}
/**
 * Environment state at any point in time
 */
export interface EnvironmentState {
    prompt: string;
    risk_score: number;
    threat_level: ThreatLevel;
    sensitivity: Sensitivity;
    last_action: Action | null;
    detected_entities: DetectedEntity[];
    attack_type: AttackType;
    reason: string;
    episode_reward: number;
    history: HistoryEntry[];
    timestamp: number;
}
/**
 * Response from step function
 */
export interface StepResponse {
    state: EnvironmentState;
    reward: number;
    done: boolean;
}
/**
 * Reward metrics tracking
 */
export interface RewardMetrics {
    correct_detection: number;
    over_blocking_penalty: number;
    missed_detection_penalty: number;
    context_boost: number;
}
//# sourceMappingURL=types.d.ts.map