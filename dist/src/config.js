"use strict";
/**
 * Configuration constants for OpenEnv Security
 * Centralized settings for all modules
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.ATTACK_PATTERNS = exports.SENSITIVE_KEYWORDS = exports.CONFIG = void 0;
exports.CONFIG = {
    // Detection thresholds
    REGEX_CONFIDENCE_THRESHOLD: 0.95,
    // Risk scoring thresholds
    RISK_THRESHOLDS: {
        ALLOW: 40,
        MASK: 70,
        BLOCK: 100,
    },
    // Entity base scores (used by HeuristicRiskScorer)
    ENTITY_SCORES: {
        EMAIL: 20,
        PHONE: 25,
        API_KEY: 50,
        CREDIT_CARD: 60,
        PASSWORD: 70,
        SECRET: 65,
        TOKEN: 55,
    },
    // Context escalation factors
    CONTEXT_BOOST: {
        EMAIL_PASSWORD: 25,
        API_KEY_SECRET: 20,
        MULTI_STEP: 10,
    },
    // Reward function values
    REWARDS: {
        CORRECT_BLOCK: 1.0,
        CORRECT_MASK: 0.7,
        CORRECT_ALLOW: 0.5,
        CORRECT_REWRITE: 0.8,
        WRONG_DECISION: -1.0,
        SUBOPTIMAL: -0.5,
    },
    // History management
    MAX_HISTORY_LENGTH: 100,
    HISTORY_RETENTION_SECONDS: 3600, // 1 hour
    // Logging
    DEBUG_MODE: false,
    LOG_LEVEL: "INFO", // DEBUG, INFO, WARN, ERROR
};
exports.SENSITIVE_KEYWORDS = {
    password: 30,
    secret: 35,
    credentials: 40,
    token: 25,
    apikey: 35,
    private: 20,
    confidential: 25,
    ssn: 50,
    "credit card": 45,
    "social security": 50,
    encrypt: 15,
    decrypt: 20,
    private_key: 60,
    access_token: 50,
    bearer: 40,
};
exports.ATTACK_PATTERNS = {
    CREDENTIAL_EXFILTRATION: [
        { history: "email", current: "password" },
        { history: "phone", current: "password" },
        { history: "email", current: "send" },
    ],
    API_KEY_LEAK: [
        { history: "api", current: "secret" },
        { history: "api", current: "key" },
    ],
    PROMPT_INJECTION: [
        "ignore",
        "forget",
        "ignore previous",
        "system prompt",
        "override",
        "bypass",
    ],
};
//# sourceMappingURL=config.js.map