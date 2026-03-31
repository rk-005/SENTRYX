/**
 * Configuration constants for OpenEnv Security
 * Centralized settings for all modules
 */
export declare const CONFIG: {
    REGEX_CONFIDENCE_THRESHOLD: number;
    RISK_THRESHOLDS: {
        ALLOW: number;
        MASK: number;
        BLOCK: number;
    };
    ENTITY_SCORES: {
        EMAIL: number;
        PHONE: number;
        API_KEY: number;
        CREDIT_CARD: number;
        PASSWORD: number;
        SECRET: number;
        TOKEN: number;
    };
    CONTEXT_BOOST: {
        EMAIL_PASSWORD: number;
        API_KEY_SECRET: number;
        MULTI_STEP: number;
    };
    REWARDS: {
        CORRECT_BLOCK: number;
        CORRECT_MASK: number;
        CORRECT_ALLOW: number;
        CORRECT_REWRITE: number;
        WRONG_DECISION: number;
        SUBOPTIMAL: number;
    };
    MAX_HISTORY_LENGTH: number;
    HISTORY_RETENTION_SECONDS: number;
    DEBUG_MODE: boolean;
    LOG_LEVEL: string;
};
export declare const SENSITIVE_KEYWORDS: {
    password: number;
    secret: number;
    credentials: number;
    token: number;
    apikey: number;
    private: number;
    confidential: number;
    ssn: number;
    "credit card": number;
    "social security": number;
    encrypt: number;
    decrypt: number;
    private_key: number;
    access_token: number;
    bearer: number;
};
export declare const ATTACK_PATTERNS: {
    CREDENTIAL_EXFILTRATION: {
        history: string;
        current: string;
    }[];
    API_KEY_LEAK: {
        history: string;
        current: string;
    }[];
    PROMPT_INJECTION: string[];
};
//# sourceMappingURL=config.d.ts.map