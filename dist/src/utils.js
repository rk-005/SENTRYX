"use strict";
/**
 * Utility functions for OpenEnv Security
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.calculateEntropy = calculateEntropy;
exports.isObfuscated = isObfuscated;
exports.deduplicateEntities = deduplicateEntities;
exports.sortEntitiesByRisk = sortEntitiesByRisk;
exports.formatRiskScore = formatRiskScore;
exports.isValidAction = isValidAction;
exports.getActionDescription = getActionDescription;
exports.stringSimilarity = stringSimilarity;
exports.extractEmailDomain = extractEmailDomain;
exports.isSuspiciousDomain = isSuspiciousDomain;
exports.formatTimestamp = formatTimestamp;
exports.deepClone = deepClone;
exports.batchArray = batchArray;
const config_1 = require("./config");
/**
 * Calculate Shannon entropy of a string
 * Used to detect obfuscation
 */
function calculateEntropy(text) {
    const length = text.length;
    const frequencies = {};
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
function isObfuscated(text) {
    const entropy = calculateEntropy(text);
    return entropy > 5.5; // High entropy indicates possible obfuscation
}
/**
 * Remove duplicates from entity array
 */
function deduplicateEntities(entities) {
    const seen = new Set();
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
function sortEntitiesByRisk(entities) {
    const scoreMap = config_1.CONFIG.ENTITY_SCORES;
    return [...entities].sort((a, b) => {
        const scoreA = scoreMap[a.type] || 0;
        const scoreB = scoreMap[b.type] || 0;
        return scoreB - scoreA;
    });
}
/**
 * Format risk score as human-readable text
 */
function formatRiskScore(score) {
    if (score < 20)
        return "Very Low";
    if (score < 40)
        return "Low";
    if (score < 60)
        return "Medium";
    if (score < 80)
        return "High";
    return "Very High";
}
/**
 * Validate action string
 */
function isValidAction(action) {
    return ["ALLOW", "MASK", "BLOCK", "REWRITE"].includes(action);
}
/**
 * Get action description
 */
function getActionDescription(action) {
    const descriptions = {
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
function stringSimilarity(str1, str2) {
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
function getEditDistance(str1, str2) {
    const costs = [];
    for (let i = 0; i <= str1.length; i++) {
        let lastValue = i;
        for (let j = 0; j <= str2.length; j++) {
            if (i === 0) {
                costs[j] = j;
            }
            else if (j > 0) {
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
function extractEmailDomain(email) {
    const parts = email.split("@");
    return parts.length > 1 ? parts[1] : "";
}
/**
 * Check if domain is suspicious
 */
function isSuspiciousDomain(domain) {
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
function formatTimestamp(ms) {
    return new Date(ms).toISOString();
}
/**
 * Deep clone object
 */
function deepClone(obj) {
    if (obj === null || typeof obj !== "object") {
        return obj;
    }
    if (obj instanceof Date) {
        return new Date(obj.getTime());
    }
    if (obj instanceof Array) {
        return obj.map((item) => deepClone(item));
    }
    if (obj instanceof Object) {
        const clonedObj = {};
        for (const key in obj) {
            if (obj.hasOwnProperty(key)) {
                clonedObj[key] = deepClone(obj[key]);
            }
        }
        return clonedObj;
    }
    return obj;
}
/**
 * Batch array into chunks
 */
function batchArray(array, batchSize) {
    const batches = [];
    for (let i = 0; i < array.length; i += batchSize) {
        batches.push(array.slice(i, i + batchSize));
    }
    return batches;
}
//# sourceMappingURL=utils.js.map