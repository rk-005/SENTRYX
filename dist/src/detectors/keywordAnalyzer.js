"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.KeywordAnalyzer = void 0;
class KeywordAnalyzer {
    constructor() {
        this.sensitiveKeywords = {
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
        };
    }
    analyze(text) {
        const lowerText = text.toLowerCase();
        const findings = [];
        for (const [keyword, score] of Object.entries(this.sensitiveKeywords)) {
            if (lowerText.includes(keyword)) {
                findings.push({ keyword, score });
            }
        }
        return findings;
    }
    getTotalScore(findings) {
        return findings.reduce((sum, f) => sum + f.score, 0);
    }
}
exports.KeywordAnalyzer = KeywordAnalyzer;
//# sourceMappingURL=keywordAnalyzer.js.map