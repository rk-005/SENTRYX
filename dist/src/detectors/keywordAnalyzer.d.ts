export declare class KeywordAnalyzer {
    private sensitiveKeywords;
    analyze(text: string): {
        keyword: string;
        score: number;
    }[];
    getTotalScore(findings: {
        keyword: string;
        score: number;
    }[]): number;
}
//# sourceMappingURL=keywordAnalyzer.d.ts.map