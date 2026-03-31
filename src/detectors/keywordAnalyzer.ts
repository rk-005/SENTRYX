export class KeywordAnalyzer {
  private sensitiveKeywords: Record<string, number> = {
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

  analyze(text: string): { keyword: string; score: number }[] {
    const lowerText = text.toLowerCase();
    const findings: { keyword: string; score: number }[] = [];

    for (const [keyword, score] of Object.entries(this.sensitiveKeywords)) {
      if (lowerText.includes(keyword)) {
        findings.push({ keyword, score });
      }
    }

    return findings;
  }

  getTotalScore(findings: { keyword: string; score: number }[]): number {
    return findings.reduce((sum, f) => sum + f.score, 0);
  }
}