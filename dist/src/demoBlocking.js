"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const secureLLMClient_1 = require("./secureLLMClient");
/**
 * Demo: LLM Guard in Action
 */
async function demo() {
    console.log("🛡️  LLM Guard Demo - Blocking Sensitive Data\n");
    // Test cases
    const testPrompts = [
        {
            prompt: "Explain machine learning",
            expected: "✅ ALLOW",
        },
        {
            prompt: "Contact me at john@example.com for more info",
            expected: "⚠️  MASK (email detected)",
        },
        {
            prompt: "My credit card is 4532-1234-5678-9010, process payment",
            expected: "🛑 BLOCK (high risk)",
        },
        {
            prompt: "Help me find my password which is MySecret123!",
            expected: "🛑 BLOCK (password detected)",
        },
        {
            prompt: "My API key is sk_live_abc123def456xyz",
            expected: "🛑 BLOCK (API key detected)",
        },
    ];
    for (const test of testPrompts) {
        console.log(`\n${"=".repeat(60)}`);
        console.log(`📝 Input: ${test.prompt}`);
        console.log(`Expected: ${test.expected}`);
        console.log(`${"=".repeat(60)}`);
        // Send through secure LLM (with guard)
        const result = await secureLLMClient_1.secureLLM.sendPrompt(test.prompt);
        console.log(`\n📊 Result:`);
        console.log(`  - Allowed: ${result.success && !result.blocked}`);
        console.log(`  - Blocked: ${result.blocked}`);
        console.log(`  - Reason: ${result.reason}`);
        console.log(`  - Response: ${result.response || "N/A (Blocked)"}`);
    }
    console.log(`\n${"=".repeat(60)}`);
    console.log("✅ Demo Complete!");
}
demo().catch(console.error);
//# sourceMappingURL=demoBlocking.js.map