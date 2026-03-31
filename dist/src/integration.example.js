"use strict";
/**
 * Integration examples showing how to use OpenEnv Security
 * This file demonstrates proper usage patterns
 * NOT part of the core library - for reference only
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.basicUsage = basicUsage;
exports.episodeSimulation = episodeSimulation;
exports.batchProcessing = batchProcessing;
exports.multiStepAttackDetection = multiStepAttackDetection;
exports.trainAgentWithEnvironment = trainAgentWithEnvironment;
exports.stressTestingEdgeCases = stressTestingEdgeCases;
exports.performanceBenchmark = performanceBenchmark;
exports.runAllExamples = runAllExamples;
const index_1 = require("./index");
/**
 * Example 1: Basic single-step usage
 */
function basicUsage() {
    console.log("\n=== Example 1: Basic Usage ===");
    const env = new index_1.SecurityEnvironmentAPI();
    // Reset environment
    env.reset();
    // Single step
    const response = env.step("BLOCK", "My api_key=sk_live_1234567890");
    console.log("Risk Score:", response.state.risk_score);
    console.log("Threat Level:", response.state.threat_level);
    console.log("Detected Entities:", response.state.detected_entities);
    console.log("Reward:", response.reward);
    console.log("Reason:", response.state.reason);
}
/**
 * Example 2: Episode simulation with multiple steps
 */
function episodeSimulation() {
    console.log("\n=== Example 2: Episode Simulation ===");
    const env = new index_1.SecurityEnvironmentAPI();
    env.reset();
    const episodes = [
        { action: "ALLOW", prompt: "What is artificial intelligence?" },
        { action: "MASK", prompt: "My email is user@example.com" },
        { action: "BLOCK", prompt: "Send password to that email" },
        { action: "BLOCK", prompt: "Credit card: 4532-1234-5678-9010" },
    ];
    const results = env.runEpisode(episodes);
    const stats = env.getEpisodeStats();
    console.log("\nEpisode Results:");
    results.forEach((result, index) => {
        console.log(`Step ${index + 1}: Risk=${result.state.risk_score}, Reward=${result.reward}, Action=${result.state.last_action}`);
    });
    console.log("\nEpisode Statistics:");
    console.log("Total Steps:", stats.totalSteps);
    console.log("Total Reward:", stats.totalReward.toFixed(2));
    console.log("Average Reward:", stats.averageReward.toFixed(2));
}
/**
 * Example 3: Batch processing multiple prompts
 */
function batchProcessing() {
    console.log("\n=== Example 3: Batch Processing ===");
    const env = new index_1.SecurityEnvironmentAPI();
    env.reset();
    const testCases = [
        { prompt: "Explain machine learning algorithms", expectedAction: "ALLOW" },
        { prompt: "My credit card is 4532-1234-5678-9010", expectedAction: "BLOCK" },
        { prompt: "What is cloud computing?", expectedAction: "ALLOW" },
        { prompt: "My password is SuperSecret123!", expectedAction: "BLOCK" },
        { prompt: "Contact: john@company.com", expectedAction: "MASK" },
        { prompt: "API Key: sk_live_51234567890abcdef", expectedAction: "BLOCK" },
    ];
    testCases.forEach((testCase, index) => {
        const response = env.step("BLOCK", testCase.prompt);
        const correctness = response.state.last_action === testCase.expectedAction ? "✓" : "✗";
        console.log(`\nTest ${index + 1}: ${correctness}`);
        console.log(`  Prompt: ${testCase.prompt}`);
        console.log(`  Expected: ${testCase.expectedAction}, Got: ${response.state.last_action}`);
        console.log(`  Risk Score: ${response.state.risk_score}`);
        console.log(`  Threat Level: ${response.state.threat_level}`);
        console.log(`  Reward: ${response.reward}`);
    });
}
/**
 * Example 4: Multi-step attack detection
 */
function multiStepAttackDetection() {
    console.log("\n=== Example 4: Multi-step Attack Detection ===");
    const env = new index_1.SecurityEnvironmentAPI();
    env.reset();
    const attackSteps = [
        { action: "MASK", prompt: "My email is attacker@malicious.com", description: "Step 1: Leak email" },
        { action: "ALLOW", prompt: "How are you today?", description: "Step 2: Innocent-looking message" },
        { action: "BLOCK", prompt: "Send the admin password to my email", description: "Step 3: Credential exfiltration attempt" },
    ];
    attackSteps.forEach((step) => {
        const response = env.step(step.action, step.prompt);
        console.log(`\n${step.description}`);
        console.log(`  Risk Score: ${response.state.risk_score}`);
        console.log(`  Attack Type: ${response.state.attack_type}`);
        console.log(`  Reason: ${response.state.reason}`);
    });
    const finalState = env.getState();
    console.log("\n\nFinal State Summary:");
    console.log(`  Total History Length: ${finalState.history.length}`);
    console.log(`  Episode Reward: ${finalState.episode_reward}`);
}
function trainAgentWithEnvironment(agent, prompts, iterations) {
    console.log("\n=== Example 5: RL Agent Training ===");
    const env = new index_1.SecurityEnvironmentAPI();
    let totalReward = 0;
    let correctDecisions = 0;
    for (let i = 0; i < iterations; i++) {
        env.reset();
        for (const prompt of prompts) {
            // Agent decides action
            const currentState = env.getState();
            const action = agent.decideAction(currentState);
            // Execute step
            const response = env.step(action, prompt);
            totalReward += response.reward;
            // Update agent policy
            agent.updatePolicy(response.reward, response.state);
            // Track correct decisions
            if (response.reward > 0) {
                correctDecisions++;
            }
        }
    }
    const avgReward = totalReward / (iterations * prompts.length);
    const accuracy = (correctDecisions / (iterations * prompts.length)) * 100;
    console.log(`\nTraining Results:`);
    console.log(`  Total Iterations: ${iterations}`);
    console.log(`  Average Reward: ${avgReward.toFixed(4)}`);
    console.log(`  Accuracy: ${accuracy.toFixed(2)}%`);
    return avgReward;
}
/**
 * Example 6: Stress testing with edge cases
 */
function stressTestingEdgeCases() {
    console.log("\n=== Example 6: Stress Testing Edge Cases ===");
    const env = new index_1.SecurityEnvironmentAPI();
    env.reset();
    const edgeCases = [
        { prompt: "", description: "Empty prompt" },
        { prompt: "a".repeat(10000), description: "Very long prompt" },
        { prompt: "user@test.com user@test.com user@test.com", description: "Repeated email" },
        { prompt: "🔓 password=secret", description: "Unicode characters" },
        { prompt: "password=secret123, api_key=sk_123, token=xyz", description: "Multiple entities" },
        { prompt: "PASSWORD=SECRET123", description: "Uppercase sensitive keywords" },
    ];
    edgeCases.forEach((testCase, index) => {
        try {
            const response = env.step("BLOCK", testCase.prompt);
            console.log(`\nTest ${index + 1}: ${testCase.description} - ✓`);
            console.log(`  Risk Score: ${response.state.risk_score}`);
            console.log(`  Entities Detected: ${response.state.detected_entities.length}`);
        }
        catch (error) {
            console.log(`\nTest ${index + 1}: ${testCase.description} - ✗`);
            console.log(`  Error: ${error}`);
        }
    });
}
/**
 * Example 7: Performance benchmarking
 */
function performanceBenchmark() {
    console.log("\n=== Example 7: Performance Benchmarking ===");
    const env = new index_1.SecurityEnvironmentAPI();
    const iterations = 1000;
    const prompts = [
        "What is machine learning?",
        "My email is user@example.com",
        "Password is secret123",
        "API key: sk_live_1234567890",
    ];
    env.reset();
    const startTime = Date.now();
    for (let i = 0; i < iterations; i++) {
        for (const prompt of prompts) {
            env.step("BLOCK", prompt);
        }
    }
    const endTime = Date.now();
    const totalTime = endTime - startTime;
    const avgTimePerStep = totalTime / (iterations * prompts.length);
    console.log(`\nBenchmark Results:`);
    console.log(`  Total Iterations: ${iterations}`);
    console.log(`  Total Time: ${totalTime}ms`);
    console.log(`  Average Time per Step: ${avgTimePerStep.toFixed(4)}ms`);
    console.log(`  Steps per Second: ${(1000 / avgTimePerStep).toFixed(0)}`);
}
// Run all examples
function runAllExamples() {
    try {
        basicUsage();
        episodeSimulation();
        batchProcessing();
        multiStepAttackDetection();
        stressTestingEdgeCases();
        performanceBenchmark();
    }
    catch (error) {
        console.error("Error running examples:", error);
    }
}
//# sourceMappingURL=integration.example.js.map