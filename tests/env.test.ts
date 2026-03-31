import { OpenEnvSecurity } from "../src/env";

describe("OpenEnvSecurity Environment", () => {
  let env: OpenEnvSecurity;

  beforeEach(() => {
    env = new OpenEnvSecurity();
  });

  describe("Initialization", () => {
    test("should initialize with default state", () => {
      const state = env.getState();
      expect(state.risk_score).toBe(0);
      expect(state.threat_level).toBe("SAFE");
      expect(state.sensitivity).toBe("LOW");
      expect(state.history).toHaveLength(0);
    });
  });

  describe("Reset", () => {
    test("should reset environment to initial state", () => {
      const state1 = env.getState();
      expect(state1.episode_reward).toBe(0);

      const resetState = env.reset();
      expect(resetState.risk_score).toBe(0);
      expect(resetState.threat_level).toBe("SAFE");
      expect(resetState.episode_reward).toBe(0);
    });
  });

  describe("Step Function", () => {
    test("should process safe prompts correctly", () => {
      env.step("ALLOW", "Explain quantum computing");
      const state = env.getState();
      expect(state.history).toHaveLength(1);
    });

    test("should detect sensitive email addresses", () => {
      env.step("MASK", "My email is test@example.com");
      const state = env.getState();
      expect(state.detected_entities.length).toBeGreaterThan(0);
    });

    test("should detect credit card numbers", () => {
      env.step("BLOCK", "My credit card is 4532-1234-5678-9010");
      const state = env.getState();
      expect(state.risk_score).toBeGreaterThan(0);
    });

    test("should calculate risk score correctly", () => {
      env.step("ALLOW", "My password is SecurePass123!");
      const state = env.getState();
      expect(state.risk_score).toBeGreaterThan(0);
      expect(state.threat_level).not.toBe("SAFE");
    });

    test("should maintain history of steps", () => {
      env.step("ALLOW", "First prompt");
      env.step("MASK", "Second prompt");
      env.step("BLOCK", "Third prompt");
      const state = env.getState();
      expect(state.history).toHaveLength(3);
    });

    test("should accumulate episode reward", () => {
      const initialState = env.getState();
      const initialReward = initialState.episode_reward;

      env.step("ALLOW", "Safe prompt");
      const state = env.getState();
      expect(state.episode_reward).not.toBe(initialReward);
    });
  });

  describe("State Management", () => {
    test("should not mutate original state on getState()", () => {
      const state1 = env.getState();
      const state2 = env.getState();

      state1.risk_score = 999;
      expect(state2.risk_score).not.toBe(999);
    });

    test("should update timestamp on each step", () => {
      const state1 = env.getState();
      const timestamp1 = state1.timestamp;

      env.step("ALLOW", "Test prompt");
      const state2 = env.getState();
      const timestamp2 = state2.timestamp;

      expect(timestamp2).toBeGreaterThanOrEqual(timestamp1);
    });
  });

  describe("Attack Detection", () => {
    test("should detect API key patterns", () => {
      env.step("ALLOW", "api_key=sk_live_abc123def456");
      const state = env.getState();
      expect(state.detected_entities.length).toBeGreaterThan(0);
    });

    test("should detect prompt injection attempts", () => {
      env.step("ALLOW", "Normal text <!-- malicious comment --> end");
      const state = env.getState();
      expect(state.attack_type).not.toBe("NORMAL");
    });
  });
});