"""Quick smoke test for the OpenEnv Security Environment."""

from env import SecurityEnv
from models import Action, ActionType
from tasks import ALL_TASKS, TaskGrader

env = SecurityEnv()

# Test 1: Reset
print("=== Test 1: Reset ===")
obs = env.reset("simple_pii_detection")
print(f"  Prompt: {obs.prompt[:60]}")
print(f"  Risk: {obs.risk_score}, Threat: {obs.threat_level}")
print(f"  Step: {obs.step_number}/{obs.total_steps}")
print("  PASS")

# Test 2: Step
print("\n=== Test 2: Step ===")
result = env.step(Action(action_type=ActionType.ALLOW))
print(f"  Reward: {result.reward}, Done: {result.done}")
print(f"  Next prompt: {result.observation.prompt[:60]}")
print("  PASS")

# Test 3: State
print("\n=== Test 3: State ===")
state = env.state()
print(f"  Step: {state.step_number}/{state.total_steps}")
print(f"  Cumulative reward: {state.cumulative_reward}")
print(f"  History entries: {len(state.history)}")
print("  PASS")

# Test 4: All tasks exist
print("\n=== Test 4: All Tasks ===")
for name, task in ALL_TASKS.items():
    print(f"  {name} ({task.difficulty}): {len(task.scenarios)} scenarios")
print("  PASS")

# Test 5: Run full episode on easy task
print("\n=== Test 5: Full Episode (easy) ===")
obs = env.reset("simple_pii_detection")
actions_taken = []
rewards = []
step = 0
while True:
    step += 1
    # Use a simple heuristic agent
    if obs.threat_level.value == "CRITICAL":
        action = ActionType.BLOCK
    elif obs.threat_level.value == "WARNING":
        action = ActionType.MASK
    else:
        action = ActionType.ALLOW

    result = env.step(Action(action_type=action))
    actions_taken.append(action)
    rewards.append(result.reward)
    print(f"  Step {step}: {action.value} -> reward={result.reward:.2f}, done={result.done}")

    if result.done:
        score = result.info.get("final_score", 0)
        print(f"  Final score: {score:.3f}")
        break
    obs = result.observation

print("  PASS")

# Test 6: Grader
print("\n=== Test 6: Grader ===")
for task_name in ALL_TASKS:
    task = ALL_TASKS[task_name]
    grader = TaskGrader(task)

    # Perfect agent
    perfect = [s.expected_action for s in task.scenarios]
    score = grader.grade(perfect)
    print(f"  {task_name} perfect score: {score:.3f}")
    assert score == 1.0, f"Perfect score should be 1.0, got {score}"

    # Worst agent (all ALLOW)
    worst = [ActionType.ALLOW] * len(task.scenarios)
    score = grader.grade(worst)
    print(f"  {task_name} all-ALLOW score: {score:.3f}")
    assert 0.0 <= score <= 1.0, f"Score out of range: {score}"
print("  PASS")

# Test 7: Reward range
print("\n=== Test 7: Reward Range ===")
for action in ActionType:
    for risk in [0, 20, 40, 55, 70, 90, 100]:
        from reward_engine import RewardEngine
        eng = RewardEngine()
        r, _, _ = eng.calculate(action, risk)
        assert -1.0 <= r <= 1.0, f"Reward {r} out of range for {action} at risk {risk}"
print("  All rewards in [-1.0, 1.0] range")
print("  PASS")

print("\n" + "=" * 50)
print("ALL 7 TESTS PASSED!")
print("=" * 50)
