"""Test all HTTP endpoints of the server."""
import requests
import json

BASE = "http://localhost:7860"

def test_endpoint(name, method, url, data=None):
    print(f"\n--- {name} ---")
    if method == "GET":
        r = requests.get(url, timeout=10)
    else:
        r = requests.post(url, json=data or {}, timeout=10)
    print(f"  Status: {r.status_code}")
    body = r.json()
    print(f"  Response: {json.dumps(body, indent=2)[:500]}")
    assert r.status_code == 200, f"Expected 200, got {r.status_code}"
    return body

# 1. Root
test_endpoint("Root", "GET", f"{BASE}/")

# 2. Tasks
test_endpoint("List Tasks", "GET", f"{BASE}/tasks")

# 3. Reset (default task)
obs = test_endpoint("Reset (default)", "POST", f"{BASE}/reset", {})

# 4. Reset (specific task)
obs = test_endpoint("Reset (easy)", "POST", f"{BASE}/reset", {"task": "simple_pii_detection"})

# 5. Step
result = test_endpoint("Step (ALLOW)", "POST", f"{BASE}/step", {"action_type": "ALLOW"})

# 6. Step again
result = test_endpoint("Step (BLOCK)", "POST", f"{BASE}/step", {"action_type": "BLOCK"})

# 7. State
test_endpoint("Get State", "GET", f"{BASE}/state")

# 8. Run full episode
print("\n--- Full Episode ---")
obs = requests.post(f"{BASE}/reset", json={"task": "simple_pii_detection"}).json()
done = False
step_count = 0
total_reward = 0

while not done:
    step_count += 1
    threat = obs.get("threat_level", "SAFE")
    if threat == "CRITICAL":
        action = "BLOCK"
    elif threat == "WARNING":
        action = "MASK"
    else:
        action = "ALLOW"

    result = requests.post(f"{BASE}/step", json={"action_type": action}).json()
    reward = result["reward"]
    done = result["done"]
    total_reward += reward
    obs = result["observation"]
    print(f"  Step {step_count}: {action} -> reward={reward:.2f}, done={done}")

print(f"  Total reward: {total_reward:.2f}")
if result.get("info", {}).get("final_score"):
    print(f"  Final score: {result['info']['final_score']:.3f}")

# 9. Test medium task
print("\n--- Medium Task Episode ---")
obs = requests.post(f"{BASE}/reset", json={"task": "threat_classification"}).json()
done = False
step_count = 0
while not done:
    step_count += 1
    threat = obs.get("threat_level", "SAFE")
    action = {"CRITICAL": "BLOCK", "WARNING": "MASK"}.get(threat, "ALLOW")
    result = requests.post(f"{BASE}/step", json={"action_type": action}).json()
    done = result["done"]
    obs = result["observation"]
    print(f"  Step {step_count}: {action} -> reward={result['reward']:.2f}")
if result.get("info", {}).get("final_score"):
    print(f"  Final score: {result['info']['final_score']:.3f}")

# 10. Test hard task
print("\n--- Hard Task Episode ---")
obs = requests.post(f"{BASE}/reset", json={"task": "multi_step_attack"}).json()
done = False
step_count = 0
while not done:
    step_count += 1
    threat = obs.get("threat_level", "SAFE")
    action = {"CRITICAL": "BLOCK", "WARNING": "MASK"}.get(threat, "ALLOW")
    result = requests.post(f"{BASE}/step", json={"action_type": action}).json()
    done = result["done"]
    obs = result["observation"]
    print(f"  Step {step_count}: {action} -> reward={result['reward']:.2f}")
if result.get("info", {}).get("final_score"):
    print(f"  Final score: {result['info']['final_score']:.3f}")

print("\n" + "=" * 50)
print("ALL HTTP ENDPOINT TESTS PASSED!")
print("=" * 50)
