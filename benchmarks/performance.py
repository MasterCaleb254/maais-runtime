"""Simple reproducible benchmark for policy evaluation latency.

This script measures `PolicyEngine.evaluate` latency using a sample
`ActionRequest`. It is intentionally lightweight so contributors can
reproduce the README metrics locally.
"""
import time
import tempfile
import yaml
from pathlib import Path

from core.engine.policy_engine import PolicyEngine
from core.models import ActionRequest, ActionType


def create_sample_policy(path: Path):
    sample = {
        "policies": [
            {
                "id": "deny_external_http",
                "applies_to": ["tool_call", "api_call", "network_request"],
                "condition": {"target": {"pattern": "https?:\\/\\/.*"}},
                "decision": "DENY",
                "reason": "Block external HTTP calls",
                "priority": 10
            }
        ]
    }

    with open(path, 'w') as f:
        yaml.safe_dump(sample, f)


def run(iterations: int = 1000):
    # Ensure a policy file exists for the engine to load
    with tempfile.NamedTemporaryFile(prefix="policies_", suffix=".yaml", delete=False) as tf:
        temp_policy = Path(tf.name)
    create_sample_policy(temp_policy)

    engine = PolicyEngine(str(temp_policy))

    action = ActionRequest(
        agent_id="bench_agent",
        action_type=ActionType.TOOL_CALL,
        target="https://example.com/collect",
        parameters={"data": "x"},
        declared_goal="collect data"
    )

    start = time.time()
    denied = 0
    for _ in range(iterations):
        p = engine.evaluate(action)
        if p:
            denied += 1
    total = time.time() - start

    avg_ms = (total / iterations) * 1000.0
    print(f"Iterations: {iterations}")
    print(f"Total time: {total:.4f}s, average: {avg_ms:.3f} ms")
    print(f"Denied count: {denied}")


if __name__ == "__main__":
    run(1000)
