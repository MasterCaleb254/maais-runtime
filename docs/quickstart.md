---
layout: default
title: Quickstart
nav_order: 4
---

# 5-Minute Quickstart

Get MAAIS-Runtime running quickly.

```bash
git clone https://github.com/MasterCaleb254/maais-runtime.git
cd maais-runtime
pip install -r requirements.txt
python -m demo.scenarios.attack_scenarios
```

Open `docs/demo.md` for interactive examples.
# MAAIS-Runtime Quick Start

## Installation

```bash
# Clone repository
git clone https://github.com/MasterCaleb254/maais-runtime.git
cd maais-runtime

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

Quick Demo
Run the complete demo:

bash
python run_demo.py
This will:

Generate attack scenarios to test security policies

Launch a Streamlit dashboard at http://localhost:8501

Show real-time security enforcement

Using MAAIS-Runtime with Your Agents
Basic Usage
python
from core.runtime import get_runtime
from core.models import ActionRequest, ActionType

# Get runtime instance
runtime = get_runtime()

# Create action request
action = ActionRequest(
    agent_id="my_agent",
    action_type=ActionType.TOOL_CALL,
    target="http_request",
    parameters={"url": "https://api.example.com"},
    declared_goal="Fetch data"
)

# Evaluate security
decision = runtime.intercept(action)

if decision.allow:
    print("✅ Action allowed")
else:
    print(f"❌ Action blocked: {decision.explanation}")
LangGraph Integration
python
from core.adapters.langgraph_adapter import secure_tool

@secure_tool(agent_id="data_agent", goal="Process data")
def process_data(data: dict):
    """Secure tool that goes through MAAIS-Runtime"""
    # Your tool logic here
    return transform(data)

# Use in LangGraph
from langgraph.prebuilt import create_react_agent
agent = create_react_agent(tools=[process_data])
Custom Policies
Add to policies/static/security_policies.yaml:

yaml
- id: "custom_rule"
  applies_to: ["tool_call"]
  condition:
    target: "my_tool"
    parameters:
      sensitive_field:
        pattern: ".*secret.*"
  decision: "DENY"
  reason: "Custom security rule"
  priority: 50
Dashboard Features
The Streamlit dashboard provides:

Real-time Monitoring: Live view of agent actions and decisions

Security Analytics: Charts and metrics for blocked/allowed actions

MITRE ATLAS Integration: Mapping to security frameworks

Audit Logs: Immutable, hash-chained event history

Export Capabilities: Download logs and reports

Testing Security Policies
bash
# Run attack scenarios
python -m demo.scenarios.attack_scenarios

# Run unit tests
pytest tests/ -v

# Test specific components
python test_runtime.py
Configuration
Policies: Edit YAML files in policies/static/

CIAA Rules: Configure in core/engine/ciaa_evaluator.py

Accountability: Set agent owners in core/engine/accountability.py

Audit Logs: Configure in core/engine/audit_logger.py

Architecture
text
Agent → ActionRequest → MAAIS Runtime → Decision
                  ↳ Policy Engine (YAML)
                  ↳ CIAA Evaluator
                  ↳ Accountability Resolver
                  ↳ Audit Logger (Immutable)
Security Features
✅ Real-time Interception: No bypass possible

✅ Deterministic Evaluation: Same input → same decision

✅ CIAA Enforcement: Confidentiality, Integrity, Availability, Accountability

✅ MITRE ATLAS Mapping: Industry-standard security framework

✅ Immutable Audit Logs: Hash-chained, tamper-evident

✅ Fail-Closed: No execution without security clearance

text