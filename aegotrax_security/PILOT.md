# AgentGuard Pilot Guide

This document is for teams running a **limited production pilot**.

---

## 1. Goals of a pilot

- Protect 1–3 real agents (not the whole org on day one)
- Prove block/allow decisions on **your** tools and data patterns
- Collect false-positive feedback and tune `policy.yaml`
- Decide whether to expand

---

## 2. Architecture for pilot

```text
Your Agent  ──►  AgentGuard SDK (or MCP Gateway)
                      │
                      ▼
              Risk Engine (:8000)
                      │
         ┌────────────┼────────────┬─────────────────┐
         ▼            ▼            ▼                 ▼
      policy.yaml  audit.log  audit webhook   approval webhook
```

**Recommended for pilot:** Python SDK (`verify_tool_call` / `@protected_tool`)  
Use MCP Gateway when the agent already speaks MCP and you want a single interception point.

---

## 3. Install on pilot host

### Option A — Docker (recommended)

**Requirements:** Docker Desktop running (Windows/Mac) or Docker Engine (Linux).

```bash
cd agentguard_clean          # or agentguard_pip_ready — folder with docker-compose.yml
docker compose up --build
```

Leave this terminal open. The engine listens on **http://127.0.0.1:8000**.

Verify:

```bash
curl http://127.0.0.1:8000/health
```

Expected: `{"status":"ok",...}`

| Path on host | Purpose |
|--------------|---------|
| `./data/policy.yaml` | Edit policy without rebuilding the image |
| `./data/agentguard_audit.log` | Audit log (created at runtime) |

After editing policy:

```bash
docker compose restart
```

Optional webhook (set in `docker-compose.yml` under `environment`, then restart):

```yaml
AGENTGUARD_AUDIT_WEBHOOK: "https://your-endpoint.example/audit"
```

Stop:

```bash
docker compose down
```

---

### Option B — Local Python (without Docker)

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .
```

Optional hardening:

```bash
export AGENTGUARD_API_KEY="replace-with-long-random-string"
export AGENTGUARD_AUDIT_LOG="/var/log/agentguard/audit.log"
export AGENTGUARD_POLICY_PATH="/etc/agentguard/policy.yaml"
export AGENTGUARD_FAIL_CLOSED=true
export AGENTGUARD_AUDIT_WEBHOOK="https://your-endpoint.example/audit"
```

Start engine:

```bash
python -m agentguard.risk_engine
# or: agentguard-engine
```

Verify:

```bash
curl http://127.0.0.1:8000/health
```

---

## 4. Wire your first agent (SDK)

```python
from agentguard import set_session_context, verify_tool_call, AgentGuardError

SESSION = "pilot-agent-001"
INTENT = "Answer the customer question; do not export data"

set_session_context(SESSION, user_intent=INTENT, agent_id="pilot-bot")

def safe_tool(name: str, arguments: dict):
    decision = verify_tool_call(
        session_id=SESSION,
        agent_id="pilot-bot",
        user_intent=INTENT,
        tool=name,
        arguments=arguments,
        raise_on_block=True,  # raises AgentGuardError on BLOCK / REQUIRE_APPROVAL
    )
    # only runs if ALLOW
    return actually_run(name, arguments)
```

**Critical:** call `verify_tool_call` **before** the real side effect (email, HTTP, DB write).

---

## 5. Tune policy for your environment

Copy the package policy and edit:

```bash
cp $(python -c "import agentguard, pathlib; print(pathlib.Path(agentguard.__file__).parent / 'policy.yaml')") ./policy.yaml
export AGENTGUARD_POLICY_PATH=$PWD/policy.yaml
```

Minimum changes for pilot:

1. `trusted_domains` — your corporate email domains  
2. `trusted_endpoints` — internal APIs that may receive telemetry  
3. `sensitive_tools` — names of **your** tools that read PII / secrets  
4. `sensitive_payload_keywords` — strings that appear in exfil payloads  
5. Thresholds — start stricter (`block: 40`), loosen if FPR is high  

Reload without restart:

```bash
curl -X POST http://127.0.0.1:8000/policy/reload \
  -H "X-API-Key: $AGENTGUARD_API_KEY"
```

---

## 6. Approval path (optional)

Set:

```bash
export AGENTGUARD_APPROVAL_WEBHOOK=https://hooks.your-company.com/agentguard-approval
```

When decision is `REQUIRE_APPROVAL`, the engine POSTs the audit event JSON to that URL.  
Your system can page a human; the tool call itself is **not** executed by AgentGuard.

---

## 7. Success metrics (2–4 week pilot)

| Metric | Target (example) |
|--------|------------------|
| True blocks on known red-team cases | ≥ 95% |
| False positives on normal workflows | ≤ 5% (tune policy) |
| Engine latency P95 | < 50 ms (local network) |
| Coverage | All tool calls of the pilot agents go through verify |

Review `agentguard_audit.log` weekly with security + the agent owners.

---

## 8. Limitations (be explicit with stakeholders)

- Policy is still largely rule/keyword-based (not full LLM judge)
- Session state is in-memory (single engine process); use one instance or add Redis later
- MCP gateway ships demo tools; production agents should use the **SDK** around real tools
- `REQUIRE_APPROVAL` does not pause a human UI out of the box — it notifies + blocks execution

---

## 9. Rollback

- Remove `verify_tool_call` wrappers / stop the gateway
- Engine is passive: if nothing calls it, agents behave as before

---

## 10. Support checklist before kickoff

- [ ] Engine runs under process supervisor  
- [ ] API key set in pilot environment  
- [ ] Custom `policy.yaml` reviewed by security  
- [ ] Audit log path writable and rotated  
- [ ] One happy-path agent + one red-team script validated  
- [ ] Owner for weekly FP review named  

---

## Central audit stream (optional)

Set on the pilot host:

```bash
export AGENTGUARD_AUDIT_WEBHOOK=https://your-endpoint.example/audit
```

Every decision is POSTed as JSON (same fields as each `audit.log` line):

- `event_id`, `timestamp`, `session_id`, `agent_id`
- `tool_name`, `arguments`, `user_intent`
- `risk_score`, `decision`, `reasons`, `attack_path`

Local `audit.log` is still written.

If the webhook is down or slow, decisions continue normally (logging is best-effort, 2s timeout).

### Weekly feedback cadence

1. Review streamed events (or shared `audit.log`)
2. 20–30 min sync: blocked events, false positives, missing rules
3. Update `policy.yaml` together
