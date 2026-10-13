# Aegotrax

**Runtime protection for AI agents — checks tool calls before they run.**

Public site: [https://aegotrax.com](https://aegotrax.com)  
Repository: [https://github.com/aegotrax-dev/aegotrax](https://github.com/aegotrax-dev/aegotrax)

This repo is the open **pilot runtime**. Package name: `aegotrax`.

---

# 🛡️ Aegotrax v0.2.6

Intercept tool calls, evaluate **server-side session intent + scope**, apply **read budgets**, **sensitivity ceiling**, **tool risk classes**, and **block / require human approval** before sensitive actions run.

| Integration | Use when |
|-------------|----------|
| **Python SDK** | You call tools from your own code (`verify_tool_call` / `@protected_tool`) |
| **MCP Gateway** | The agent already speaks MCP and you want one interception point |

### What’s new in 0.2.6
- **Session exhaust** — after a read-budget exceed, the session can close; further calls `BLOCK` until a new `/session`
- **Sensitivity ceiling** — monotonic session tag after sensitive reads; outbound tools are gated on the ceiling
- **Tool classes** — `open_risk` / `reduce_risk` in policy; unclassified tools default to **open_risk** (fail-closed)
- **Approval delivery** — `POST /approval/delivery` with `delivered` | `delivery_uncertain` | `failed`; new permits for the same tool+args are held while delivery is unresolved

### From 0.2.5 / 0.2.4
- Scoped session intent (`allowed_tools` / `denied_tools` on `/session`)
- Cumulative read budgets on `sensitive_tools`
- Human-approval token queue (single-use resume)
- Server-side intent only (client cannot spoof `user_intent` on verify)
- Hostname allowlists, SSRF/IMDS guards, MCP schema pinning + drift detection

---

## Quick start

```bash
git clone https://github.com/aegotrax-dev/aegotrax.git
cd aegotrax
python -m venv .venv
# Windows: .venv\Scripts\activate
source .venv/bin/activate
pip install .

export AEGOTRAX_API_KEY=test-key-change-me   # Windows: set AEGOTRAX_API_KEY=...
aegotrax-engine
# other terminal:
curl -s http://127.0.0.1:8000/health   # → version 0.2.6
python examples/sdk_pilot_example.py
```

Docker:

```bash
docker compose up --build
```

---

## Core controls

| Control | Where | Behavior |
|---------|--------|----------|
| Session intent + scope | `POST /session` | Host-declared envelope; agent does not write the boundary |
| Read budgets | `policy.yaml` → `read_budgets` | Count sensitive reads; exceed → approval/block + optional **end session** |
| Sensitivity ceiling | `policy.yaml` → `sensitivity_ceiling` | Raise tag on sensitive reads; gate outbound |
| Tool classes | `policy.yaml` → `tool_classes` | `open_risk` elevates to approval/block; default fail-closed |
| Human approval | `REQUIRE_APPROVAL` → `/approval/decide` → resume | Single-use token bound to tool+args fingerprint |
| Delivery tracking | `POST /approval/delivery` | Avoid quiet double-permits when side effect is uncertain |
| Schema pinning | MCP path | Drift / poisoned tool descriptions |

Example `policy.yaml` fragments:

```yaml
read_budgets:
  default_max_calls: 20
  on_exceed: REQUIRE_APPROVAL
  end_session_on_exceed: true
  tools:
    read_db:
      max_calls: 10

sensitivity_ceiling:
  enabled: true
  raise_to: 1
  outbound_min_ceiling: 1
  on_outbound: REQUIRE_APPROVAL

tool_classes:
  default: open_risk
  reduce_risk: [read_db, read_document, list_users]
  open_risk: [http_post, send_email, run_shell]
  open_risk_min_decision: REQUIRE_APPROVAL
```

---

## Demos

```bash
# offline
python examples/security_hardening_test.py
python examples/schema_pinning_demo.py

# engine required + AEGOTRAX_API_KEY
python examples/scoped_intent_demo.py
python examples/read_budget_demo.py
python examples/sensitivity_ceiling_demo.py
python examples/approval_flow_demo.py
python examples/sdk_pilot_example.py
```

---

## Threats covered (pilot)

- In-scope tool abuse (sequence / volume), not only static allowlists
- Client spoofing of `user_intent`
- Slow-drip sensitive reads (budgets + session exhaust)
- Outbound after sensitive context (ceiling + heuristics)
- Unclassified / new tools defaulting open (fail-closed class)
- Poisoned MCP tool definitions (schema pinning)
- SSRF / IMDS / private hosts; hostname allowlists (no substring bypass)
- Single-use approval resume; hold while delivery uncertain

### Still limited (honest gaps)

- Not full data-lineage / per-field taint through LLM transforms
- Not multi-agent spawn manifests (design only — child ⊂ parent)
- Not multi-instance shared session/approval state (in-memory)
- Not byte-level budgets; not enterprise HA / SSO
- Heuristic policy — tune thresholds; it will not catch everything
- Default `AEGOTRAX_REQUIRE_API_KEY=false` is pilot-only — turn on for any shared host

---

## Security notes

This is a **local pilot / sandbox** runtime — not a production enterprise control plane.

1. Set a strong `AEGOTRAX_API_KEY` and `AEGOTRAX_REQUIRE_API_KEY=1` before shared use.
2. Do not expose port 8000 to the internet without auth + network ACL.
3. Default MCP gateway mode is `simulate`.
4. Never commit audit logs.
5. Approval queue and sessions are **in-memory** (cleared on restart).
6. Envelope must be registered by the **host** on `/session`, not by the model.

---

## Support

If Aegotrax helped, a GitHub star helps others find the pilot:

⭐ **https://github.com/aegotrax-dev/aegotrax**

Issues and break reports are equally welcome.

---

## License

Apache-2.0
