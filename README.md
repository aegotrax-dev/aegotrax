# Aegotrax

**Runtime protection for AI agents — checks tool calls before they run.**

Public site: [https://aegotrax.com](https://aegotrax.com)  
Repository: [https://github.com/aegotrax-dev/aegotrax](https://github.com/aegotrax-dev/aegotrax)

This repo is the open **pilot runtime**. Package name: `aegotrax`.

---

# 🛡️ Aegotrax v0.2.8

Intercept tool calls, evaluate **server-side session intent + scope**, apply **read budgets**, **sensitivity ceiling**, **tool risk classes**, and **block / require human approval** before sensitive actions run.

| Integration | Use when |
|-------------|----------|
| **Python SDK** | You call tools from your own code (`verify_tool_call` / `@protected_tool`) |
| **MCP Gateway** | The agent already speaks MCP and you want one interception point |

### What’s new in 0.2.8
- **Agents can no longer approve their own requests.** The engine never gives the agent an approval secret (only an `approval_id`). `POST /approval/decide` needs a separate **approver credential** (`X-Approver-Key`, set with `AEGOTRAX_APPROVER_KEY` / `AEGOTRAX_APPROVER_KEYS`), and `decided_by` is the authenticated approver, not a client-supplied string. **Breaking:** old clients that sent `token` / `decided_by` to `/approval/decide` now get 401 until they use the approver key; `approval_token` is gone from responses, and resume is `approval_id` alone.
- **Shadow mode** (`AEGOTRAX_ENFORCEMENT=shadow`): the engine decides and audits everything but always answers `ALLOW`, with `would_decide` showing what it would have done. Never blocks, never queues approvals, never closes sessions. `aegotrax-shadow-report` summarises it. See [Shadow mode](#shadow-mode).
- `POST /approval/delivery` now actually exists (it was documented in 0.2.6 but not served); the SDK has `report_delivery()` and the gateway reports it for you.
- Fixes: tool-name mismatch between `tool_classes` and the code-execution checks (`execute_code` / `run_shell` skipped the script-keyword check); one version string everywhere; plain read tools no longer trip the "read-only / list only" intent heuristic; an email to an external recipient now asks for approval instead of hard-blocking (after a sensitive read it still blocks); short script keywords (`rm`) match whole tokens, so `format_report.py` is no longer blocked (`rmtree` / `rmdir` were added so `shutil.rmtree` still is).
- Hard blocks that return before scoring (scope, closed session, rate limit, user binding, failed approval resume) are now written to the audit log too.
- Tests: `python -m unittest discover -s tests -t .` (or `pytest`).

### What’s new in 0.2.7
- Secure-by-default: AEGOTRAX_REQUIRE_API_KEY=true (set to 0 for old behavior)
- Hand-written benchmark (77 scenarios)

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
pip install .                       # for development and tests: pip install -e ".[test]" && python -m pytest

# The engine refuses to start without a key (secure by default). Generate one:
export AEGOTRAX_API_KEY="your-strong-api-key-here"
# Humans who approve REQUIRE_APPROVAL calls use a DIFFERENT secret (optional; without it
# approvals stay blocked). It must not equal AEGOTRAX_API_KEY:
export AEGOTRAX_APPROVER_KEY="another-strong-secret"
# Windows (PowerShell): $env:AEGOTRAX_API_KEY = "..."; $env:AEGOTRAX_APPROVER_KEY = "..."
# Windows (cmd): set "AEGOTRAX_API_KEY=..."   (quotes avoid a trailing space becoming part of the key)
# Or copy .env.example to .env (git-ignored) and fill it in: every process reads it.
aegotrax-engine
# If the aegotrax-engine command is not on PATH (Windows): python -c "from aegotrax.risk_engine import main; main()"
# other terminal:
curl -s http://127.0.0.1:8000/health   # → version 0.2.8
python examples/sdk_pilot_example.py
```

Docker:

```bash
export AEGOTRAX_API_KEY="your-strong-api-key-here"
export AEGOTRAX_APPROVER_KEY="another-strong-secret"   # optional
docker compose up --build        # compose fails fast if AEGOTRAX_API_KEY is missing
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
2. Do not expose port 8000 to the internet without auth + network ACL.
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
