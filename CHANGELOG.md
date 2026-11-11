# Changelog

## [0.2.8] - 2026-11-11

### Security
- **Agents can no longer approve their own requests.** Before, `REQUIRE_APPROVAL` responses carried `approval_token`, and `POST /approval/decide` needed only that token plus the same API key the agent/SDK uses; `decided_by` was a client-supplied string. Now the agent only receives `approval_id`; `/approval/decide` and `/approvals/pending` require a separate approver credential (`X-Approver-Key`, from `AEGOTRAX_APPROVER_KEY` or `AEGOTRAX_APPROVER_KEYS`); `decided_by` is the authenticated approver; `GET /approval/{id}` with the agent key returns status only. An approver key equal to the API key is ignored and the engine refuses to start with it. The approval webhook no longer carries a token. The MCP gateway no longer prints any approval secret into the tool result the model sees, keeps the `approval_id` host-side and re-attaches it when the identical call is retried.
- Hard blocks that returned before scoring (session scope, closed session, rate limit, user binding, failed approval resume) are now audited.

### Added
- **Shadow mode**: `AEGOTRAX_ENFORCEMENT=shadow` (default `enforce`). Decisions are computed and audited (`mode`, `enforced_decision` on audit events) but the caller always gets `ALLOW` plus `shadow` / `would_decide`. No approvals queued, no sessions closed; SDK and gateway fail open in shadow. `/health` reports `enforcement`.
- `aegotrax-shadow-report` CLI (`aegotrax/shadow_report.py`): would-allow / approve / block counts, friction rate, per-tool table, top rules and reasons, examples.
- `POST /approval/delivery` is now actually served (it was documented since 0.2.6 but missing), `report_delivery()` in the SDK, automatic reporting in the gateway.
- Policy keys `code_execution_tools` and `email_untrusted_recipient` (both optional; defaults apply to older policy files).
- `tests/` (unittest-style, also runs under pytest) and a `test` extra.

### Changed
- **Breaking**: `/approval/decide` no longer accepts the agent API key and ignores `token` / `decided_by`; `approval_token` is removed from responses and from the SDK request (`verify_tool_call(approval_token=...)` is accepted and ignored); resume is `approval_id` alone.
- A resume attempt for a still-undecided approval returns `REQUIRE_APPROVAL` (`approval_status: pending`, same `approval_id`) instead of BLOCK.
- An email to a recipient outside `trusted_domains` now returns `REQUIRE_APPROVAL` instead of BLOCK (set `email_untrusted_recipient: BLOCK` for the old behaviour). After a sensitive read it is still blocked.
- Plain read tools (`read_db`, `list_users`, `query_customers`) no longer count as side-effect tools for the restrictive-intent heuristic ("read-only", "list only" intents no longer hard-block reads). `execute_code`, `run_shell`, `delete_user` now count as side-effect tools.
- Script keywords of 3 characters or fewer (`rm`) match whole tokens only. Default policy: `format` replaced by `format c:`; `rmdir` and `rmtree` added.
- `docker-compose.yml` fails immediately if `AEGOTRAX_API_KEY` is missing and passes `AEGOTRAX_APPROVER_KEY` / `AEGOTRAX_ENFORCEMENT`.

### Fixed
- `execute_code` / `run_shell` (listed in `tool_classes`) skipped the dangerous-script keyword check, which only knew `execute_script` / `run_code` / `shell`.
- Version was 0.2.6 in code, 0.2.7 in `pyproject.toml` and docs; now a single `__version__` in `aegotrax/__init__.py` (a test checks they agree).

### Packaging and housekeeping
- `mcp` is pinned to `<2` (mcp 2.x renamed `FastMCP` to `MCPServer` and the gateway targets 1.x).
- pytest is limited to `tests/` (`testpaths`), so it no longer collects the demos in `examples/`.
- Added `.env.example` (API key, approver key, enforcement mode; the real `.env` stays git-ignored).
- Removed the leftover `agentguard/` and `agentguard_demo/` directories, as the 0.2.7 changelog already claimed.

### Benchmark (engine 0.2.8)
- Attacks intercepted 51 / 53 (unchanged); hard-blocked 33 / 53. Benign hard false positives 4 → 0 (clean ALLOW 10 → 12, needs approval 10 → 12).

## [0.2.7] - 2026-11-09

### Changed
- **Breaking**: `AEGOTRAX_REQUIRE_API_KEY` now defaults to `true`. The engine refuses to start without `AEGOTRAX_API_KEY`. Set `AEGOTRAX_REQUIRE_API_KEY=0` explicitly to restore the previous pilot behavior.
- Benchmark rewritten: 77 hand-written scenarios (no synthetic loops).
- Removed leftover `agentguard` / `agentguard_demo` directories.
- README now includes measured results and known gaps.

### Security
- Secure-by-default for API key requirement.

## [0.2.6] - previous
- Session exhaust, sensitivity ceiling, tool classes, approval delivery tracking.
