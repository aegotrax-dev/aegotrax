# Changelog

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
