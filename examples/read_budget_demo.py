"""Demo: cumulative read budgets on sensitive tools — 0.2.6.

Requires engine on 127.0.0.1:8000.

    set AEGOTRAX_API_KEY=<your-api-key>
    aegotrax-engine
    python examples/read_budget_demo.py
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aegotrax import set_session_context, verify_tool_call

API_KEY = os.environ.get("AEGOTRAX_API_KEY") or ""
if not API_KEY:
    raise SystemExit("Set AEGOTRAX_API_KEY before running this demo")


def main() -> None:
    set_session_context(
        "sess-budget",
        user_intent="Help with CRM analytics",
        agent_id="demo",
        api_key=API_KEY,
    )

    # policy: read_db max_calls=10 → call 11 exceeds
    last = None
    for i in range(1, 12):
        last = verify_tool_call(
            session_id="sess-budget",
            agent_id="demo",
            tool="read_db",
            arguments={"query": f"select {i}"},
            api_key=API_KEY,
        )
        print(f"call {i}: {last['decision']} budget={last.get('read_budget')}")

    assert last is not None
    assert last.get("read_budget", {}).get("count", 0) >= 11
    assert last["decision"] in ("REQUIRE_APPROVAL", "BLOCK"), last
    assert "read_budget" in (last.get("matched_policies") or [])

    # 0.2.6: further calls blocked — session closed after budget exceed
    closed = verify_tool_call(
        session_id="sess-budget",
        agent_id="demo",
        tool="read_db",
        arguments={"query": "after-exhaust"},
        api_key=API_KEY,
    )
    print(
        "after exceed:",
        closed["decision"],
        "policies=",
        closed.get("matched_policies"),
    )
    assert closed["decision"] == "BLOCK"
    assert "session_exhausted" in (closed.get("matched_policies") or [])

    print("\n✅ Read budget demo OK")
if __name__ == "__main__":
    main()
