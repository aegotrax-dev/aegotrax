"""Demo: cumulative read budgets on sensitive tools — 0.2.5.

Requires engine on 127.0.0.1:8000.

    set AEGOTRAX_API_KEY=test-key-change-me
    aegotrax-engine
    python examples/read_budget_demo.py
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aegotrax import set_session_context, verify_tool_call

API_KEY = os.environ.get("AEGOTRAX_API_KEY", "test-key-change-me")


def main() -> None:
    set_session_context(
        "sess-budget",
        user_intent="Help with CRM analytics",
        agent_id="demo",
        api_key=API_KEY,
    )

    # policy default for read_document max_calls=15; use read_db max_calls=10
    # Force a low limit by repeating until exceed — default read_db is 10.
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

    print("\n✅ Read budget demo OK")


if __name__ == "__main__":
    main()
