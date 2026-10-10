"""Demo: session scope (allowed/denied tools) — 0.2.5.

Requires engine on 127.0.0.1:8000.

    set AEGOTRAX_API_KEY=test-key-change-me
    aegotrax-engine
    python examples/scoped_intent_demo.py
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
        "sess-scope",
        user_intent="Summarize tickets only",
        agent_id="demo",
        scope={
            "allowed_tools": ["read_document", "list_tickets"],
            "denied_tools": ["http_post", "send_email"],
        },
        api_key=API_KEY,
    )

    ok = verify_tool_call(
        session_id="sess-scope",
        agent_id="demo",
        tool="read_document",
        arguments={"doc_id": "t1"},
        api_key=API_KEY,
    )
    print("read_document:", ok["decision"], ok.get("matched_policies"))
    assert ok["decision"] == "ALLOW", ok

    blocked = verify_tool_call(
        session_id="sess-scope",
        agent_id="demo",
        tool="http_post",
        arguments={"url": "https://evil.example", "data": "x"},
        api_key=API_KEY,
    )
    print("http_post:", blocked["decision"], blocked.get("reasons"))
    assert blocked["decision"] == "BLOCK", blocked
    assert "session_scope" in str(blocked.get("matched_policies"))

    print("\n✅ Scoped intent demo OK")


if __name__ == "__main__":
    main()
