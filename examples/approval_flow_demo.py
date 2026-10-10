"""Demo: real REQUIRE_APPROVAL queue (token + decide + resume).

Requires a running engine on 127.0.0.1:8000.

    set AEGOTRAX_API_KEY=test-key-change-me
    aegotrax-engine

    python examples/approval_flow_demo.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import requests
from aegotrax import set_session_context, verify_tool_call

API_KEY = os.environ.get("AEGOTRAX_API_KEY", "test-key-change-me")
BASE = os.environ.get("AEGOTRAX_ENGINE_BASE", "http://127.0.0.1:8000")
HEADERS = {"X-API-Key": API_KEY}


def main() -> None:
    set_session_context(
        "sess-approval",
        user_intent="Draft a reply only — do not send email",
        agent_id="demo",
        api_key=API_KEY,
    )

    # Force mid-risk: untrusted outbound after no sensitive read → score ~25
    # Lower block threshold isn't needed; use always_require path by picking
    # a score band. Easiest: use send_email outside trusted domain → +70 BLOCK.
    # For REQUIRE_APPROVAL we need score in [50, 70).
    # Policy block=70, approval=50. Untrusted outbound alone is +25.
    # Add schema_drift medium? Simpler: temporarily we just call with
    # outbound untrusted + restrictive intent → 70+ → BLOCK.
    # So use a non-restrictive intent session for approval demo:

    set_session_context(
        "sess-approval",
        user_intent="Help process outbound notifications",
        agent_id="demo",
        api_key=API_KEY,
    )

    # Score: untrusted outbound +25. Not enough for approval.
    # Use execute_script without dangerous keywords → low score.
    # Put tool on always_require via direct engine call with high-ish score:
    # We'll call send_email to untrusted → +70 = BLOCK.
    # Alternative: craft arguments that hit approval band only.
    # Practical approach for demo: POST verify with a tool that scores 50-69.
    # Looking at policy: outbound untrusted after sensitive = 50 (MEDIUM).
    # So: first "read" sensitive, then outbound without sensitive payload keywords.

    # Step A: touch sensitive tool (records provenance)
    r0 = verify_tool_call(
        session_id="sess-approval",
        agent_id="demo",
        tool="read_document",
        arguments={"doc_id": "q3"},
        api_key=API_KEY,
    )
    print("step A (read_document):", r0["decision"], r0["risk_score"])

    # Step B: outbound without sensitive keywords in payload → +50 MEDIUM → REQUIRE_APPROVAL
    r1 = verify_tool_call(
        session_id="sess-approval",
        agent_id="demo",
        tool="http_post",
        arguments={"url": "https://hooks.example.com/notify", "data": "status=ok"},
        api_key=API_KEY,
    )
    print("step B (http_post):", r1["decision"], r1["risk_score"], r1.get("matched_policies"))
    print("  approval_id:", r1.get("approval_id"))
    assert r1["decision"] == "REQUIRE_APPROVAL", r1
    assert r1.get("approval_id") and r1.get("approval_token")

    aid, tok = r1["approval_id"], r1["approval_token"]

    # Step C: human approves
    resp = requests.post(
        f"{BASE}/approval/decide",
        json={
            "approval_id": aid,
            "token": tok,
            "decision": "approve",
            "decided_by": "demo-operator",
        },
        headers=HEADERS,
        timeout=5,
    )
    print("step C (decide approve):", resp.status_code, resp.json().get("status"))
    resp.raise_for_status()
    assert resp.json()["status"] == "approved"

    # Step D: resume with token → ALLOW (single-use)
    r2 = verify_tool_call(
        session_id="sess-approval",
        agent_id="demo",
        tool="http_post",
        arguments={"url": "https://hooks.example.com/notify", "data": "status=ok"},
        approval_id=aid,
        approval_token=tok,
        api_key=API_KEY,
    )
    print("step D (resume):", r2["decision"], r2.get("reasons"))
    assert r2["decision"] == "ALLOW"

    # Step E: reuse token → BLOCK (consumed)
    r3 = verify_tool_call(
        session_id="sess-approval",
        agent_id="demo",
        tool="http_post",
        arguments={"url": "https://hooks.example.com/notify", "data": "status=ok"},
        approval_id=aid,
        approval_token=tok,
        api_key=API_KEY,
    )
    print("step E (reuse):", r3["decision"], r3.get("reasons"))
    assert r3["decision"] == "BLOCK"

    print("\n✅ Approval queue flow OK")


if __name__ == "__main__":
    main()
