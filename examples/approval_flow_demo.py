"""Demo: human approval with a separate approver credential (0.2.8).

The agent can ask for approval but can never grant it: deciding needs the APPROVER key,
which the agent/SDK process does not hold.

    # terminal 1 (engine) — two DIFFERENT secrets
    set AEGOTRAX_API_KEY=<agent-key>
    set AEGOTRAX_APPROVER_KEY=<approver-key>
    aegotrax-engine

    # terminal 2
    set AEGOTRAX_API_KEY=<agent-key>
    set AEGOTRAX_APPROVER_KEY=<approver-key>     # only so this demo can play the human
    python examples/approval_flow_demo.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import requests
from aegotrax import report_delivery, set_session_context, verify_tool_call

API_KEY = os.environ.get("AEGOTRAX_API_KEY") or ""
APPROVER_KEY = os.environ.get("AEGOTRAX_APPROVER_KEY") or ""
if not API_KEY or not APPROVER_KEY:
    raise SystemExit("Set AEGOTRAX_API_KEY and AEGOTRAX_APPROVER_KEY (two different values)")
BASE = os.environ.get("AEGOTRAX_ENGINE_BASE", "http://127.0.0.1:8000")

SESSION = "sess-approval"
CALL = dict(
    session_id=SESSION,
    agent_id="demo",
    tool="send_email",
    arguments={"to": "contact@vendor-example.com", "body": "Meeting invite for Tuesday 10:00"},
)


def decide(approval_id: str, decision: str, key: str, header: str) -> requests.Response:
    return requests.post(
        f"{BASE}/approval/decide",
        json={"approval_id": approval_id, "decision": decision},
        headers={header: key},
        timeout=10,
    )


def main() -> None:
    set_session_context(
        SESSION,
        user_intent="Send the meeting invite to our vendor contact",
        agent_id="demo",
        api_key=API_KEY,
    )

    # 1. An email outside trusted_domains needs a human. The agent gets an approval_id only.
    first = verify_tool_call(**CALL, api_key=API_KEY)
    print("1. first call        :", first["decision"], "| approval_id:", first.get("approval_id"))
    print("   secret in response:", "approval_token" in first)
    if first["decision"] != "REQUIRE_APPROVAL":
        raise SystemExit("expected REQUIRE_APPROVAL (is the policy customised?)")
    aid = first["approval_id"]

    # 2. The agent tries to approve itself with the only credential it has.
    r = decide(aid, "approve", API_KEY, "X-Approver-Key")
    print("2. agent self-approve:", r.status_code, "(expected 401)")
    r = decide(aid, "approve", API_KEY, "X-API-Key")
    print("   with X-API-Key    :", r.status_code, "(expected 401)")

    # 3. Retrying before any human decided stays pending.
    pending = verify_tool_call(**CALL, approval_id=aid, api_key=API_KEY)
    print("3. retry, undecided  :", pending["decision"], pending.get("approval_status"))

    # 4. The human approver decides. decided_by is the authenticated identity.
    r = decide(aid, "approve", APPROVER_KEY, "X-Approver-Key")
    print("4. approver decides  :", r.status_code, r.json().get("status"), "by", r.json().get("decided_by"))

    # 5. The agent repeats the same call with the approval_id: released once.
    ok = verify_tool_call(**CALL, approval_id=aid, api_key=API_KEY)
    print("5. resume            :", ok["decision"])
    replay = verify_tool_call(**CALL, approval_id=aid, api_key=API_KEY)
    print("   replay            :", replay["decision"], "(single use)")

    # 6. Tell the engine the approved action ran, so it stops holding the same call.
    print("6. delivery report   :", report_delivery(aid, "delivered", api_key=API_KEY).get("delivery_status"))


if __name__ == "__main__":
    main()
