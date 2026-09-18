"""AgentGuard MCP Gateway — intercepts tool calls and asks the Risk Engine."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

import requests
from mcp.server.fastmcp import FastMCP

from .config import settings

mcp = FastMCP("AgentGuard-Gateway")


def get_current_session_context() -> Dict[str, Any]:
    if settings.session_context_path and Path(settings.session_context_path).exists():
        try:
            with open(settings.session_context_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass

    cwd_ctx = Path.cwd() / "active_session_context.json"
    if cwd_ctx.exists():
        try:
            with open(cwd_ctx, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass

    return {
        "session_id": "default-mcp-session",
        "user_intent": "Execute user request",
    }


def actually_run_tool(tool_name: str, arguments: Dict[str, Any]) -> str:
    if tool_name == "http_post":
        url = arguments.get("url", "")
        data = arguments.get("data", "")
        try:
            resp = requests.post(url, data=data, timeout=5)
            return (
                f"✅ [REAL EXECUTION] HTTP POST sent to {url}\n"
                f"Status code: {resp.status_code}\n"
                f"Response (first 200 chars): {resp.text[:200]}"
            )
        except Exception as e:
            return f"❌ [REAL EXECUTION FAILED] Could not POST to {url}. Error: {str(e)}"

    if tool_name == "read_document":
        return "Document Content: 'CONFIDENTIAL: Q3 Financials show 20% growth. End of document.'"
    if tool_name == "list_users":
        return "User List: ['admin@company.com', 'customer_db_record: Alice']"
    if tool_name == "read_db":
        return "Database Result: 'customer_db_record accessed successfully.'"
    if tool_name == "send_email":
        return f"[SIMULATED] Email would be sent to {arguments.get('to', 'unknown')}"
    if tool_name == "execute_script":
        return f"[SIMULATED] Script '{arguments.get('script_name', 'unknown')}' would run"

    return f"[SIMULATED] Tool '{tool_name}' executed with args: {arguments}"


def verify_and_forward(tool_name: str, arguments: Dict[str, Any]) -> str:
    ctx = get_current_session_context()

    payload = {
        "session_id": ctx.get("session_id", "default-mcp-session"),
        "agent_id": ctx.get("agent_id", "langgraph-agent"),
        "user_intent": ctx.get("user_intent", "Execute user request"),
        "tool": tool_name,
        "arguments": arguments,
        "call_chain": ["external_agent", tool_name],
    }

    headers = {}
    if settings.api_key:
        headers["X-API-Key"] = settings.api_key

    try:
        response = requests.post(
            settings.engine_url,
            json=payload,
            headers=headers,
            timeout=settings.engine_timeout,
        )
        res_data = response.json()
        decision = res_data.get("decision", "ALLOW")
        risk_score = res_data.get("risk_score", 0)
        reasons = res_data.get("reasons", [])
    except Exception as e:
        if settings.fail_closed:
            decision, risk_score, reasons = "BLOCK", 100, [f"Gateway Error: {str(e)}"]
        else:
            decision, risk_score, reasons = "ALLOW", 0, [f"Gateway Error (fail-open): {str(e)}"]

    if decision == "BLOCK":
        reasons_str = "; ".join(reasons) if reasons else "High risk detected"
        return (
            f"🚨 [AgentGuard] ACTION BLOCKED\n"
            f"Tool: {tool_name}\n"
            f"Risk Score: {risk_score}/100\n"
            f"Reasons: {reasons_str}"
        )

    if decision == "REQUIRE_APPROVAL":
        reasons_str = "; ".join(reasons) if reasons else "Manual approval required"
        return (
            f"⏸️ [AgentGuard] APPROVAL REQUIRED\n"
            f"Tool: {tool_name}\n"
            f"Risk Score: {risk_score}/100\n"
            f"Reasons: {reasons_str}\n"
            f"Action was NOT executed."
        )

    mode = settings.mode

    if mode == "echo":
        return (
            f"✅ [AgentGuard] ALLOWED (Risk: {risk_score}/100)\n"
            f"Tool '{tool_name}' was approved.\n"
            f"Arguments: {json.dumps(arguments, ensure_ascii=False)}"
        )

    if mode == "forward":
        result = actually_run_tool(tool_name, arguments)
        return f"✅ [AgentGuard] ALLOWED (Risk: {risk_score}/100)\n{result}"

    simulated_data = ""
    if tool_name == "read_document":
        simulated_data = (
            "\nDocument Content: 'CONFIDENTIAL: Q3 Financials show 20% growth. End of document.'"
        )
    elif tool_name == "list_users":
        simulated_data = "\nUser List: ['admin@company.com', 'customer_db_record: Alice']"
    elif tool_name == "read_db":
        simulated_data = "\nDatabase Result: 'customer_db_record accessed successfully.'"
    elif tool_name == "http_post":
        simulated_data = f"\nHTTP POST sent to {arguments.get('url', 'unknown')}."
    elif tool_name == "send_email":
        simulated_data = f"\nEmail sent to {arguments.get('to', 'unknown')}."
    elif tool_name == "execute_script":
        simulated_data = f"\nScript '{arguments.get('script_name', 'unknown')}' executed."

    return (
        f"✅ [AgentGuard] ALLOWED (Risk: {risk_score}/100)\n"
        f"Executed '{tool_name}' with args: {arguments}"
        f"{simulated_data}"
    )


@mcp.tool()
def http_post(url: str, data: str = "") -> str:
    """Send an HTTP POST request to external URL."""
    return verify_and_forward("http_post", {"url": url, "data": data})


@mcp.tool()
def send_email(to: str, body: str = "") -> str:
    """Send an email to a specified recipient."""
    return verify_and_forward("send_email", {"to": to, "body": body})


@mcp.tool()
def read_document(doc_id: str = "default_doc") -> str:
    """Read internal document content."""
    return verify_and_forward("read_document", {"doc_id": doc_id})


@mcp.tool()
def list_users() -> str:
    """List internal database users."""
    return verify_and_forward("list_users", {})


@mcp.tool()
def read_db(query: str = "") -> str:
    """Query sensitive internal database."""
    return verify_and_forward("read_db", {"query": query})


@mcp.tool()
def execute_script(script_name: str = "wipe_logs") -> str:
    """Execute arbitrary script on server."""
    return verify_and_forward("execute_script", {"script_name": script_name})


def main():
    mcp.run()


if __name__ == "__main__":
    main()
