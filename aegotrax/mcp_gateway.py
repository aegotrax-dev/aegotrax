"""Aegotrax MCP Gateway — intercepts tool calls and asks the Risk Engine.

SANDBOX SAFETY: default mode is simulate (no real side effects).
AEGOTRAX_MODE=forward performs real HTTP and must only be used in an isolated lab.

Schema pinning: tool definitions are pinned at startup. Any later change to a
tool's name/description/parameters is treated as potential poisoning (drift)
and is logged; high-severity drift can force BLOCK before execution.
"""

from __future__ import annotations

import json
import logging
from collections import OrderedDict
from pathlib import Path
from typing import Any, Dict, Optional

import requests
from mcp.server.fastmcp import FastMCP

from .approval import call_fingerprint
from .config import settings
from .schema_pinning import (
    CANONICAL_SCHEMAS,
    DriftEvent,
    SchemaRegistry,
    default_registry,
)

logger = logging.getLogger("aegotrax.mcp_gateway")

mcp = FastMCP("Aegotrax-Gateway")

# approval_id handles, kept HERE (host side) and never shown to the LLM. When the model
# retries the identical call after a human approved it, the gateway attaches the
# approval_id itself. The approval_id is not a secret that can approve anything: deciding
# needs the approver credential, which this process does not have.
_APPROVAL_HANDLES: "OrderedDict[str, str]" = OrderedDict()
_MAX_APPROVAL_HANDLES = 1000


def _handle_key(session_id: str, tool_name: str, arguments: Dict[str, Any]) -> str:
    return f"{session_id}|{call_fingerprint(tool_name, arguments)}"


def _remember_handle(key: str, approval_id: str) -> None:
    _APPROVAL_HANDLES[key] = approval_id
    _APPROVAL_HANDLES.move_to_end(key)
    while len(_APPROVAL_HANDLES) > _MAX_APPROVAL_HANDLES:
        _APPROVAL_HANDLES.popitem(last=False)


def _report_delivery(approval_id: str, result: str) -> None:
    """Best effort: tell the engine the approved call ran, so it stops holding the same
    tool+args. A failure here must never change what the agent sees."""
    try:
        headers = {"X-API-Key": settings.api_key} if settings.api_key else {}
        base = settings.engine_url.rsplit("/", 1)[0]
        status = "failed" if "❌" in result else "delivered"
        requests.post(
            f"{base}/approval/delivery",
            json={"approval_id": approval_id, "status": status},
            headers=headers,
            timeout=settings.engine_timeout,
        )
    except Exception as e:  # pragma: no cover - best effort
        logger.warning("Could not report approval delivery: %s", e)

# Pin all canonical tool schemas at import / startup time.
_PIN_COUNT = default_registry.pin_canonical()
logger.info("Schema pinning: %d tools pinned at gateway startup", _PIN_COUNT)


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
        import os
        from .security_utils import is_url_blocked

        # Double gate: mode=forward alone is not enough; require explicit opt-in.
        if os.getenv("AEGOTRAX_ALLOW_REAL_HTTP", "").lower() not in ("1", "true", "yes", "on"):
            return (
                "❌ [BLOCKED BY SANDBOX] Real HTTP is disabled. "
                "Set AEGOTRAX_MODE=forward AND AEGOTRAX_ALLOW_REAL_HTTP=1 "
                "only inside an isolated lab."
            )
        url = arguments.get("url", "")
        data = arguments.get("data", "")

        # Hard SSRF / IMDS guard — never contact private/link-local/metadata hosts
        blocked, why = is_url_blocked(str(url))
        if blocked:
            return (
                f"❌ [BLOCKED BY SSRF GUARD] Destination not allowed: {url}\n"
                f"Reason: {why}"
            )

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


def _check_schema_drift(tool_name: str) -> Optional[DriftEvent]:
    """
    Verify the tool still matches its pinned schema.

    For the built-in gateway tools we re-check against CANONICAL_SCHEMAS.
    When proxying upstream MCP servers, call registry.check_drift() with the
    *observed* tool definition returned by tools/list.
    """
    canonical = CANONICAL_SCHEMAS.get(tool_name)
    if canonical is None:
        # Unknown tool — treat as high-severity drift so it surfaces
        return default_registry.check_drift(
            tool_name,
            {"name": tool_name, "description": "", "parameters": {}},
        )
    return default_registry.check_drift(tool_name, canonical)


def verify_and_forward(tool_name: str, arguments: Dict[str, Any]) -> str:
    ctx = get_current_session_context()
    shadow = settings.enforcement == "shadow"
    session_id = ctx.get("session_id", "default-mcp-session")
    handle_key = _handle_key(session_id, tool_name, arguments)
    used_handle = _APPROVAL_HANDLES.get(handle_key)

    # --- Schema pinning / drift gate (runs before the risk engine) ---
    # In shadow mode the gateway does not block on its own; the drift is forwarded to
    # the engine, which reports what it would have done.
    drift = _check_schema_drift(tool_name)
    if drift is not None and drift.severity == "high" and not shadow:
        reasons_str = "; ".join(drift.differences)
        return (
            f"🚨 [Aegotrax] ACTION BLOCKED — SCHEMA DRIFT\n"
            f"Tool: {tool_name}\n"
            f"Severity: {drift.severity}\n"
            f"Reasons: {reasons_str}\n"
            f"Pinned fingerprint: {drift.pinned_fingerprint[:16] or '(none)'}…\n"
            f"Observed fingerprint: {drift.observed_fingerprint[:16]}…"
        )

    payload = {
        "session_id": session_id,
        "agent_id": ctx.get("agent_id", "langgraph-agent"),
        "user_intent": ctx.get("user_intent", "Execute user request"),
        "tool": tool_name,
        "arguments": arguments,
        "call_chain": ["external_agent", tool_name],
    }
    # Surface medium/low drift to the engine as extra context (pilot)
    if drift is not None:
        payload["schema_drift"] = drift.to_dict()
    if used_handle:
        payload["approval_id"] = used_handle

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
        approval_id = res_data.get("approval_id")
        approval_expires_at = res_data.get("approval_expires_at")
        if res_data.get("shadow") and res_data.get("would_decide") not in (None, "ALLOW"):
            logger.info(
                "[shadow] would %s %s (risk %s): %s",
                res_data.get("would_decide"), tool_name, risk_score, "; ".join(reasons),
            )
    except Exception as e:
        # Shadow mode must never break the agent, so it always fails open.
        if settings.fail_closed and not shadow:
            decision, risk_score, reasons = "BLOCK", 100, [f"Gateway Error: {str(e)}"]
        else:
            decision, risk_score, reasons = "ALLOW", 0, [f"Gateway Error (fail-open): {str(e)}"]
        approval_id = approval_expires_at = None
        used_handle = None

    # Keep the handle while the approval is pending; drop it once the call was released,
    # denied, expired or otherwise rejected.
    if decision == "REQUIRE_APPROVAL" and approval_id:
        _remember_handle(handle_key, approval_id)
    elif used_handle:
        _APPROVAL_HANDLES.pop(handle_key, None)
    if decision != "ALLOW":
        used_handle = None

    if decision == "BLOCK":
        reasons_str = "; ".join(reasons) if reasons else "High risk detected"
        return (
            f"🚨 [Aegotrax] ACTION BLOCKED\n"
            f"Tool: {tool_name}\n"
            f"Risk Score: {risk_score}/100\n"
            f"Reasons: {reasons_str}"
        )

    if decision == "REQUIRE_APPROVAL":
        reasons_str = "; ".join(reasons) if reasons else "Manual approval required"
        # Hard gate: never execute until a human approver decides (approver credential,
        # out-of-band). The model then simply repeats the same call; the gateway
        # attaches the approval_id it remembered. No secret is shown to the model.
        lines = [
            "⏸️ [Aegotrax] APPROVAL REQUIRED — ACTION NOT EXECUTED",
            f"Tool: {tool_name}",
            f"Arguments: {json.dumps(arguments, ensure_ascii=False)}",
            f"Risk Score: {risk_score}/100",
            f"Reasons: {reasons_str}",
        ]
        if approval_id:
            lines.append(f"approval_id: {approval_id}")
            if approval_expires_at:
                lines.append(f"approval_expires_at: {approval_expires_at}")
            lines.append(
                "Next: a human approver must decide this out-of-band "
                "(POST /approval/decide with the approver credential). "
                "After approval, repeat this exact call and it will be released once."
            )
        else:
            lines.append(
                "To proceed: obtain human approval out-of-band, then re-issue the call."
            )
        return "\n".join(lines)

    result = _execute(tool_name, arguments, risk_score)
    if used_handle:
        _report_delivery(used_handle, result)
    return result


def _execute(tool_name: str, arguments: Dict[str, Any], risk_score: Any) -> str:
    mode = settings.mode

    if mode == "echo":
        return (
            f"✅ [Aegotrax] ALLOWED (Risk: {risk_score}/100)\n"
            f"Tool '{tool_name}' was approved.\n"
            f"Arguments: {json.dumps(arguments, ensure_ascii=False)}"
        )

    if mode == "forward":
        result = actually_run_tool(tool_name, arguments)
        return f"✅ [Aegotrax] ALLOWED (Risk: {risk_score}/100)\n{result}"

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
        f"✅ [Aegotrax] ALLOWED (Risk: {risk_score}/100)\n"
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


@mcp.tool()
def schema_status() -> str:
    """Return pinned tool schemas and any recorded drift events (introspection)."""
    pinned = default_registry.list_pinned()
    drifts = default_registry.list_drift_events()
    return json.dumps(
        {
            "pinned_count": len(pinned),
            "pinned": pinned,
            "drift_events": drifts,
        },
        indent=2,
        ensure_ascii=False,
    )


# ---------------------------------------------------------------------------
# Public helpers for callers that proxy upstream MCP servers
# ---------------------------------------------------------------------------

def pin_upstream_tool(name: str, observed_schema: Dict[str, Any]) -> None:
    """
    Pin a tool schema obtained from an upstream MCP server's tools/list.

    Call this once when the upstream connection is established (or when you
    intentionally accept a new tool). Subsequent tools/list responses should
    be checked with check_upstream_drift().
    """
    default_registry.pin(name, observed_schema, source="upstream")


def check_upstream_drift(name: str, observed_schema: Dict[str, Any]) -> Optional[DriftEvent]:
    """
    Compare an observed upstream tool definition against the pin.

    Returns a DriftEvent (and records it) if the schema has changed.
    High-severity drift should be treated as BLOCK before the tool is offered
    to the agent or executed.
    """
    return default_registry.check_drift(name, observed_schema)


def get_schema_registry() -> SchemaRegistry:
    """Access the gateway's schema registry (for tests / advanced integration)."""
    return default_registry


def main():
    mcp.run()


if __name__ == "__main__":
    main()
