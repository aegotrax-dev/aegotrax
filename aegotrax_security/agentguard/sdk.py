"""
AgentGuard Python SDK — for pilot integration without MCP.

Usage (simplest):

    from agentguard import verify_tool_call

    result = verify_tool_call(
        session_id="sess-123",
        agent_id="support-agent",
        user_intent="Summarize the ticket only",
        tool="http_post",
        arguments={"url": "https://evil.com", "data": "..."},
    )
    if result["decision"] == "BLOCK":
        raise PermissionError(result["reasons"])

Or as a decorator on your own tools:

    from agentguard import protected_tool

    @protected_tool(session_id_fn=lambda: current_session_id(), ...)
    def send_email(to: str, body: str):
        ...
"""

from __future__ import annotations

import functools
import os
from typing import Any, Callable, Dict, List, Optional

import requests

from .config import settings


class AgentGuardError(Exception):
    """Raised when a tool call is blocked (optional strict mode)."""

    def __init__(self, decision: str, reasons: List[str], risk_score: int, raw: dict):
        self.decision = decision
        self.reasons = reasons
        self.risk_score = risk_score
        self.raw = raw
        super().__init__(f"AgentGuard {decision}: {'; '.join(reasons)}")


def verify_tool_call(
    *,
    session_id: str,
    agent_id: str,
    user_intent: str,
    tool: str,
    arguments: Optional[Dict[str, Any]] = None,
    call_chain: Optional[List[str]] = None,
    engine_url: Optional[str] = None,
    api_key: Optional[str] = None,
    timeout: Optional[float] = None,
    raise_on_block: bool = False,
) -> Dict[str, Any]:
    """
    Ask the Risk Engine whether a tool call is allowed.

    Returns:
        {
          "decision": "ALLOW" | "BLOCK" | "REQUIRE_APPROVAL",
          "risk_score": int,
          "reasons": [str],
          "attack_path": str,
        }
    """
    url = engine_url or settings.engine_url
    key = api_key if api_key is not None else settings.api_key
    to = timeout if timeout is not None else settings.engine_timeout

    payload = {
        "session_id": session_id,
        "agent_id": agent_id,
        "user_intent": user_intent,
        "tool": tool,
        "arguments": arguments or {},
        "call_chain": call_chain or ["sdk", tool],
    }

    headers = {}
    if key:
        headers["X-API-Key"] = key

    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=to)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        if settings.fail_closed:
            data = {
                "decision": "BLOCK",
                "risk_score": 100,
                "reasons": [f"Engine unreachable (fail-closed): {e}"],
                "attack_path": " -> ".join(payload["call_chain"]),
            }
        else:
            data = {
                "decision": "ALLOW",
                "risk_score": 0,
                "reasons": [f"Engine unreachable (fail-open): {e}"],
                "attack_path": " -> ".join(payload["call_chain"]),
            }

    if raise_on_block and data.get("decision") in ("BLOCK", "REQUIRE_APPROVAL"):
        raise AgentGuardError(
            decision=data["decision"],
            reasons=data.get("reasons", []),
            risk_score=data.get("risk_score", 0),
            raw=data,
        )

    return data


def set_session_context(
    session_id: str,
    user_intent: str,
    *,
    agent_id: str = "default-agent",
    engine_base: Optional[str] = None,
    api_key: Optional[str] = None,
) -> dict:
    """Register / update session intent on the engine (pilot helper)."""
    base = engine_base or settings.engine_base
    key = api_key if api_key is not None else settings.api_key
    headers = {}
    if key:
        headers["X-API-Key"] = key

    resp = requests.post(
        f"{base.rstrip('/')}/session",
        json={
            "session_id": session_id,
            "user_intent": user_intent,
            "agent_id": agent_id,
        },
        headers=headers,
        timeout=settings.engine_timeout,
    )
    resp.raise_for_status()
    return resp.json()


def protected_tool(
    *,
    tool_name: Optional[str] = None,
    session_id_fn: Callable[[], str],
    agent_id_fn: Callable[[], str],
    user_intent_fn: Callable[[], str],
    raise_on_block: bool = True,
):
    """
    Decorator: verify before running your real tool function.

        @protected_tool(
            session_id_fn=lambda: ctx.session_id,
            agent_id_fn=lambda: "billing-agent",
            user_intent_fn=lambda: ctx.user_intent,
        )
        def charge_customer(customer_id: str, amount: float):
            ...
    """

    def decorator(fn: Callable):
        name = tool_name or fn.__name__

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            # Best-effort argument capture for the engine
            arguments: Dict[str, Any] = {}
            try:
                import inspect

                sig = inspect.signature(fn)
                bound = sig.bind_partial(*args, **kwargs)
                arguments = dict(bound.arguments)
            except Exception:
                arguments = {"args": list(args), "kwargs": kwargs}

            result = verify_tool_call(
                session_id=session_id_fn(),
                agent_id=agent_id_fn(),
                user_intent=user_intent_fn(),
                tool=name,
                arguments=arguments,
                raise_on_block=raise_on_block,
            )
            if result.get("decision") in ("BLOCK", "REQUIRE_APPROVAL") and not raise_on_block:
                return {
                    "agentguard_blocked": True,
                    "decision": result["decision"],
                    "reasons": result.get("reasons", []),
                    "risk_score": result.get("risk_score", 0),
                }
            return fn(*args, **kwargs)

        return wrapper

    return decorator
