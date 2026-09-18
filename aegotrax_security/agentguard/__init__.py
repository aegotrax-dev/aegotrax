"""AgentGuard — Runtime security gateway for AI agents (MCP + SDK)."""

__version__ = "0.2.0"

from .sdk import (
    AgentGuardError,
    protected_tool,
    set_session_context,
    verify_tool_call,
)

__all__ = [
    "verify_tool_call",
    "set_session_context",
    "protected_tool",
    "AgentGuardError",
    "__version__",
]
