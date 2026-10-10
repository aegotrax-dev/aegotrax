"""AgentGuard — Runtime security gateway for AI agents (MCP + SDK)."""

__version__ = "0.2.5"

from .sdk import (
    AgentGuardError,
    protected_tool,
    set_session_context,
    verify_tool_call,
)
from .schema_pinning import (
    SchemaDriftError,
    SchemaRegistry,
    default_registry,
    schema_fingerprint,
)

__all__ = [
    "verify_tool_call",
    "set_session_context",
    "protected_tool",
    "AgentGuardError",
    "SchemaRegistry",
    "SchemaDriftError",
    "default_registry",
    "schema_fingerprint",
    "__version__",
]
