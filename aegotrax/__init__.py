"""Aegotrax — Runtime security gateway for AI agents (MCP + SDK)."""

__version__ = "0.2.8"

from .sdk import (
    AegotraxError,
    protected_tool,
    report_delivery,
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
    "report_delivery",
    "protected_tool",
    "AegotraxError",
    "SchemaRegistry",
    "SchemaDriftError",
    "default_registry",
    "schema_fingerprint",
    "__version__",
]
