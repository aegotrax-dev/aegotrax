"""Schema pinning & drift detection for MCP tools.

Protects against poisoned tool descriptions that steer the agent *before*
the tool-call interceptor runs.

Usage (gateway startup):
    from aegotrax.schema_pinning import SchemaRegistry

    registry = SchemaRegistry()
    registry.pin_from_function("http_post", http_post_fn, description="...")
    # or pin explicit canonical schemas:
    registry.pin("http_post", CANONICAL_SCHEMAS["http_post"])

    # Later — before trusting a tool definition from an upstream MCP server:
    drift = registry.check_drift("http_post", observed_schema)
    if drift:
        # log / block / require_approval
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("aegotrax.schema_pinning")


def _canonical_json(obj: Any) -> str:
    """Stable JSON representation for hashing."""
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def schema_fingerprint(schema: Dict[str, Any]) -> str:
    """SHA-256 fingerprint of a tool schema (name + description + parameters)."""
    relevant = {
        "name": schema.get("name"),
        "description": schema.get("description"),
        "parameters": schema.get("parameters") or schema.get("inputSchema") or {},
    }
    return hashlib.sha256(_canonical_json(relevant).encode("utf-8")).hexdigest()


@dataclass
class PinnedSchema:
    name: str
    description: str
    parameters: Dict[str, Any]
    fingerprint: str
    pinned_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    )
    source: str = "registration"  # registration | config | upstream

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters,
            "fingerprint": self.fingerprint,
            "pinned_at": self.pinned_at,
            "source": self.source,
        }


@dataclass
class DriftEvent:
    tool_name: str
    pinned_fingerprint: str
    observed_fingerprint: str
    differences: List[str]
    severity: str  # "low" | "medium" | "high"
    observed_schema: Dict[str, Any]
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "pinned_fingerprint": self.pinned_fingerprint,
            "observed_fingerprint": self.observed_fingerprint,
            "differences": self.differences,
            "severity": self.severity,
            "observed_schema": self.observed_schema,
            "timestamp": self.timestamp,
        }


# Canonical schemas for the tools exposed by the Aegotrax MCP Gateway.
# These are the *trusted* definitions; any change is treated as potential poisoning.
CANONICAL_SCHEMAS: Dict[str, Dict[str, Any]] = {
    "http_post": {
        "name": "http_post",
        "description": "Send an HTTP POST request to external URL.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL"},
                "data": {"type": "string", "description": "POST body", "default": ""},
            },
            "required": ["url"],
        },
    },
    "send_email": {
        "name": "send_email",
        "description": "Send an email to a specified recipient.",
        "parameters": {
            "type": "object",
            "properties": {
                "to": {"type": "string", "description": "Recipient email address"},
                "body": {"type": "string", "description": "Email body", "default": ""},
            },
            "required": ["to"],
        },
    },
    "read_document": {
        "name": "read_document",
        "description": "Read internal document content.",
        "parameters": {
            "type": "object",
            "properties": {
                "doc_id": {
                    "type": "string",
                    "description": "Document identifier",
                    "default": "default_doc",
                },
            },
            "required": [],
        },
    },
    "list_users": {
        "name": "list_users",
        "description": "List internal database users.",
        "parameters": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    "read_db": {
        "name": "read_db",
        "description": "Query sensitive internal database.",
        "parameters": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Database query", "default": ""},
            },
            "required": [],
        },
    },
    "execute_script": {
        "name": "execute_script",
        "description": "Execute arbitrary script on server.",
        "parameters": {
            "type": "object",
            "properties": {
                "script_name": {
                    "type": "string",
                    "description": "Script to run",
                    "default": "wipe_logs",
                },
            },
            "required": [],
        },
    },
}


class SchemaRegistry:
    """In-memory registry of pinned tool schemas with drift detection."""

    def __init__(self) -> None:
        self._pinned: Dict[str, PinnedSchema] = {}
        self._drift_log: List[DriftEvent] = []

    # ------------------------------------------------------------------
    # Pinning
    # ------------------------------------------------------------------

    def pin(
        self,
        name: str,
        schema: Dict[str, Any],
        *,
        source: str = "registration",
    ) -> PinnedSchema:
        """Pin a tool schema. Overwrites any previous pin for the same name."""
        description = schema.get("description") or ""
        parameters = schema.get("parameters") or schema.get("inputSchema") or {}
        full = {
            "name": name,
            "description": description,
            "parameters": parameters,
        }
        fp = schema_fingerprint(full)
        pinned = PinnedSchema(
            name=name,
            description=description,
            parameters=parameters,
            fingerprint=fp,
            source=source,
        )
        self._pinned[name] = pinned
        logger.info("Pinned schema for tool '%s' (fp=%s…)", name, fp[:12])
        return pinned

    def pin_canonical(self, tool_names: Optional[List[str]] = None) -> int:
        """Pin all (or selected) tools from CANONICAL_SCHEMAS. Returns count pinned."""
        names = tool_names or list(CANONICAL_SCHEMAS.keys())
        count = 0
        for name in names:
            if name in CANONICAL_SCHEMAS:
                self.pin(name, CANONICAL_SCHEMAS[name], source="canonical")
                count += 1
        return count

    def pin_from_function(
        self,
        name: str,
        fn: Callable,
        *,
        description: Optional[str] = None,
    ) -> PinnedSchema:
        """Best-effort pin from a Python function signature + docstring."""
        import inspect

        desc = description or (inspect.getdoc(fn) or "").strip().split("\n")[0]
        sig = inspect.signature(fn)
        properties: Dict[str, Any] = {}
        required: List[str] = []
        for pname, param in sig.parameters.items():
            if pname in ("self", "cls"):
                continue
            prop: Dict[str, Any] = {"type": "string"}  # simplified for pilot
            if param.default is not inspect.Parameter.empty:
                prop["default"] = param.default
            else:
                required.append(pname)
            properties[pname] = prop
        schema = {
            "name": name,
            "description": desc,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required,
            },
        }
        return self.pin(name, schema, source="function")

    # ------------------------------------------------------------------
    # Drift detection
    # ------------------------------------------------------------------

    def check_drift(
        self,
        name: str,
        observed: Dict[str, Any],
        *,
        record: bool = True,
    ) -> Optional[DriftEvent]:
        """
        Compare an observed tool schema against the pinned one.

        Returns a DriftEvent if differences are found, else None.
        Unknown tools (never pinned) are treated as high-severity drift
        so that new/unexpected tools surface for review.
        """
        observed_name = observed.get("name") or name
        observed_desc = observed.get("description") or ""
        observed_params = (
            observed.get("parameters") or observed.get("inputSchema") or {}
        )
        observed_full = {
            "name": observed_name,
            "description": observed_desc,
            "parameters": observed_params,
        }
        observed_fp = schema_fingerprint(observed_full)

        pinned = self._pinned.get(name)
        if pinned is None:
            event = DriftEvent(
                tool_name=name,
                pinned_fingerprint="",
                observed_fingerprint=observed_fp,
                differences=[f"Tool '{name}' was never pinned (unknown tool definition)."],
                severity="high",
                observed_schema=observed_full,
            )
            if record:
                self._drift_log.append(event)
                logger.warning("Schema drift (unknown tool): %s", name)
            return event

        if observed_fp == pinned.fingerprint:
            return None

        differences: List[str] = []
        severity = "low"

        if observed_desc != pinned.description:
            differences.append(
                f"description changed: pinned={pinned.description!r} → observed={observed_desc!r}"
            )
            # Description changes are the classic poisoning vector → high severity
            severity = "high"

        pinned_props = (pinned.parameters or {}).get("properties") or {}
        observed_props = (observed_params or {}).get("properties") or {}
        pinned_keys = set(pinned_props.keys())
        observed_keys = set(observed_props.keys())

        added = observed_keys - pinned_keys
        removed = pinned_keys - observed_keys
        if added:
            differences.append(f"parameters added: {sorted(added)}")
            severity = "high" if severity != "high" else severity
        if removed:
            differences.append(f"parameters removed: {sorted(removed)}")
            severity = "medium" if severity == "low" else severity

        for key in pinned_keys & observed_keys:
            if pinned_props[key] != observed_props[key]:
                differences.append(f"parameter '{key}' definition changed")
                severity = "medium" if severity == "low" else severity

        if not differences:
            differences.append("fingerprint mismatch (structural difference not classified)")
            severity = "medium"

        event = DriftEvent(
            tool_name=name,
            pinned_fingerprint=pinned.fingerprint,
            observed_fingerprint=observed_fp,
            differences=differences,
            severity=severity,
            observed_schema=observed_full,
        )
        if record:
            self._drift_log.append(event)
            logger.warning(
                "Schema drift detected for '%s' (severity=%s): %s",
                name,
                severity,
                "; ".join(differences),
            )
        return event

    def assert_no_drift(self, name: str, observed: Dict[str, Any]) -> None:
        """Raise SchemaDriftError if the observed schema differs from the pin."""
        event = self.check_drift(name, observed)
        if event:
            raise SchemaDriftError(event)

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def get(self, name: str) -> Optional[PinnedSchema]:
        return self._pinned.get(name)

    def list_pinned(self) -> List[Dict[str, Any]]:
        return [p.to_dict() for p in self._pinned.values()]

    def list_drift_events(self) -> List[Dict[str, Any]]:
        return [e.to_dict() for e in self._drift_log]

    def clear_drift_log(self) -> None:
        self._drift_log.clear()


class SchemaDriftError(Exception):
    """Raised when a tool schema has drifted from its pinned definition."""

    def __init__(self, event: DriftEvent):
        self.event = event
        super().__init__(
            f"Schema drift for '{event.tool_name}' ({event.severity}): "
            + "; ".join(event.differences)
        )


# Module-level default registry used by the MCP gateway.
default_registry = SchemaRegistry()
