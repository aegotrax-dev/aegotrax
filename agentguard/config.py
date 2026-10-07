"""AgentGuard configuration — env-first, pilot-friendly."""

from __future__ import annotations

import logging
import os
from typing import Optional

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("agentguard.config")


def _env(key: str, default: Optional[str] = None) -> Optional[str]:
    val = os.getenv(key)
    if val is None or val.strip() == "":
        return default
    return val.strip()


def _env_bool(key: str, default: bool = False) -> bool:
    val = _env(key)
    if val is None:
        return default
    return val.lower() in ("1", "true", "yes", "on")


class Settings:
    """Central settings for engine + gateway + SDK."""

    # Engine bind
    host: str = _env("AGENTGUARD_HOST", "127.0.0.1") or "127.0.0.1"
    port: int = int(_env("AGENTGUARD_PORT", "8000") or "8000")

    # Auth between clients (gateway/SDK) and engine
    # If AGENTGUARD_REQUIRE_API_KEY=true (default in hardened mode), missing key → refuse to start decisions
    api_key: Optional[str] = _env("AGENTGUARD_API_KEY")
    require_api_key: bool = _env_bool("AGENTGUARD_REQUIRE_API_KEY", False)

    # URLs
    engine_url: str = _env(
        "AGENTGUARD_ENGINE_URL", "http://127.0.0.1:8000/verify-multi-agent"
    ) or "http://127.0.0.1:8000/verify-multi-agent"
    engine_base: str = _env(
        "AGENTGUARD_ENGINE_BASE", "http://127.0.0.1:8000"
    ) or "http://127.0.0.1:8000"

    # Gateway behaviour
    mode: str = _env("AGENTGUARD_MODE", "simulate") or "simulate"  # simulate|echo|forward

    # Policy / audit paths
    policy_path: Optional[str] = _env("AGENTGUARD_POLICY_PATH")
    audit_log: str = _env("AGENTGUARD_AUDIT_LOG", "agentguard_audit.log") or "agentguard_audit.log"
    session_context_path: Optional[str] = _env("AGENTGUARD_SESSION_CONTEXT")

    # Pilot: approval webhook (optional)
    approval_webhook: Optional[str] = _env("AGENTGUARD_APPROVAL_WEBHOOK")

    # Pilot: stream ALL audit events (optional)
    audit_webhook: Optional[str] = _env("AGENTGUARD_AUDIT_WEBHOOK")

    # Fail closed if engine unreachable (SDK/gateway)
    fail_closed: bool = _env_bool("AGENTGUARD_FAIL_CLOSED", True)

    # Request timeout to engine (seconds)
    engine_timeout: float = float(_env("AGENTGUARD_ENGINE_TIMEOUT", "2.0") or "2.0")

    # Session TTL (seconds). 0 = never expire (legacy pilot behaviour).
    session_ttl_seconds: int = int(_env("AGENTGUARD_SESSION_TTL", "3600") or "3600")

    # Trust only server-side session intent (ignore client-supplied user_intent on verify)
    trust_server_intent_only: bool = _env_bool("AGENTGUARD_SERVER_INTENT_ONLY", True)

    # Basic rate limit: max verify calls per session per window
    rate_limit_per_session: int = int(_env("AGENTGUARD_RATE_LIMIT", "120") or "120")
    rate_limit_window_seconds: int = int(_env("AGENTGUARD_RATE_WINDOW", "60") or "60")

    # Redact sensitive argument keys in audit log
    audit_redact: bool = _env_bool("AGENTGUARD_AUDIT_REDACT", True)

    # Pending approval TTL (seconds) for REQUIRE_APPROVAL queue
    approval_ttl_seconds: int = int(_env("AGENTGUARD_APPROVAL_TTL", "1800") or "1800")


settings = Settings()


def warn_insecure_defaults() -> None:
    """Log warnings for insecure pilot defaults that should not ship to prod."""
    if not settings.api_key:
        logger.warning(
            "AGENTGUARD_API_KEY is not set — engine endpoints are unauthenticated. "
            "Set AGENTGUARD_API_KEY (and AGENTGUARD_REQUIRE_API_KEY=1) before any shared deployment."
        )
    if settings.require_api_key and not settings.api_key:
        logger.error(
            "AGENTGUARD_REQUIRE_API_KEY=1 but AGENTGUARD_API_KEY is empty — "
            "all authenticated endpoints will reject requests."
        )
    if settings.host in ("0.0.0.0", "::"):
        logger.warning(
            "Engine bound to %s — do not expose without a strong API key and network controls.",
            settings.host,
        )
    if not settings.fail_closed:
        logger.warning("AGENTGUARD_FAIL_CLOSED=false — engine outages will ALLOW tool calls.")
    if not settings.trust_server_intent_only:
        logger.warning(
            "AGENTGUARD_SERVER_INTENT_ONLY=false — clients can supply arbitrary user_intent "
            "and bypass intent constraints."
        )
