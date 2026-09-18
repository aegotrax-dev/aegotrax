"""AgentGuard configuration — env-first, pilot-friendly."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

load_dotenv()


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
    api_key: Optional[str] = _env("AGENTGUARD_API_KEY")  # if set, required on all /verify calls

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
    # If decision == REQUIRE_APPROVAL and webhook is set, engine POSTs the event there.
    approval_webhook: Optional[str] = _env("AGENTGUARD_APPROVAL_WEBHOOK")

    # Pilot: stream ALL audit events (optional)
    # If set, every decision is POSTed as JSON to this URL (best-effort, never blocks decisions).
    audit_webhook: Optional[str] = _env("AGENTGUARD_AUDIT_WEBHOOK")

    # Fail closed if engine unreachable (SDK/gateway)
    fail_closed: bool = _env_bool("AGENTGUARD_FAIL_CLOSED", True)

    # Request timeout to engine (seconds)
    engine_timeout: float = float(_env("AGENTGUARD_ENGINE_TIMEOUT", "2.0") or "2.0")


settings = Settings()
