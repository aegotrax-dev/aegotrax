"""AgentGuard Risk Engine — Provenance & Decision Engine (hardened pilot)."""

from __future__ import annotations

import logging
import secrets
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Set, Tuple

import requests
import yaml
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from .audit_models import AuditEvent
from .config import settings, warn_insecure_defaults
from .security_utils import (
    email_domain_allowed,
    hostname_allowed,
    intent_is_restrictive,
    is_url_blocked,
    normalize_arg_text,
    redact_arguments,
    tool_has_side_effects,
)

logger = logging.getLogger("agentguard.risk_engine")

VERSION = "0.2.3"

app = FastAPI(
    title="AgentGuard Risk Engine",
    version=VERSION,
    description="Runtime policy + provenance decisions for AI agent tool calls",
)

# session_id → {history, sensitive_sources, last_access}
SESSION_PROVENANCE: Dict[str, Dict[str, Any]] = {}
# session_id → {user_intent, agent_id, user_id, updated_at}
SESSION_META: Dict[str, Dict[str, Any]] = {}

# Simple in-memory rate limiter: session_id → deque of timestamps
_RATE_BUCKETS: Dict[str, Deque[float]] = defaultdict(deque)


def require_api_key(x_api_key: Optional[str] = Header(default=None)) -> None:
    expected = settings.api_key
    if settings.require_api_key and not expected:
        raise HTTPException(
            status_code=503,
            detail="Server misconfigured: AGENTGUARD_REQUIRE_API_KEY=1 but no key set",
        )
    if not expected:
        return  # auth disabled (pilot / local only)
    if not x_api_key or not secrets.compare_digest(str(x_api_key), str(expected)):
        raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key")


class MultiAgentRequest(BaseModel):
    session_id: str
    agent_id: str
    user_intent: str = ""  # ignored when trust_server_intent_only=True
    tool: str
    arguments: Dict[str, Any] = Field(default_factory=dict)
    call_chain: List[str] = Field(default_factory=list)
    schema_drift: Optional[Dict[str, Any]] = None
    # Optional caller-declared user binding (for multi-tenant isolation)
    user_id: Optional[str] = None


class SessionUpdate(BaseModel):
    session_id: str
    user_intent: str
    agent_id: str = "default-agent"
    user_id: Optional[str] = None


class SessionReset(BaseModel):
    session_id: str


def _default_policy() -> dict:
    return {
        "risk_thresholds": {"block": 70, "require_approval": 50},
        "trusted_domains": ["@company.com"],
        "trusted_endpoints": ["https://api.internal-analytics.com/log"],
        "trusted_hosts": ["api.internal-analytics.com"],
        "sensitive_tools": ["list_users", "read_document", "read_db"],
        "dangerous_script_keywords": ["wipe", "delete", "rm", "logs", "privilege", "shred", "unlink"],
        "sensitive_payload_keywords": {
            "read_db": ["customer", "db_record", "sql", "confidential"],
            "list_users": ["user_list", "email_list", "ssn", "list_users"],
            "read_document": ["doc_content", "confidential", "read_document"],
        },
        "always_block_tools": [],
        "always_require_approval_tools": [],
        "outbound_tools": ["http_post", "send_email", "http_request", "webhook"],
    }


def load_policy() -> dict:
    if settings.policy_path:
        p = Path(settings.policy_path)
        if p.exists():
            with open(p, "r", encoding="utf-8") as f:
                return yaml.safe_load(f) or {}

    cwd_policy = Path.cwd() / "policy.yaml"
    if cwd_policy.exists():
        with open(cwd_policy, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    package_policy = Path(__file__).parent / "policy.yaml"
    if package_policy.exists():
        with open(package_policy, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    return _default_policy()


POLICY_CONFIG = load_policy()
RISK_THRESHOLDS = POLICY_CONFIG.get("risk_thresholds", {"block": 70, "require_approval": 50})


def reload_policy() -> dict:
    global POLICY_CONFIG, RISK_THRESHOLDS
    POLICY_CONFIG = load_policy()
    RISK_THRESHOLDS = POLICY_CONFIG.get("risk_thresholds", {"block": 70, "require_approval": 50})
    return POLICY_CONFIG


# ---------------------------------------------------------------------------
# Session lifecycle
# ---------------------------------------------------------------------------

def _purge_expired_sessions() -> None:
    ttl = settings.session_ttl_seconds
    if ttl <= 0:
        return
    now = time.time()
    expired = [
        sid
        for sid, data in SESSION_PROVENANCE.items()
        if now - data.get("last_access", 0) > ttl
    ]
    for sid in expired:
        SESSION_PROVENANCE.pop(sid, None)
        SESSION_META.pop(sid, None)
        _RATE_BUCKETS.pop(sid, None)


def _touch_session(session_id: str) -> Dict[str, Any]:
    data = SESSION_PROVENANCE.get(session_id)
    if data is None:
        data = {"history": [], "sensitive_sources": set(), "last_access": time.time()}
        SESSION_PROVENANCE[session_id] = data
    else:
        if not isinstance(data.get("sensitive_sources"), set):
            data["sensitive_sources"] = set(data.get("sensitive_sources") or [])
        data["last_access"] = time.time()
    return data


def _check_rate_limit(session_id: str) -> Optional[str]:
    limit = settings.rate_limit_per_session
    window = settings.rate_limit_window_seconds
    if limit <= 0 or window <= 0:
        return None
    now = time.time()
    bucket = _RATE_BUCKETS[session_id]
    while bucket and now - bucket[0] > window:
        bucket.popleft()
    if len(bucket) >= limit:
        return f"Rate limit exceeded: {limit} calls / {window}s for this session"
    bucket.append(now)
    return None


# ---------------------------------------------------------------------------
# Audit / webhooks
# ---------------------------------------------------------------------------

def log_audit_event(event: AuditEvent) -> None:
    log_path = Path(settings.audit_log)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(event.model_dump_json() + "\n")


def _webhook_url_allowed(url: str) -> bool:
    blocked, _ = is_url_blocked(url)
    return not blocked


def maybe_stream_audit(event: AuditEvent) -> None:
    webhook = settings.audit_webhook
    if not webhook or not _webhook_url_allowed(webhook):
        return
    try:
        requests.post(webhook, json=event.model_dump(), timeout=2.0)
    except Exception:
        pass


def maybe_notify_approval(event: AuditEvent) -> None:
    webhook = settings.approval_webhook
    if not webhook or event.decision != "REQUIRE_APPROVAL":
        return
    if not _webhook_url_allowed(webhook):
        return
    try:
        requests.post(webhook, json=event.model_dump(), timeout=2.0)
    except Exception:
        pass


def analyze_payload_sensitivity(arg_text: str, sensitive_sources: Set[str]) -> bool:
    keywords_map = POLICY_CONFIG.get("sensitive_payload_keywords", {})
    for source in sensitive_sources:
        keywords = keywords_map.get(source, [])
        if any(k in arg_text for k in keywords):
            return True
    return False


# ---------------------------------------------------------------------------
# Core evaluate
# ---------------------------------------------------------------------------

def evaluate(request: MultiAgentRequest) -> dict:
    _purge_expired_sessions()

    # Rate limit
    rate_err = _check_rate_limit(request.session_id)
    if rate_err:
        return {
            "decision": "BLOCK",
            "risk_score": 100,
            "reasons": [rate_err],
            "attack_path": request.tool,
            "matched_policies": ["rate_limit"],
            "session_id": request.session_id,
        }

    session_data = _touch_session(request.session_id)
    meta = SESSION_META.get(request.session_id)

    # --- Server-side intent only (critical trust boundary) ---
    if settings.trust_server_intent_only:
        if meta and meta.get("user_intent"):
            user_intent = meta["user_intent"]
        else:
            # No registered session intent → treat as unknown / unrestricted label
            # but still apply other controls. Callers should register via /session.
            user_intent = meta.get("user_intent") if meta else ""
            if not user_intent:
                user_intent = "(no server-side intent registered)"
    else:
        user_intent = request.user_intent or ""
        if meta and meta.get("user_intent") and user_intent in ("Execute user request", "", None):
            user_intent = meta["user_intent"]

    # Optional user_id binding check
    if meta and meta.get("user_id") and request.user_id:
        if meta["user_id"] != request.user_id:
            return {
                "decision": "BLOCK",
                "risk_score": 100,
                "reasons": [
                    f"Session user_id mismatch: session bound to '{meta['user_id']}', "
                    f"request claims '{request.user_id}'."
                ],
                "attack_path": request.tool,
                "matched_policies": ["user_binding"],
                "session_id": request.session_id,
            }

    score = 0
    reasons: List[str] = []
    matched: List[str] = []
    arg_text = normalize_arg_text(request.arguments)

    always_block = POLICY_CONFIG.get("always_block_tools") or []
    always_approval = POLICY_CONFIG.get("always_require_approval_tools") or []
    if request.tool in always_block:
        score = 100
        reasons.append(f"Tool '{request.tool}' is on the always-block list.")
        matched.append("always_block_tools")
    if request.tool in always_approval:
        score = max(score, RISK_THRESHOLDS.get("require_approval", 50))
        reasons.append(f"Tool '{request.tool}' requires human approval.")
        matched.append("always_require_approval_tools")

    # Schema pinning / drift
    if request.schema_drift:
        severity = (request.schema_drift.get("severity") or "medium").lower()
        diffs = request.schema_drift.get("differences") or []
        if severity == "high":
            score += 80
            reasons.append(
                "SCHEMA DRIFT (high): tool definition changed since pin — "
                + "; ".join(diffs[:3])
            )
            matched.append("schema_drift_high")
        elif severity == "medium":
            score += 40
            reasons.append(
                "SCHEMA DRIFT (medium): tool definition differs from pin — "
                + "; ".join(diffs[:3])
            )
            matched.append("schema_drift_medium")
        else:
            score += 15
            reasons.append("SCHEMA DRIFT (low): minor fingerprint mismatch.")
            matched.append("schema_drift_low")

    # Intent constraint (broader than just the word "only")
    if intent_is_restrictive(user_intent) and tool_has_side_effects(request.tool):
        score += 70
        reasons.append(
            f"Intent Constraint Violation: restrictive intent ({user_intent[:80]!r}) "
            f"but agent used side-effect tool '{request.tool}'."
        )
        matched.append("intent_constraint")

    # Dangerous scripts
    if request.tool in ("execute_script", "run_code", "shell"):
        dangerous_keywords = POLICY_CONFIG.get("dangerous_script_keywords", [])
        if any(k in arg_text for k in dangerous_keywords):
            score += 70
            reasons.append("CRITICAL: Malicious script execution attempt blocked.")
            matched.append("dangerous_script")

    # Track sensitive tools for provenance
    sensitive_tools = POLICY_CONFIG.get("sensitive_tools", [])
    if request.tool in sensitive_tools:
        session_data["sensitive_sources"].add(request.tool)

    # Email domain (strict)
    if request.tool in ("send_email", "email"):
        recipient = str(request.arguments.get("to", "") or "")
        if recipient:
            trusted_domains = POLICY_CONFIG.get("trusted_domains", [])
            if not email_domain_allowed(recipient, trusted_domains):
                score += 70
                reasons.append(
                    f"Security Violation: Email recipient '{recipient}' is outside trusted domains."
                )
                matched.append("email_domain")

    # Outbound / exfiltration
    outbound_tools = set(
        POLICY_CONFIG.get("outbound_tools")
        or ["http_post", "send_email", "http_request", "webhook"]
    )
    if request.tool in outbound_tools:
        destination = str(
            request.arguments.get("url")
            or request.arguments.get("to")
            or request.arguments.get("endpoint")
            or ""
        )

        # Block private/IMDS destinations outright
        if destination and request.tool in ("http_post", "http_request", "webhook"):
            blocked, why = is_url_blocked(destination)
            if blocked:
                score += 90
                reasons.append(f"SSRF/IMDS guard: destination blocked ({why}).")
                matched.append("ssrf_guard")

        has_sensitive_origin = len(session_data["sensitive_sources"]) > 0
        has_sensitive_payload = analyze_payload_sensitivity(
            arg_text, session_data["sensitive_sources"]
        )

        if destination:
            trusted_hosts = list(POLICY_CONFIG.get("trusted_hosts") or [])
            # also accept hosts extracted from trusted_endpoints for backward compat
            for ep in POLICY_CONFIG.get("trusted_endpoints") or []:
                trusted_hosts.append(ep)
            is_trusted_dest = hostname_allowed(destination, trusted_hosts)
            # emails use domain list separately; for http use hosts
            if request.tool in ("send_email", "email"):
                is_trusted_dest = email_domain_allowed(
                    destination, POLICY_CONFIG.get("trusted_domains") or []
                )

            if has_sensitive_origin and not is_trusted_dest:
                if has_sensitive_payload:
                    score += 70
                    reasons.append(
                        f"HIGH RISK: Exfiltration of sensitive payload to untrusted "
                        f"destination '{destination}'."
                    )
                    matched.append("exfiltration")
                else:
                    score += 50
                    reasons.append(
                        f"MEDIUM RISK: Outbound request to '{destination}' following "
                        f"sensitive data access."
                    )
                    matched.append("outbound_after_sensitive")
            elif not is_trusted_dest and request.tool in ("http_post", "http_request", "webhook"):
                # Untrusted outbound even without prior sensitive read — still elevate
                score += 25
                reasons.append(f"Outbound to untrusted host: '{destination}'.")
                matched.append("untrusted_outbound")
        else:
            if has_sensitive_payload:
                score += 50
                reasons.append("WARNING: Sensitive payload detected with unknown destination.")
                matched.append("sensitive_payload_unknown_dest")

    session_data["history"].append(
        {
            "agent_id": request.agent_id,
            "tool": request.tool,
            "timestamp": time.time(),
        }
    )
    # cap history length
    if len(session_data["history"]) > 200:
        session_data["history"] = session_data["history"][-200:]
    SESSION_PROVENANCE[request.session_id] = session_data

    final_score = min(score, 100)
    block_threshold = RISK_THRESHOLDS.get("block", 70)
    approval_threshold = RISK_THRESHOLDS.get("require_approval", 50)

    if final_score >= block_threshold:
        decision = "BLOCK"
    elif final_score >= approval_threshold:
        decision = "REQUIRE_APPROVAL"
    else:
        decision = "ALLOW"

    attack_path = (
        " -> ".join(request.call_chain + [request.tool]) if request.call_chain else request.tool
    )

    audit_args = (
        redact_arguments(request.arguments)
        if settings.audit_redact
        else request.arguments
    )

    audit_event = AuditEvent(
        session_id=request.session_id,
        agent_id=request.agent_id,
        tool_name=request.tool,
        arguments=audit_args,
        user_intent=user_intent,
        risk_score=final_score,
        decision=decision,
        reasons=reasons,
        attack_path=attack_path,
        matched_policies=matched,
    )
    log_audit_event(audit_event)
    maybe_stream_audit(audit_event)
    maybe_notify_approval(audit_event)

    return {
        "decision": decision,
        "risk_score": final_score,
        "reasons": reasons,
        "attack_path": attack_path,
        "matched_policies": matched,
        "session_id": request.session_id,
        "server_intent": user_intent,
    }


# ---------------------------------------------------------------------------
# HTTP API
# ---------------------------------------------------------------------------

@app.on_event("startup")
def _on_startup() -> None:
    warn_insecure_defaults()


@app.get("/health")
def health():
    return {
        "status": "ok",
        "version": VERSION,
        "auth_enabled": bool(settings.api_key),
        "require_api_key": settings.require_api_key,
        "server_intent_only": settings.trust_server_intent_only,
        "session_ttl_seconds": settings.session_ttl_seconds,
        "sessions": len(SESSION_PROVENANCE),
    }


@app.post("/verify-multi-agent")
def verify_multi_agent(request: MultiAgentRequest, _: None = Depends(require_api_key)):
    return evaluate(request)


@app.post("/session")
def upsert_session(body: SessionUpdate, _: None = Depends(require_api_key)):
    SESSION_META[body.session_id] = {
        "user_intent": body.user_intent,
        "agent_id": body.agent_id,
        "user_id": body.user_id,
        "updated_at": time.time(),
    }
    if body.session_id not in SESSION_PROVENANCE:
        SESSION_PROVENANCE[body.session_id] = {
            "history": [],
            "sensitive_sources": set(),
            "last_access": time.time(),
        }
    return {
        "ok": True,
        "session_id": body.session_id,
        "user_intent": body.user_intent,
        "user_id": body.user_id,
    }


@app.post("/session/reset")
def reset_session(body: SessionReset, _: None = Depends(require_api_key)):
    SESSION_PROVENANCE.pop(body.session_id, None)
    SESSION_META.pop(body.session_id, None)
    _RATE_BUCKETS.pop(body.session_id, None)
    return {"ok": True, "session_id": body.session_id}


@app.get("/session/{session_id}")
def get_session(session_id: str, _: None = Depends(require_api_key)):
    _purge_expired_sessions()
    prov = SESSION_PROVENANCE.get(session_id)
    meta = SESSION_META.get(session_id)
    if not prov and not meta:
        raise HTTPException(status_code=404, detail="Session not found")
    sensitive = list(prov["sensitive_sources"]) if prov else []
    history = prov.get("history", []) if prov else []
    return {
        "session_id": session_id,
        "meta": meta,
        "sensitive_sources": sensitive,
        "history": history,
    }


@app.post("/policy/reload")
def policy_reload(_: None = Depends(require_api_key)):
    cfg = reload_policy()
    # Audit the reload itself
    event = AuditEvent(
        session_id="__system__",
        agent_id="risk-engine",
        tool_name="policy.reload",
        arguments={},
        user_intent="system",
        risk_score=0,
        decision="ALLOW",
        reasons=["Policy reloaded"],
        attack_path="policy.reload",
        matched_policies=["policy_reload"],
    )
    log_audit_event(event)
    return {"ok": True, "thresholds": cfg.get("risk_thresholds"), "version": VERSION}


def main():
    import uvicorn

    warn_insecure_defaults()
    uvicorn.run(app, host=settings.host, port=settings.port)


if __name__ == "__main__":
    main()
