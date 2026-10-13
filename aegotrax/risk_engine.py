"""Aegotrax Risk Engine — Provenance & Decision Engine (hardened pilot)."""

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

from .approval import approval_queue, call_fingerprint
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

logger = logging.getLogger("aegotrax.risk_engine")

VERSION = "0.2.6"

app = FastAPI(
    title="Aegotrax Risk Engine",
    version=VERSION,
    description="Runtime policy + provenance decisions for AI agent tool calls",
)

# session_id → {history, sensitive_sources, last_access}
SESSION_PROVENANCE: Dict[str, Dict[str, Any]] = {}
# session_id → {user_intent, agent_id, user_id, updated_at}
SESSION_META: Dict[str, Dict[str, Any]] = {}

# Simple in-memory rate limiter: session_id → deque of timestamps
_RATE_BUCKETS: Dict[str, Deque[float]] = defaultdict(deque)

# Align in-memory approval queue TTL with settings
approval_queue.ttl_seconds = max(60, int(settings.approval_ttl_seconds))


def require_api_key(x_api_key: Optional[str] = Header(default=None)) -> None:
    expected = settings.api_key
    if settings.require_api_key and not expected:
        raise HTTPException(
            status_code=503,
            detail="Server misconfigured: AEGOTRAX_REQUIRE_API_KEY=1 but no key set",
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
    # Human-approval resume (from a prior REQUIRE_APPROVAL)
    approval_id: Optional[str] = None
    approval_token: Optional[str] = None


class SessionScope(BaseModel):
    """Optional structured envelope for a session (0.2.5+).

    When present, /verify becomes a consistency check against this scope
    in addition to heuristic risk scoring.
    """
    allowed_tools: Optional[List[str]] = None
    denied_tools: Optional[List[str]] = None
    allowed_hosts: Optional[List[str]] = None
    max_risk_without_approval: Optional[int] = None


class SessionUpdate(BaseModel):
    session_id: str
    user_intent: str
    agent_id: str = "default-agent"
    user_id: Optional[str] = None
    scope: Optional[SessionScope] = None


class SessionReset(BaseModel):
    session_id: str


class ApprovalDecide(BaseModel):
    approval_id: str
    decision: str  # approve | deny
    token: str
    decided_by: str = "human"


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
        "read_budgets": {
            "default_max_calls": 20,
            "on_exceed": "REQUIRE_APPROVAL",
            "tools": {},
        },
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
        data = {
            "history": [],
            "sensitive_sources": set(),
            "read_counts": {},
            "last_access": time.time(),
        }
        SESSION_PROVENANCE[session_id] = data
    else:
        if not isinstance(data.get("sensitive_sources"), set):
            data["sensitive_sources"] = set(data.get("sensitive_sources") or [])
        if not isinstance(data.get("read_counts"), dict):
            data["read_counts"] = {}
        data["last_access"] = time.time()
    return data


def _budget_limit_for_tool(tool: str) -> Optional[int]:
    """Max calls for tool this session, or None if budgets do not apply."""
    budgets = POLICY_CONFIG.get("read_budgets") or {}
    if not budgets:
        return None
    sensitive = set(POLICY_CONFIG.get("sensitive_tools") or [])
    tool_overrides = budgets.get("tools") or {}
    if tool in tool_overrides:
        lim = tool_overrides[tool].get("max_calls")
        return int(lim) if lim is not None else None
    if tool not in sensitive:
        return None
    default = budgets.get("default_max_calls")
    if default is None:
        return None
    return int(default)


def _budget_on_exceed() -> str:
    budgets = POLICY_CONFIG.get("read_budgets") or {}
    action = (budgets.get("on_exceed") or "REQUIRE_APPROVAL").strip().upper()
    return action if action in ("BLOCK", "REQUIRE_APPROVAL") else "REQUIRE_APPROVAL"

def _end_session_on_budget_exceed() -> bool:
    budgets = POLICY_CONFIG.get("read_budgets") or {}
    return bool(budgets.get("end_session_on_exceed", True))


def _close_session(session_id: str, reason: str) -> None:
    meta = SESSION_META.get(session_id) or {}
    meta["closed"] = True
    meta["closed_reason"] = reason
    meta["closed_at"] = time.time()
    SESSION_META[session_id] = meta


def _session_is_closed(session_id: str) -> Optional[str]:
    meta = SESSION_META.get(session_id) or {}
    if meta.get("closed"):
        return str(meta.get("closed_reason") or "session_closed")
    return None


def _tool_class(tool: str) -> str:
    """open_risk | reduce_risk — default open_risk (fail-closed)."""
    cfg = POLICY_CONFIG.get("tool_classes") or {}
    default = (cfg.get("default") or "open_risk").strip().lower()
    if tool in (cfg.get("reduce_risk") or []):
        return "reduce_risk"
    if tool in (cfg.get("open_risk") or []):
        return "open_risk"
    return default if default in ("open_risk", "reduce_risk") else "open_risk"


def _sensitivity_cfg() -> dict:
    return POLICY_CONFIG.get("sensitivity_ceiling") or {}


def _raise_sensitivity_ceiling(session_data: Dict[str, Any], tool: str) -> int:
    cfg = _sensitivity_cfg()
    if not cfg.get("enabled", True):
        return int(session_data.get("sensitivity_ceiling") or 0)
    raise_tools = set(cfg.get("raise_on_tools") or [])
    if not raise_tools:
        raise_tools = set(POLICY_CONFIG.get("sensitive_tools") or [])
    ceiling = int(session_data.get("sensitivity_ceiling") or 0)
    if tool in raise_tools:
        target = int(cfg.get("raise_to") or 1)
        if target > ceiling:
            ceiling = target
            session_data["sensitivity_ceiling"] = ceiling
    return ceiling



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

    # --- Resume path: prior REQUIRE_APPROVAL was human-approved ---
    if request.approval_id and request.approval_token:
        err = approval_queue.consume_if_approved(
            approval_id=request.approval_id,
            token=request.approval_token,
            tool=request.tool,
            arguments=request.arguments or {},
            session_id=request.session_id,
        )
        if err is None:
            # Single-use approved call — short-circuit to ALLOW with audit
            user_intent = (meta or {}).get("user_intent") or request.user_intent or ""
            attack_path = (
                " -> ".join(request.call_chain + [request.tool])
                if request.call_chain
                else request.tool
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
                risk_score=0,
                decision="ALLOW",
                reasons=[f"Human-approved (approval_id={request.approval_id}, consumed)"],
                attack_path=attack_path,
                matched_policies=["human_approval"],
            )
            log_audit_event(audit_event)
            maybe_stream_audit(audit_event)
            return {
                "decision": "ALLOW",
                "risk_score": 0,
                "reasons": [f"Human-approved (approval_id={request.approval_id})"],
                "attack_path": attack_path,
                "matched_policies": ["human_approval"],
                "session_id": request.session_id,
                "server_intent": user_intent,
                "approval_id": request.approval_id,
                "approval_status": "consumed",
            }
        # Token supplied but not valid → BLOCK (do not fall through silently)
        return {
            "decision": "BLOCK",
            "risk_score": 100,
            "reasons": [f"Approval resume failed: {err}"],
            "attack_path": request.tool,
            "matched_policies": ["approval_resume_failed"],
            "session_id": request.session_id,
            "approval_id": request.approval_id,
            "approval_status": "invalid",
        }

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



    # --- Hold new permits while prior delivery is uncertain (0.2.6) ---
    try:
        fp_hold = call_fingerprint(request.tool, request.arguments or {})
        prior = approval_queue.uncertain_fingerprint(fp_hold)
        if prior is not None and not (request.approval_id and request.approval_token):
            return {
                "decision": "BLOCK",
                "risk_score": 80,
                "reasons": [
                    f"Prior approval {prior.approval_id} for this tool+args has delivery_status="
                    f"{prior.delivery_status}. Resolve via POST /approval/delivery before a new permit."
                ],
                "attack_path": request.tool,
                "matched_policies": ["delivery_uncertain_hold"],
                "session_id": request.session_id,
                "approval_id": prior.approval_id,
                "delivery_status": prior.delivery_status,
            }
    except Exception:
        pass

    # --- Session exhausted / closed (0.2.6) ---
    closed_reason = _session_is_closed(request.session_id)
    if closed_reason:
        return {
            "decision": "BLOCK",
            "risk_score": 100,
            "reasons": [
                f"Session closed ({closed_reason}). Register a new /session with a fresh intent envelope."
            ],
            "attack_path": request.tool,
            "matched_policies": ["session_exhausted"],
            "session_id": request.session_id,
            "session_closed": True,
            "closed_reason": closed_reason,
        }


    # --- Scoped session intent (0.2.5) ---
    scope = (meta or {}).get("scope") if meta else None
    if not isinstance(scope, dict):
        scope = None

    if scope:
        denied = scope.get("denied_tools") or []
        allowed = scope.get("allowed_tools")
        if request.tool in denied:
            return {
                "decision": "BLOCK",
                "risk_score": 100,
                "reasons": [
                    f"Session scope denies tool '{request.tool}' "
                    f"(denied_tools={denied})."
                ],
                "attack_path": request.tool,
                "matched_policies": ["session_scope_denied"],
                "session_id": request.session_id,
                "server_intent": (
                    (meta or {}).get("user_intent")
                    if settings.trust_server_intent_only
                    else (request.user_intent or "")
                ),
            }
        if allowed is not None and len(allowed) > 0 and request.tool not in allowed:
            return {
                "decision": "BLOCK",
                "risk_score": 100,
                "reasons": [
                    f"Tool '{request.tool}' is outside session scope "
                    f"(allowed_tools={allowed})."
                ],
                "attack_path": request.tool,
                "matched_policies": ["session_scope_allowed"],
                "session_id": request.session_id,
                "server_intent": (
                    (meta or {}).get("user_intent")
                    if settings.trust_server_intent_only
                    else (request.user_intent or "")
                ),
            }

    budget_info = None
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

    # --- Cumulative read budgets (0.2.5) ---
    budget_limit = _budget_limit_for_tool(request.tool)
    if budget_limit is not None:
        counts = session_data.setdefault("read_counts", {})
        new_count = int(counts.get(request.tool, 0)) + 1
        counts[request.tool] = new_count
        budget_info = {"tool": request.tool, "count": new_count, "limit": budget_limit}
        if new_count > budget_limit:
            action = _budget_on_exceed()
            reasons.append(
                f"Read budget exceeded for tool '{request.tool}': "
                f"{new_count}/{budget_limit} calls this session."
            )
            matched.append("read_budget")
            if _end_session_on_budget_exceed():
                _close_session(
                    request.session_id,
                    f"read_budget_exhausted tool={request.tool}",
                )
                matched.append("session_budget_exhausted")
                reasons.append(
                    "Session closed after read budget exceed — open a new /session to continue."
                )
            if action == "BLOCK":
                score = 100
            else:
                score = max(score, RISK_THRESHOLDS.get("require_approval", 50))

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


    # --- Sensitivity ceiling (0.2.6): raise on sensitive reads; gate outbound ---
    ceiling = _raise_sensitivity_ceiling(session_data, request.tool)
    scfg = _sensitivity_cfg()
    if scfg.get("enabled", True):
        outbound = set(POLICY_CONFIG.get("outbound_tools") or [])
        min_c = int(scfg.get("outbound_min_ceiling") or 1)
        if request.tool in outbound and ceiling >= min_c:
            action = (scfg.get("on_outbound") or "REQUIRE_APPROVAL").strip().upper()
            if action not in ("BLOCK", "REQUIRE_APPROVAL"):
                action = "REQUIRE_APPROVAL"
            reasons.append(
                f"Session sensitivity ceiling={ceiling}: outbound tool '{request.tool}' "
                f"requires {action} after sensitive context."
            )
            matched.append("sensitivity_ceiling_outbound")
            if action == "BLOCK":
                score = max(score, RISK_THRESHOLDS.get("block", 70))
            else:
                score = max(score, RISK_THRESHOLDS.get("require_approval", 50))

    # --- Tool class open_risk default fail-closed (0.2.6) ---
    tclass = _tool_class(request.tool)
    matched.append(f"tool_class:{tclass}")
    if tclass == "open_risk":
        tc = POLICY_CONFIG.get("tool_classes") or {}
        min_dec = (tc.get("open_risk_min_decision") or "REQUIRE_APPROVAL").strip().upper()
        if min_dec == "BLOCK":
            score = max(score, RISK_THRESHOLDS.get("block", 70))
            reasons.append(f"Tool '{request.tool}' classed open_risk (fail-closed) → BLOCK.")
            matched.append("tool_class_open_risk")
        else:
            score = max(score, RISK_THRESHOLDS.get("require_approval", 50))
            reasons.append(
                f"Tool '{request.tool}' classed open_risk (default fail-closed) → REQUIRE_APPROVAL."
            )
            matched.append("tool_class_open_risk")

    final_score = min(score, 100)
    block_threshold = RISK_THRESHOLDS.get("block", 70)
    approval_threshold = RISK_THRESHOLDS.get("require_approval", 50)

    if scope and scope.get("max_risk_without_approval") is not None:
        try:
            session_bar = int(scope["max_risk_without_approval"])
            approval_threshold = min(approval_threshold, max(0, session_bar))
        except (TypeError, ValueError):
            pass

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

    approval_id = None
    approval_token = None
    approval_status = None
    approval_expires_at = None

    if decision == "REQUIRE_APPROVAL":
        pending = approval_queue.create(
            session_id=request.session_id,
            agent_id=request.agent_id,
            tool=request.tool,
            arguments=request.arguments or {},
            risk_score=final_score,
            reasons=reasons,
            user_intent=user_intent,
        )
        approval_id = pending.approval_id
        approval_token = pending.token
        approval_status = pending.status
        approval_expires_at = pending.expires_at
        matched.append("approval_queued")

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

    if decision == "REQUIRE_APPROVAL":
        # Enrich webhook payload with approval credentials for human operators
        try:
            extra = audit_event.model_dump()
            extra["approval_id"] = approval_id
            extra["approval_token"] = approval_token
            extra["approval_expires_at"] = approval_expires_at
            webhook = settings.approval_webhook
            if webhook and _webhook_url_allowed(webhook):
                requests.post(webhook, json=extra, timeout=2.0)
        except Exception:
            pass
    else:
        maybe_notify_approval(audit_event)

    result = {
        "decision": decision,
        "risk_score": final_score,
        "reasons": reasons,
        "attack_path": attack_path,
        "matched_policies": matched,
        "session_id": request.session_id,
        "server_intent": user_intent,
    }
    if approval_id:
        result["approval_id"] = approval_id
        result["approval_token"] = approval_token
        result["approval_status"] = approval_status
        result["approval_expires_at"] = approval_expires_at
    if budget_info is not None:
        result["read_budget"] = budget_info
    if scope:
        result["session_scope"] = {
            k: scope.get(k)
            for k in (
                "allowed_tools",
                "denied_tools",
                "allowed_hosts",
                "max_risk_without_approval",
            )
            if scope.get(k) is not None
        }
    return result


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
        "approval_ttl_seconds": settings.approval_ttl_seconds,
        "pending_approvals": len(approval_queue.list_pending()),
        "sessions": len(SESSION_PROVENANCE),
    }


@app.post("/verify-multi-agent")
def verify_multi_agent(request: MultiAgentRequest, _: None = Depends(require_api_key)):
    return evaluate(request)


@app.post("/session")
def upsert_session(body: SessionUpdate, _: None = Depends(require_api_key)):
    scope_data = body.scope.model_dump(exclude_none=True) if body.scope is not None else None
    SESSION_META[body.session_id] = {
        "user_intent": body.user_intent,
        "agent_id": body.agent_id,
        "user_id": body.user_id,
        "scope": scope_data,
        "updated_at": time.time(),
        "closed": False,
        "closed_reason": None,
    }
    if body.session_id not in SESSION_PROVENANCE:
        SESSION_PROVENANCE[body.session_id] = {
            "history": [],
            "sensitive_sources": set(),
            "read_counts": {},
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
    read_counts = dict(prov.get("read_counts") or {}) if prov else {}
    ceiling = int(prov.get("sensitivity_ceiling") or 0) if prov else 0
    return {
        "session_id": session_id,
        "meta": meta,
        "sensitive_sources": sensitive,
        "read_counts": read_counts,
        "sensitivity_ceiling": ceiling,
        "closed": bool((meta or {}).get("closed")),
        "closed_reason": (meta or {}).get("closed_reason"),
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



@app.post("/approval/decide")
def approval_decide(body: ApprovalDecide, _: None = Depends(require_api_key)):
    """Approve or deny a pending REQUIRE_APPROVAL item (human / external workflow)."""
    try:
        item = approval_queue.decide(
            body.approval_id,
            decision=body.decision,
            token=body.token,
            decided_by=body.decided_by or "human",
        )
    except KeyError:
        raise HTTPException(status_code=404, detail="approval not found")
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))

    event = AuditEvent(
        session_id=item.session_id,
        agent_id=item.agent_id,
        tool_name=item.tool,
        arguments=redact_arguments(item.arguments) if settings.audit_redact else item.arguments,
        user_intent=item.user_intent,
        risk_score=item.risk_score,
        decision=f"APPROVAL_{item.status.upper()}",
        reasons=[f"Human decision={item.status} by {item.decided_by}"],
        attack_path=item.tool,
        matched_policies=["human_approval_decide"],
    )
    log_audit_event(event)
    maybe_stream_audit(event)
    return {"ok": True, **item.to_public_dict()}


@app.get("/approval/{approval_id}")
def approval_status(approval_id: str, _: None = Depends(require_api_key)):
    item = approval_queue.get(approval_id)
    if item is None:
        raise HTTPException(status_code=404, detail="approval not found")
    data = item.to_public_dict()
    # never expose token on status GET
    return data


@app.get("/approvals/pending")
def approvals_pending(session_id: Optional[str] = None, _: None = Depends(require_api_key)):
    return {"pending": approval_queue.list_pending(session_id=session_id)}


def main():
    import uvicorn

    warn_insecure_defaults()
    uvicorn.run(app, host=settings.host, port=settings.port)


if __name__ == "__main__":
    main()
