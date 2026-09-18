"""AgentGuard Risk Engine — Provenance & Decision Engine (Pilot)."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import requests
import yaml
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from .audit_models import AuditEvent
from .config import settings

app = FastAPI(
    title="AgentGuard Risk Engine",
    version="0.2.0",
    description="Runtime policy + provenance decisions for AI agent tool calls",
)

SESSION_PROVENANCE: Dict[str, Dict[str, Any]] = {}
SESSION_META: Dict[str, Dict[str, Any]] = {}


def require_api_key(x_api_key: Optional[str] = Header(default=None)) -> None:
    expected = settings.api_key
    if not expected:
        return
    if not x_api_key or x_api_key != expected:
        raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key")


class MultiAgentRequest(BaseModel):
    session_id: str
    agent_id: str
    user_intent: str
    tool: str
    arguments: Dict[str, Any] = Field(default_factory=dict)
    call_chain: List[str] = Field(default_factory=list)


class SessionUpdate(BaseModel):
    session_id: str
    user_intent: str
    agent_id: str = "default-agent"


class SessionReset(BaseModel):
    session_id: str


def _default_policy() -> dict:
    return {
        "risk_thresholds": {"block": 70, "require_approval": 50},
        "trusted_domains": ["@company.com"],
        "trusted_endpoints": ["https://api.internal-analytics.com/log"],
        "sensitive_tools": ["list_users", "read_document", "read_db"],
        "dangerous_script_keywords": ["wipe", "delete", "rm", "logs", "privilege"],
        "sensitive_payload_keywords": {
            "read_db": ["customer", "db_record", "sql", "confidential"],
            "list_users": ["user_list", "email_list", "ssn", "list_users"],
            "read_document": ["doc_content", "confidential", "read_document"],
        },
        "always_block_tools": [],
        "always_require_approval_tools": [],
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


def log_audit_event(event: AuditEvent) -> None:
    log_path = Path(settings.audit_log)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(event.model_dump_json() + "\n")


def maybe_stream_audit(event: AuditEvent) -> None:
    """Send every audit event to optional central webhook (pilot observability)."""
    webhook = settings.audit_webhook
    if not webhook:
        return
    try:
        requests.post(webhook, json=event.model_dump(), timeout=2.0)
    except Exception:
        # Never break the decision path because of logging
        pass


def maybe_notify_approval(event: AuditEvent) -> None:
    webhook = settings.approval_webhook
    if not webhook or event.decision != "REQUIRE_APPROVAL":
        return
    try:
        requests.post(webhook, json=event.model_dump(), timeout=2.0)
    except Exception:
        pass


def analyze_payload_sensitivity(arguments: Dict[str, Any], sensitive_sources: Set[str]) -> bool:
    arg_str = str(arguments).lower()
    keywords_map = POLICY_CONFIG.get("sensitive_payload_keywords", {})
    for source in sensitive_sources:
        keywords = keywords_map.get(source, [])
        if any(k in arg_str for k in keywords):
            return True
    return False


def evaluate(request: MultiAgentRequest) -> dict:
    session_data = SESSION_PROVENANCE.get(
        request.session_id,
        {"history": [], "sensitive_sources": set()},
    )
    if not isinstance(session_data.get("sensitive_sources"), set):
        session_data["sensitive_sources"] = set(session_data.get("sensitive_sources") or [])

    meta = SESSION_META.get(request.session_id)
    user_intent = request.user_intent
    if meta and meta.get("user_intent") and user_intent in ("Execute user request", "", None):
        user_intent = meta["user_intent"]

    score = 0
    reasons: List[str] = []
    matched: List[str] = []
    intent_lower = (user_intent or "").lower()
    arg_str = str(request.arguments).lower()

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

    if "only" in intent_lower and request.tool in [
        "send_email",
        "execute_script",
        "http_post",
        "read_db",
        "list_users",
        "query_customers",
        "export_records",
    ]:
        score += 70
        reasons.append(
            f"Intent Constraint Violation: User specified 'only', but agent used '{request.tool}'."
        )
        matched.append("intent_constraint")

    if request.tool in ("execute_script", "run_code", "shell"):
        dangerous_keywords = POLICY_CONFIG.get("dangerous_script_keywords", [])
        if any(k in arg_str for k in dangerous_keywords):
            score += 70
            reasons.append("CRITICAL: Malicious script execution attempt blocked.")
            matched.append("dangerous_script")

    sensitive_tools = POLICY_CONFIG.get("sensitive_tools", [])
    if request.tool in sensitive_tools:
        session_data["sensitive_sources"].add(request.tool)

    if request.tool in ("send_email", "email"):
        recipient = str(request.arguments.get("to", "") or "")
        if recipient:
            trusted_domains = POLICY_CONFIG.get("trusted_domains", [])
            is_trusted = any(recipient.endswith(d) for d in trusted_domains)
            if not is_trusted:
                score += 70
                reasons.append(
                    f"Security Violation: Email recipient '{recipient}' is outside trusted domains."
                )
                matched.append("email_domain")

    if request.tool in ("http_post", "send_email", "http_request", "webhook"):
        destination = str(
            request.arguments.get("url")
            or request.arguments.get("to")
            or request.arguments.get("endpoint")
            or ""
        ).lower()
        has_sensitive_origin = len(session_data["sensitive_sources"]) > 0
        has_sensitive_payload = analyze_payload_sensitivity(
            request.arguments, session_data["sensitive_sources"]
        )

        if destination:
            trusted_list = (POLICY_CONFIG.get("trusted_endpoints") or []) + (
                POLICY_CONFIG.get("trusted_domains") or []
            )
            is_trusted_dest = any(t in destination for t in trusted_list)

            if has_sensitive_origin and not is_trusted_dest:
                if has_sensitive_payload:
                    score += 70
                    reasons.append(
                        f"HIGH RISK: Exfiltration of sensitive payload to untrusted destination '{destination}'."
                    )
                    matched.append("exfiltration")
                else:
                    score += 50
                    reasons.append(
                        f"MEDIUM RISK: Outbound request to '{destination}' following sensitive data access."
                    )
                    matched.append("outbound_after_sensitive")
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

    audit_event = AuditEvent(
        session_id=request.session_id,
        agent_id=request.agent_id,
        tool_name=request.tool,
        arguments=request.arguments,
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
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "version": "0.2.0",
        "auth_enabled": bool(settings.api_key),
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
        "updated_at": time.time(),
    }
    if body.session_id not in SESSION_PROVENANCE:
        SESSION_PROVENANCE[body.session_id] = {"history": [], "sensitive_sources": set()}
    return {"ok": True, "session_id": body.session_id, "user_intent": body.user_intent}


@app.post("/session/reset")
def reset_session(body: SessionReset, _: None = Depends(require_api_key)):
    SESSION_PROVENANCE.pop(body.session_id, None)
    SESSION_META.pop(body.session_id, None)
    return {"ok": True, "session_id": body.session_id}


@app.get("/session/{session_id}")
def get_session(session_id: str, _: None = Depends(require_api_key)):
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
    return {"ok": True, "thresholds": cfg.get("risk_thresholds")}


def main():
    import uvicorn

    uvicorn.run(app, host=settings.host, port=settings.port)


if __name__ == "__main__":
    main()
