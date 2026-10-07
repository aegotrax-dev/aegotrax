"""Human-approval queue for REQUIRE_APPROVAL decisions.

Flow
----
1. evaluate() decides REQUIRE_APPROVAL
2. create_pending() stores the call fingerprint + secrets.token
3. Response returns approval_id + approval_token (status=pending)
4. Human / webhook calls POST /approval/decide {approve|deny}
5. Client re-submits the same tool call with approval_id + approval_token
6. If approved and fingerprint matches → treated as ALLOW for that one call
   (single-use; token is consumed)

This is an in-memory pilot queue — restart clears pending items.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


def call_fingerprint(tool: str, arguments: Dict[str, Any]) -> str:
    payload = {"tool": tool, "arguments": arguments or {}}
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass
class PendingApproval:
    approval_id: str
    token: str
    session_id: str
    agent_id: str
    tool: str
    arguments: Dict[str, Any]
    fingerprint: str
    risk_score: int
    reasons: List[str]
    user_intent: str
    status: str = "pending"  # pending | approved | denied | expired | consumed
    created_at: float = field(default_factory=time.time)
    decided_at: Optional[float] = None
    decided_by: Optional[str] = None
    expires_at: float = 0.0

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "tool": self.tool,
            "arguments": self.arguments,
            "risk_score": self.risk_score,
            "reasons": self.reasons,
            "user_intent": self.user_intent,
            "status": self.status,
            "created_at": self.created_at,
            "decided_at": self.decided_at,
            "decided_by": self.decided_by,
            "expires_at": self.expires_at,
        }


class ApprovalQueue:
    """In-memory single-process approval queue."""

    def __init__(self, ttl_seconds: int = 1800) -> None:
        self._items: Dict[str, PendingApproval] = {}
        self.ttl_seconds = max(60, int(ttl_seconds))

    def _purge(self) -> None:
        now = time.time()
        dead = [
            aid
            for aid, item in self._items.items()
            if item.status in ("consumed", "denied", "expired")
            or now > item.expires_at
        ]
        for aid in dead:
            item = self._items.get(aid)
            if item and item.status == "pending" and now > item.expires_at:
                item.status = "expired"
            # drop terminal states after purge window
            if aid in self._items and self._items[aid].status in (
                "consumed",
                "denied",
                "expired",
            ):
                # keep denied/expired briefly for status queries — drop if > 2x TTL
                if now - self._items[aid].created_at > self.ttl_seconds * 2:
                    self._items.pop(aid, None)

    def create(
        self,
        *,
        session_id: str,
        agent_id: str,
        tool: str,
        arguments: Dict[str, Any],
        risk_score: int,
        reasons: List[str],
        user_intent: str,
    ) -> PendingApproval:
        self._purge()
        approval_id = secrets.token_urlsafe(16)
        token = secrets.token_urlsafe(24)
        item = PendingApproval(
            approval_id=approval_id,
            token=token,
            session_id=session_id,
            agent_id=agent_id,
            tool=tool,
            arguments=arguments or {},
            fingerprint=call_fingerprint(tool, arguments or {}),
            risk_score=risk_score,
            reasons=list(reasons),
            user_intent=user_intent or "",
            expires_at=time.time() + self.ttl_seconds,
        )
        self._items[approval_id] = item
        return item

    def get(self, approval_id: str) -> Optional[PendingApproval]:
        self._purge()
        item = self._items.get(approval_id)
        if item and item.status == "pending" and time.time() > item.expires_at:
            item.status = "expired"
        return item

    def decide(
        self,
        approval_id: str,
        *,
        decision: str,
        token: str,
        decided_by: str = "human",
    ) -> PendingApproval:
        item = self.get(approval_id)
        if item is None:
            raise KeyError("approval not found")
        if not secrets.compare_digest(item.token, token):
            raise PermissionError("invalid approval token")
        if item.status != "pending":
            raise ValueError(f"approval already in status={item.status}")
        if time.time() > item.expires_at:
            item.status = "expired"
            raise ValueError("approval expired")

        decision = (decision or "").strip().lower()
        if decision in ("approve", "approved", "allow", "yes"):
            item.status = "approved"
        elif decision in ("deny", "denied", "block", "no", "reject"):
            item.status = "denied"
        else:
            raise ValueError("decision must be approve or deny")

        item.decided_at = time.time()
        item.decided_by = decided_by
        return item

    def consume_if_approved(
        self,
        *,
        approval_id: str,
        token: str,
        tool: str,
        arguments: Dict[str, Any],
        session_id: str,
    ) -> Optional[str]:
        """
        If this call is covered by an approved, unexpired, matching pending item,
        mark it consumed and return None (meaning: treat as ALLOW).

        Returns an error string if the token was supplied but is not valid for ALLOW.
        Returns None if no approval_id was meant to short-circuit (caller should
        only call this when approval_id is present).
        """
        item = self.get(approval_id)
        if item is None:
            return "approval_id not found or expired"
        if not secrets.compare_digest(item.token, token):
            return "invalid approval token"
        if item.session_id != session_id:
            return "approval session_id mismatch"
        if item.status == "denied":
            return "approval was denied"
        if item.status == "expired":
            return "approval expired"
        if item.status == "consumed":
            return "approval token already consumed (single-use)"
        if item.status != "approved":
            return f"approval still pending (status={item.status})"

        fp = call_fingerprint(tool, arguments or {})
        if fp != item.fingerprint:
            return "tool/arguments do not match the approved request (fingerprint mismatch)"

        item.status = "consumed"
        item.decided_at = item.decided_at or time.time()
        return None  # success — caller should ALLOW

    def list_pending(self, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
        self._purge()
        out = []
        for item in self._items.values():
            if item.status != "pending":
                continue
            if session_id and item.session_id != session_id:
                continue
            out.append(item.to_public_dict())
        return out


# Module-level queue; TTL overridden from settings at engine import time.
approval_queue = ApprovalQueue(ttl_seconds=1800)
