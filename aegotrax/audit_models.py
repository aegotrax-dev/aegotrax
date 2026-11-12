"""Audit event models for Aegotrax."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from pydantic import BaseModel, Field


class AuditEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    )
    session_id: str
    agent_id: str
    tool_name: str
    arguments: Dict[str, Any]
    user_intent: str
    risk_score: int
    decision: str
    reasons: List[str]
    attack_path: str
    matched_policies: List[str] = []
    # 0.2.8. `decision` is always what the policy decided. In shadow mode the caller was
    # told ALLOW regardless; `enforced_decision` records what the caller actually got.
    # Lines written by older versions have neither field (treat as mode="enforce").
    mode: str = "enforce"
    enforced_decision: Optional[str] = None
