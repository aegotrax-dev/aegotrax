"""Audit event models for AgentGuard."""

from datetime import datetime, timezone
from typing import Any, Dict, List
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
