"""Shared test setup. Import this module FIRST in every test file.

Sets the environment before aegotrax.config is imported, points the audit log at a temp
file, and gives the tests an agent credential and two approver credentials.
"""

import os
import sys
import tempfile
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

AUDIT_LOG = str(Path(tempfile.gettempdir()) / f"aegotrax_tests_{uuid.uuid4().hex[:8]}.log")
os.environ["AEGOTRAX_AUDIT_LOG"] = AUDIT_LOG
os.environ["AEGOTRAX_API_KEY"] = "agent-key-for-tests"
os.environ["AEGOTRAX_APPROVER_KEYS"] = "alice:alice-secret,bob:bob-secret"
os.environ.pop("AEGOTRAX_APPROVER_KEY", None)
os.environ["AEGOTRAX_ENFORCEMENT"] = "enforce"
os.environ.pop("AEGOTRAX_APPROVAL_WEBHOOK", None)

from aegotrax import risk_engine as re_  # noqa: E402
from aegotrax.config import settings  # noqa: E402

settings.audit_log = AUDIT_LOG
settings.api_key = "agent-key-for-tests"
settings.approver_keys = {"alice": "alice-secret", "bob": "bob-secret"}

AGENT = {"X-API-Key": "agent-key-for-tests"}
ALICE = {"X-Approver-Key": "alice-secret"}
BOB = {"X-Approver-Key": "bob-secret"}


def client():
    from fastapi.testclient import TestClient

    return TestClient(re_.app)


def new_session(intent: str = "Post the metrics to the analytics service", scope=None) -> str:
    sid = f"t-{uuid.uuid4().hex[:10]}"
    re_.upsert_session(
        re_.SessionUpdate(
            session_id=sid,
            user_intent=intent,
            agent_id="test-agent",
            scope=re_.SessionScope(**scope) if scope else None,
        ),
        None,
    )
    return sid


def call(sid, tool, args, **extra):
    payload = {
        "session_id": sid,
        "agent_id": "test-agent",
        "user_intent": "ignored (server intent wins)",
        "tool": tool,
        "arguments": args,
        "call_chain": [tool],
    }
    payload.update(extra)
    return re_.evaluate(re_.MultiAgentRequest(**payload))


def approval_args(tag: str = ""):
    # unique per test: the engine holds permits for identical tool+args while delivery is open
    return {"url": "http://analytics-partner.example.net/log", "data": f"job {uuid.uuid4().hex[:8]}{tag}"}


def audit_events():
    import json

    try:
        with open(AUDIT_LOG, "r", encoding="utf-8") as f:
            return [json.loads(x) for x in f if x.strip()]
    except FileNotFoundError:
        return []
