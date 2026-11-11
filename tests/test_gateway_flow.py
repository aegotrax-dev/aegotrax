"""Gateway: the LLM never sees a secret, and an approved call is released on retry."""

import unittest
from unittest import mock

from tests._helpers import ALICE, approval_args, call, client, new_session, re_, settings  # noqa: F401
from aegotrax import mcp_gateway as gw


class _Resp:
    def __init__(self, data):
        self._d = data
        self.status_code = 200

    def json(self):
        return self._d


def _route_to_engine(url, json=None, headers=None, timeout=None, **kw):
    if url.endswith("/approval/delivery"):
        c = client()
        r = c.post("/approval/delivery", json=json, headers=headers)
        _route_to_engine.delivery.append((json, r.status_code))
        return _Resp(r.json())
    return _Resp(re_.evaluate(re_.MultiAgentRequest(**json)))


_route_to_engine.delivery = []


class GatewayApprovalFlow(unittest.TestCase):
    def setUp(self):
        self.sid = new_session()
        gw.get_current_session_context = lambda: {"session_id": self.sid, "agent_id": "test-agent"}
        _route_to_engine.delivery.clear()
        gw._APPROVAL_HANDLES.clear()

    def test_pending_message_has_no_secret_then_retry_releases_once(self):
        args = approval_args()
        with mock.patch.object(gw.requests, "post", _route_to_engine), \
                mock.patch.object(settings, "mode", "simulate"):
            first = gw.verify_and_forward("http_post", args)
            self.assertIn("APPROVAL REQUIRED", first)
            self.assertIn("approval_id:", first)
            self.assertNotIn("token", first.lower())

            again = gw.verify_and_forward("http_post", args)      # still undecided
            self.assertIn("APPROVAL REQUIRED", again)
            self.assertEqual(len(re_.approval_queue.list_pending(session_id=self.sid)), 1)

            aid = next(iter(gw._APPROVAL_HANDLES.values()))
            r = client().post("/approval/decide", json={"approval_id": aid, "decision": "approve"}, headers=ALICE)
            self.assertEqual(r.status_code, 200)

            released = gw.verify_and_forward("http_post", args)    # identical retry
            self.assertNotIn("APPROVAL REQUIRED", released)
            self.assertNotIn("BLOCKED", released)
            self.assertEqual(_route_to_engine.delivery, [({"approval_id": aid, "status": "delivered"}, 200)])

            third = gw.verify_and_forward("http_post", args)       # single use: asks again
            self.assertIn("APPROVAL REQUIRED", third)

    def test_denied_approval_is_blocked_and_handle_dropped(self):
        args = approval_args()
        with mock.patch.object(gw.requests, "post", _route_to_engine), \
                mock.patch.object(settings, "mode", "simulate"):
            gw.verify_and_forward("http_post", args)
            aid = next(iter(gw._APPROVAL_HANDLES.values()))
            client().post("/approval/decide", json={"approval_id": aid, "decision": "deny"}, headers=ALICE)
            out = gw.verify_and_forward("http_post", args)
            self.assertIn("BLOCKED", out)
            self.assertEqual(len(gw._APPROVAL_HANDLES), 0)

    def test_shadow_gateway_does_not_block_and_does_not_fail_closed(self):
        with mock.patch.object(settings, "enforcement", "shadow"), \
                mock.patch.object(settings, "mode", "simulate"), \
                mock.patch.object(gw.requests, "post", _route_to_engine):
            out = gw.verify_and_forward("http_post", {"url": "http://169.254.169.254/x", "data": "d"})
            self.assertNotIn("BLOCKED", out)
        with mock.patch.object(settings, "enforcement", "shadow"), \
                mock.patch.object(settings, "fail_closed", True), \
                mock.patch.object(settings, "mode", "simulate"), \
                mock.patch.object(gw.requests, "post", mock.Mock(side_effect=ConnectionError("down"))):
            self.assertNotIn("BLOCKED", gw.verify_and_forward("read_document", {"doc_id": "1"}))


if __name__ == "__main__":
    unittest.main()
