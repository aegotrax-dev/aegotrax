"""Shadow mode: decide + audit, but never enforce (0.2.8)."""

import json
import os
import tempfile
import unittest
from unittest import mock

from tests._helpers import (  # noqa: F401  (import first: sets env)
    AUDIT_LOG, approval_args, audit_events, call, new_session, re_, settings,
)
from aegotrax import shadow_report


def shadow():
    return mock.patch.object(settings, "enforcement", "shadow")


class ShadowDecisions(unittest.TestCase):
    def test_enforce_is_unchanged(self):
        sid = new_session("Answer questions about the Q3 report")
        res = call(sid, "http_post", {"url": "http://169.254.169.254/latest/meta-data", "data": "x"})
        self.assertEqual(res["decision"], "BLOCK")
        self.assertNotIn("shadow", res)
        self.assertEqual(res["enforcement"], "enforce")

    def test_block_becomes_allow_with_would_decide(self):
        sid = new_session("Answer questions about the Q3 report")
        with shadow():
            res = call(sid, "http_post", {"url": "http://169.254.169.254/latest/meta-data", "data": "x"})
        self.assertEqual(res["decision"], "ALLOW")
        self.assertTrue(res["shadow"])
        self.assertEqual(res["would_decide"], "BLOCK")
        self.assertTrue(res["reasons"])  # the reasons are still reported

    def test_audit_keeps_the_policy_decision_and_marks_the_mode(self):
        sid = new_session("Answer questions about the Q3 report")
        with shadow():
            call(sid, "http_post", {"url": "http://169.254.169.254/latest/meta-data", "data": "x"})
        ev = [e for e in audit_events() if e["session_id"] == sid][-1]
        self.assertEqual(ev["decision"], "BLOCK")
        self.assertEqual(ev["mode"], "shadow")
        self.assertEqual(ev["enforced_decision"], "ALLOW")

    def test_no_approval_is_queued_in_shadow(self):
        sid = new_session()
        before = len(re_.approval_queue.list_pending())
        with shadow():
            res = call(sid, "http_post", approval_args())
        self.assertEqual(res["would_decide"], "REQUIRE_APPROVAL")
        self.assertEqual(res["decision"], "ALLOW")
        self.assertNotIn("approval_id", res)
        self.assertEqual(len(re_.approval_queue.list_pending()), before)

    def test_shadow_does_not_close_the_session_on_budget_exceed(self):
        sid = new_session("Read customer records for the report")
        with shadow():
            for i in range(40):
                call(sid, "read_db", {"query": f"select * from customers where id={i}"})
        self.assertFalse((re_.SESSION_META.get(sid) or {}).get("closed"))
        self.assertTrue(
            any(e["session_id"] == sid and e["decision"] != "ALLOW" for e in audit_events()),
            "expected the over-budget reads to be reported as would-block/would-approve",
        )

    def test_early_returns_are_audited_too(self):
        # scope denial returns before the main scoring path; it used to leave no audit line
        sid = new_session("List invoices", scope={"allowed_tools": ["read_document"]})
        with shadow():
            res = call(sid, "http_post", {"url": "https://hooks.example.com/x", "data": "y"})
        self.assertEqual(res["would_decide"], "BLOCK")
        ev = [e for e in audit_events() if e["session_id"] == sid]
        self.assertTrue(ev)
        self.assertEqual(ev[-1]["mode"], "shadow")
        self.assertEqual(ev[-1]["decision"], "BLOCK")

    def test_enforce_audits_early_blocks_as_well(self):
        sid = new_session("List invoices", scope={"allowed_tools": ["read_document"]})
        call(sid, "http_post", {"url": "https://hooks.example.com/x", "data": "y"})
        ev = [e for e in audit_events() if e["session_id"] == sid]
        self.assertTrue(ev)
        self.assertEqual(ev[-1]["mode"], "enforce")

    def test_invalid_mode_falls_back_to_enforce(self):
        from aegotrax import config

        with mock.patch.dict(os.environ, {"AEGOTRAX_ENFORCEMENT": "monitor"}):
            self.assertEqual(config._enforcement_mode(), "enforce")
        with mock.patch.dict(os.environ, {"AEGOTRAX_ENFORCEMENT": "SHADOW"}):
            self.assertEqual(config._enforcement_mode(), "shadow")


class ShadowClients(unittest.TestCase):
    def test_sdk_fails_closed_in_enforce_and_open_in_shadow(self):
        from aegotrax import sdk

        boom = mock.Mock(side_effect=ConnectionError("engine down"))
        args = dict(session_id="s", agent_id="a", tool="read_document", arguments={"doc_id": "1"})
        with mock.patch.object(sdk.requests, "post", boom), mock.patch.object(settings, "fail_closed", True):
            self.assertEqual(sdk.verify_tool_call(**args)["decision"], "BLOCK")
            with shadow():
                self.assertEqual(sdk.verify_tool_call(**args)["decision"], "ALLOW")


class ShadowReport(unittest.TestCase):
    def test_report_counts(self):
        ev = lambda tool, dec, mode="shadow", pol=(), reason="r": {  # noqa: E731
            "timestamp": "2026-11-11T10:00:00Z", "session_id": "s1", "tool_name": tool,
            "decision": dec, "mode": mode, "matched_policies": list(pol), "reasons": [reason],
            "risk_score": 10, "arguments": {},
        }
        events = (
            [ev("read_db", "ALLOW")] * 6
            + [ev("http_post", "REQUIRE_APPROVAL", pol=["tool_class:open_risk"])] * 3
            + [ev("http_post", "BLOCK", pol=["ssrf"], reason="metadata host")]
            + [ev("read_db", "BLOCK", mode="enforce")]            # ignored: enforce mode
            + [{"decision": "APPROVAL_APPROVED", "mode": "enforce"}]  # ignored: bookkeeping
        )
        s = shadow_report.summarize(events)
        self.assertEqual(s["calls"], 10)
        self.assertEqual((s["would_allow"], s["would_require_approval"], s["would_block"]), (6, 3, 1))
        self.assertAlmostEqual(s["friction_rate"], 0.4)
        post = [t for t in s["by_tool"] if t["tool"] == "http_post"][0]
        self.assertEqual((post["calls"], post["would_block"]), (4, 1))
        self.assertEqual(s["top_policies"][0][0], "ssrf")
        self.assertEqual(shadow_report.summarize(events, include_enforce=True)["calls"], 11)
        self.assertIn("Friction rate", shadow_report.render_text(s))

    def test_end_to_end_from_the_real_audit_log(self):
        sid = new_session("Answer questions about the Q3 report")
        with shadow():
            call(sid, "read_document", {"doc_id": "q3"})
            call(sid, "http_post", {"url": "http://169.254.169.254/latest/meta-data", "data": "x"})
        s = shadow_report.summarize(shadow_report.load_events(AUDIT_LOG))
        self.assertGreaterEqual(s["calls"], 2)
        self.assertGreaterEqual(s["would_block"], 1)

    def test_empty_log_is_explained(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "missing.log")
            self.assertEqual(shadow_report.main(["--log", p, "--json"]), 0)
            self.assertIn("No shadow-mode events", shadow_report.render_text(shadow_report.summarize([])))


if __name__ == "__main__":
    unittest.main()
