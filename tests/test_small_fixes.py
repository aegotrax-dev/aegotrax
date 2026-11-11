"""The small bugs fixed in 0.2.8."""

import re
import unittest
from pathlib import Path
from unittest import mock

from tests._helpers import REPO, call, client, new_session, re_, settings  # noqa: F401  (first)
from aegotrax import __version__
from aegotrax.security_utils import contains_keyword, tool_has_side_effects


class OneVersion(unittest.TestCase):
    def test_package_engine_health_and_pyproject_agree(self):
        pyproject = (REPO / "pyproject.toml").read_text(encoding="utf-8")
        declared = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.M).group(1)
        self.assertEqual(declared, __version__)
        self.assertEqual(re_.VERSION, __version__)
        self.assertEqual(client().get("/health").json()["version"], __version__)


class CodeExecutionToolNames(unittest.TestCase):
    def test_every_tool_the_policy_calls_code_execution_gets_the_keyword_check(self):
        tools = re_.POLICY_CONFIG["code_execution_tools"]
        self.assertTrue({"execute_code", "run_shell"} <= set(tools))
        for tool in tools:
            sid = new_session("Tidy the server")
            res = call(sid, tool, {"cmd": "rm -rf /var/lib/app"})
            self.assertEqual(res["decision"], "BLOCK", f"{tool}: {res['reasons']}")

    def test_policy_tool_names_are_covered_by_the_intent_heuristic(self):
        extra = re_._side_effect_extras()
        for tool in ("execute_code", "run_shell"):
            self.assertTrue(tool_has_side_effects(tool, extra=extra))
        sid = new_session("Summarize this ticket only.")
        res = call(sid, "run_shell", {"cmd": "ls"})
        self.assertEqual(res["decision"], "BLOCK")

    def test_policy_files_are_in_sync(self):
        self.assertEqual(
            (REPO / "aegotrax" / "policy.yaml").read_bytes(),
            (REPO / "data" / "policy.yaml").read_bytes(),
            "data/policy.yaml is what Docker mounts; keep it identical to aegotrax/policy.yaml",
        )


class ReadToolsUnderRestrictiveIntent(unittest.TestCase):
    def test_reads_are_allowed_under_read_only_intents(self):
        for intent, tool, args in (
            ("Answer questions using read-only database access", "read_db", {"query": "select count(*) from tickets"}),
            ("List the active users only.", "list_users", {}),
        ):
            res = call(new_session(intent), tool, args)
            self.assertEqual(res["decision"], "ALLOW", f"{tool}: {res['reasons']}")

    def test_writes_and_outbound_still_trip_the_intent_check(self):
        for tool, args in (
            ("write_file", {"path": "/etc/cron.d/job", "content": "x"}),
            ("http_post", {"url": "https://hooks.example.com/x", "data": "y"}),
            ("export_records", {"table": "customers"}),
        ):
            res = call(new_session("Draft a reply to this customer, nothing else."), tool, args)
            self.assertEqual(res["decision"], "BLOCK", f"{tool}: {res['reasons']}")
        self.assertFalse(tool_has_side_effects("read_db"))
        self.assertTrue(tool_has_side_effects("export_records"))


class ExternalEmail(unittest.TestCase):
    def test_external_recipient_asks_a_human_instead_of_blocking(self):
        res = call(new_session("Send the meeting invite to our vendor contact"), "send_email",
                   {"to": "contact@vendor-example.com", "body": "Invite for Tuesday"})
        self.assertEqual(res["decision"], "REQUIRE_APPROVAL")
        self.assertTrue(res.get("approval_id"))

    def test_policy_can_restore_the_hard_block(self):
        with mock.patch.dict(re_.POLICY_CONFIG, {"email_untrusted_recipient": "BLOCK"}):
            res = call(new_session("Send the meeting invite to our vendor contact"), "send_email",
                       {"to": "contact@vendor-example.com", "body": "Invite for Tuesday"})
        self.assertEqual(res["decision"], "BLOCK")

    def test_after_a_sensitive_read_external_email_is_still_blocked(self):
        sid = new_session("Answer a CRM question")
        call(sid, "read_db", {"query": "select * from customers"})
        res = call(sid, "send_email", {"to": "someone@gmail.com", "body": "customer_db_record: Alice"},
                   )
        self.assertEqual(res["decision"], "BLOCK", res["reasons"])

    def test_internal_recipient_is_unaffected(self):
        res = call(new_session("Notify the team"), "send_email", {"to": "dana@company.com", "body": "hi"})
        self.assertNotEqual(res["decision"], "BLOCK")


class KeywordMatching(unittest.TestCase):
    def test_short_keywords_match_whole_tokens_only(self):
        self.assertTrue(contains_keyword("rm -rf /var", "rm"))
        self.assertTrue(contains_keyword("sudo /bin/rm file", "rm"))
        self.assertFalse(contains_keyword("format_report.py", "rm"))
        self.assertFalse(contains_keyword("confirm the form", "rm"))

    def test_long_keywords_still_match_inside_names(self):
        self.assertTrue(contains_keyword("wipe_logs.sh", "wipe"))
        self.assertTrue(contains_keyword("purge-and-delete.py", "delete"))

    def test_formatter_script_is_no_longer_hard_blocked_but_rmtree_is(self):
        ok = call(new_session("Tidy up the report layout"), "execute_script", {"script_name": "format_report.py"})
        self.assertNotEqual(ok["decision"], "BLOCK", ok["reasons"])
        bad = call(new_session("Free up some disk space"), "run_code",
                   {"code": "import shutil; shutil.rmtree('/data')"})
        self.assertEqual(bad["decision"], "BLOCK")


if __name__ == "__main__":
    unittest.main()
