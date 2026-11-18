"""Keyword matching on shell commands: argument order and spacing must not matter."""

import unittest

from aegotrax.security_utils import contains_keyword

DD_IF = "dd if="
DD_OF = "dd of=/dev/"


class ShellKeywordTests(unittest.TestCase):
    def test_dd_input_first_still_matches(self):
        self.assertTrue(contains_keyword("dd if=/dev/zero of=/dev/sda", DD_IF))

    def test_dd_arguments_in_any_order(self):
        for cmd in (
            "dd of=/dev/sda if=/dev/zero",
            "dd bs=1m of=/dev/sda if=/dev/urandom",
            "dd count=1 if=/dev/zero bs=512",
        ):
            with self.subTest(cmd=cmd):
                self.assertTrue(contains_keyword(cmd, DD_IF))

    def test_dd_extra_whitespace_and_tabs(self):
        self.assertTrue(contains_keyword("dd  if=/dev/zero of=/dev/sda", DD_IF))
        self.assertTrue(contains_keyword("dd\tof=/dev/sda\tif=/dev/zero", DD_IF))

    def test_dd_with_wrappers_and_paths(self):
        for cmd in (
            "sudo dd of=/dev/sda if=/dev/zero",
            "/bin/dd of=/dev/sda if=/dev/zero",
            "sudo -n env dd bs=1m of=/dev/sda if=/dev/zero",
            "echo hi; dd of=/dev/sda if=/dev/zero",
            "yes | dd of=/dev/sda",
        ):
            with self.subTest(cmd=cmd):
                self.assertTrue(
                    contains_keyword(cmd, DD_IF) or contains_keyword(cmd, DD_OF)
                )

    def test_dd_inside_quoted_shell_string(self):
        cmd = 'bash -c "dd of=/dev/sda if=/dev/zero"'
        self.assertTrue(contains_keyword(cmd, DD_IF))

    def test_dd_writing_to_a_device_without_input_file(self):
        self.assertTrue(contains_keyword("dd bs=1m of=/dev/sda", DD_OF))

    def test_dd_to_a_normal_file_is_not_flagged_by_the_device_rule(self):
        self.assertFalse(contains_keyword("dd bs=1m count=1 of=/tmp/out.bin", DD_OF))

    def test_benign_text_is_not_flagged(self):
        for text in (
            "add the address field to the form",
            "dd mm yyyy date format",
            "backup if=ready",
            "odd if=weird",
        ):
            with self.subTest(text=text):
                self.assertFalse(contains_keyword(text, DD_IF))
                self.assertFalse(contains_keyword(text, DD_OF))

    def test_other_multiword_keywords_keep_working(self):
        self.assertTrue(contains_keyword("drop table users", "drop table"))
        self.assertTrue(contains_keyword("drop   table users", "drop table"))
        self.assertTrue(contains_keyword("format c: /q", "format c:"))
        self.assertFalse(contains_keyword("a table to drop off", "drop table"))

    def test_short_keywords_unchanged(self):
        self.assertTrue(contains_keyword("rm -rf ./data", "rm"))
        self.assertFalse(contains_keyword("format_report.py", "rm"))


if __name__ == "__main__":
    unittest.main()
