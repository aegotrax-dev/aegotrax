"""aegotrax-init (0.2.9) and reading .env from the folder you run in."""

from tests._helpers import REPO  # noqa: F401  (first: sets the test environment)

import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path

from aegotrax import config
from aegotrax.init_cli import POLICY_FILENAME, main, merge_env


def _run(folder: Path, *extra: str) -> str:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = main(["--dir", str(folder), *extra])
    assert code == 0, out.getvalue()
    return out.getvalue()


def _env(folder: Path) -> dict:
    vals = {}
    for line in (folder / ".env").read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            vals[k.strip()] = v.strip()
    return vals


class InitCreatesAWorkingSetup(unittest.TestCase):
    def test_fresh_folder_gets_two_different_keys_and_a_policy(self):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            _run(folder)
            env = _env(folder)
            self.assertGreaterEqual(len(env["AEGOTRAX_API_KEY"]), 32)
            self.assertGreaterEqual(len(env["AEGOTRAX_APPROVER_KEY"]), 32)
            self.assertNotEqual(env["AEGOTRAX_API_KEY"], env["AEGOTRAX_APPROVER_KEY"])
            policy = folder / POLICY_FILENAME
            self.assertTrue(policy.exists())
            self.assertEqual(Path(env["AEGOTRAX_POLICY_PATH"]), policy.resolve())

    def test_running_twice_changes_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            _run(folder)
            before = (folder / ".env").read_text(encoding="utf-8")
            _run(folder)
            self.assertEqual((folder / ".env").read_text(encoding="utf-8"), before)

    def test_existing_env_keeps_other_values_and_fills_empty_keys(self):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            (folder / ".env").write_text(
                "OPENAI_API_KEY=sk-test\nAEGOTRAX_API_KEY=\nAEGOTRAX_APPROVER_KEY=\n", encoding="utf-8"
            )
            _run(folder, "--no-policy")
            env = _env(folder)
            self.assertEqual(env["OPENAI_API_KEY"], "sk-test")
            self.assertTrue(env["AEGOTRAX_API_KEY"])
            self.assertTrue(env["AEGOTRAX_APPROVER_KEY"])
            self.assertNotIn("AEGOTRAX_POLICY_PATH", env)
            self.assertFalse((folder / POLICY_FILENAME).exists())

    def test_existing_keys_are_never_overwritten(self):
        lines, written, kept = merge_env(
            ["AEGOTRAX_API_KEY=mine"], {"AEGOTRAX_API_KEY": "new", "AEGOTRAX_APPROVER_KEY": "appr"}
        )
        self.assertIn("AEGOTRAX_API_KEY=mine", lines)
        self.assertNotIn("AEGOTRAX_API_KEY=new", lines)
        self.assertEqual(kept, ["AEGOTRAX_API_KEY"])
        self.assertEqual(written, ["AEGOTRAX_APPROVER_KEY"])

    def test_equal_keys_are_reported(self):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            (folder / ".env").write_text("AEGOTRAX_API_KEY=same\nAEGOTRAX_APPROVER_KEY=same\n", encoding="utf-8")
            self.assertIn("are equal", _run(folder, "--no-policy"))


class DotenvIsReadFromTheWorkingFolder(unittest.TestCase):
    def test_env_file_in_cwd_is_found_for_a_pip_installed_package(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / ".env").write_text("X=1\n", encoding="utf-8")
            cwd = os.getcwd()
            try:
                os.chdir(d)
                self.assertEqual(Path(config._dotenv_path()).resolve(), (Path(d) / ".env").resolve())
            finally:
                os.chdir(cwd)


if __name__ == "__main__":
    unittest.main()
