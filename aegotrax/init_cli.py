"""aegotrax-init: a ready-to-run local setup in one command.

    aegotrax-init                 # in the folder you will run the engine from
    python -m aegotrax.init_cli   # same thing, if aegotrax-init is not on PATH (Windows)

What it does, in the current folder (or --dir):
  * .env                 two DIFFERENT random secrets: AEGOTRAX_API_KEY (agent/SDK) and
                         AEGOTRAX_APPROVER_KEY (humans who approve). An existing .env is
                         kept: only missing or empty AEGOTRAX_* values are filled in.
  * aegotrax_policy.yaml a copy of the default policy to edit for your own tools, wired in
                         through AEGOTRAX_POLICY_PATH. Skipped if it exists or with --no-policy.

Then it prints the next steps. Nothing is sent anywhere.
"""

from __future__ import annotations

import argparse
import re
import secrets
import shutil
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

POLICY_FILENAME = "aegotrax_policy.yaml"
ENGINE_BASE = "http://127.0.0.1:8100"

_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")


def _new_key() -> str:
    return secrets.token_urlsafe(32)


def _read_env(path: Path) -> List[str]:
    return path.read_text(encoding="utf-8").splitlines() if path.exists() else []


def _value(raw: str) -> str:
    raw = raw.split(" #", 1)[0].strip()
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "\"'":
        raw = raw[1:-1]
    return raw.strip()


def merge_env(lines: List[str], wanted: Dict[str, str]) -> Tuple[List[str], List[str], List[str]]:
    """Fill `wanted` keys into .env lines without touching values that are already set.

    Returns (new_lines, written_keys, kept_keys).
    """
    out = list(lines)
    seen: Dict[str, int] = {}
    for i, line in enumerate(out):
        m = _LINE.match(line)
        if m and not line.lstrip().startswith("#"):
            seen.setdefault(m.group(1), i)

    written, kept, missing = [], [], []
    for key, val in wanted.items():
        if key in seen:
            if _value(_LINE.match(out[seen[key]]).group(2)):
                kept.append(key)
            else:  # present but empty (e.g. copied from .env.example)
                out[seen[key]] = f"{key}={val}"
                written.append(key)
        else:
            missing.append(key)

    if missing:
        if out and out[-1].strip():
            out.append("")
        out.append("# --- Aegotrax (added by aegotrax-init) ---")
        for key in missing:
            if key == "AEGOTRAX_APPROVER_KEY":
                out.append("# Humans who approve REQUIRE_APPROVAL calls. Keep it away from the agent.")
            out.append(f"{key}={wanted[key]}")
            written.append(key)
    return out, written, kept


def _default_policy() -> Path:
    return Path(__file__).resolve().parent / "policy.yaml"


def _gitignore_warning(folder: Path) -> Optional[str]:
    gi = folder / ".gitignore"
    if not gi.exists():
        return None
    entries = {ln.strip() for ln in gi.read_text(encoding="utf-8").splitlines()}
    if entries & {".env", "/.env", "*.env", ".env*"}:
        return None
    return "  ! .gitignore does not list .env: add it before you commit (the file holds secrets)."


def _next_steps() -> str:
    win = sys.platform.startswith("win")
    engine_alt = "python -m aegotrax.risk_engine"
    return f"""
Next:
  1) Start the engine from this folder (keep the terminal open):
       aegotrax-engine
     {"If Windows says the command is not recognized:" if win else "If the command is not found:"}
       {engine_alt}

  2) Check it:  {ENGINE_BASE}/health

  3) Protect a tool in your agent:

       from aegotrax import protected_tool

       @protected_tool(
           session_id_fn=lambda: "my-session",
           agent_id_fn=lambda: "my-agent",
           user_intent_fn=lambda: "Summarize the customer ticket",
       )
       def send_email(to: str, body: str):
           ...   # runs only if Aegotrax says ALLOW

Your agent only needs AEGOTRAX_API_KEY. Give AEGOTRAX_APPROVER_KEY to the humans who approve.
"""


def run(folder: Path, write_policy: bool = True) -> int:
    folder = folder.resolve()
    if not folder.is_dir():
        print(f"aegotrax-init: {folder} is not a folder", file=sys.stderr)
        return 2

    print(f"Aegotrax setup in {folder}\n")

    policy_path = folder / POLICY_FILENAME
    wanted: Dict[str, str] = {
        "AEGOTRAX_API_KEY": _new_key(),
        "AEGOTRAX_APPROVER_KEY": _new_key(),
    }

    if write_policy:
        if policy_path.exists():
            print(f"  = {POLICY_FILENAME}: already exists, kept")
        else:
            shutil.copyfile(_default_policy(), policy_path)
            print(f"  + {POLICY_FILENAME}: starter policy (edit it to match your tools)")
        wanted["AEGOTRAX_POLICY_PATH"] = str(policy_path)

    env_path = folder / ".env"
    existed = env_path.exists()
    lines, written, kept = merge_env(_read_env(env_path), wanted)
    if written:
        env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # The two secrets must differ, or the engine refuses to start. If one was kept and the
    # other generated, they differ by construction; if both were kept, check them.
    final = {}
    for ln in lines:
        m = _LINE.match(ln)
        if m and not ln.lstrip().startswith("#"):
            final.setdefault(m.group(1), _value(m.group(2)))

    verb = "updated" if existed else "created"
    if written:
        print(f"  + .env {verb}: {', '.join(written)}")
    for key in kept:
        print(f"  = .env: {key} already set, kept")
    if final.get("AEGOTRAX_API_KEY") and final.get("AEGOTRAX_API_KEY") == final.get("AEGOTRAX_APPROVER_KEY"):
        print("  ! AEGOTRAX_API_KEY and AEGOTRAX_APPROVER_KEY are equal: the engine will refuse to start.")
        print("    Delete AEGOTRAX_APPROVER_KEY from .env and run aegotrax-init again.")

    warn = _gitignore_warning(folder)
    if warn:
        print(warn)

    print(_next_steps())
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="aegotrax-init",
        description="Create .env (two random keys) and a starter policy for Aegotrax.",
    )
    ap.add_argument("--dir", default=".", help="folder to set up (default: current folder)")
    ap.add_argument("--no-policy", action="store_true", help="do not write aegotrax_policy.yaml")
    args = ap.parse_args(argv)
    return run(Path(args.dir), write_policy=not args.no_policy)


if __name__ == "__main__":
    raise SystemExit(main())
