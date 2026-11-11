"""Shadow-mode report: "this is what Aegotrax would have done" on your real traffic.

Run the engine with AEGOTRAX_ENFORCEMENT=shadow for a while, then:

    aegotrax-shadow-report                       # reads the configured audit log
    aegotrax-shadow-report --log path/to/aegotrax_audit.log --json
    aegotrax-shadow-report --since 2026-11-01

It only reads the audit log. Events written in enforce mode are ignored unless
--include-enforce is given.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from typing import Any, Dict, Iterable, List, Optional

from .config import settings

# Bookkeeping events (approval decisions, delivery reports) are not tool calls.
_SKIP_PREFIX = "APPROVAL_"
_NOISE_POLICIES = {"approval_queued", "approval_pending", "approval_delivery"}


def load_events(path: str) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except ValueError:
                    continue  # tolerate a torn last line
                if isinstance(ev, dict):
                    events.append(ev)
    except FileNotFoundError:
        pass
    return events


def _is_call(ev: Dict[str, Any]) -> bool:
    return not str(ev.get("decision", "")).startswith(_SKIP_PREFIX)


def summarize(
    events: Iterable[Dict[str, Any]],
    since: Optional[str] = None,
    include_enforce: bool = False,
    top: int = 10,
) -> Dict[str, Any]:
    calls = [
        e for e in events
        if _is_call(e)
        and (include_enforce or e.get("mode") == "shadow")
        and (not since or str(e.get("timestamp", "")) >= since)
    ]
    total = len(calls)
    decisions = Counter(str(e.get("decision")) for e in calls)
    by_tool: Dict[str, Counter] = defaultdict(Counter)
    policies: Counter = Counter()
    reasons: Counter = Counter()
    sessions = set()
    flagged: List[Dict[str, Any]] = []

    for e in calls:
        d = str(e.get("decision"))
        by_tool[str(e.get("tool_name"))][d] += 1
        sessions.add(e.get("session_id"))
        if d in ("BLOCK", "REQUIRE_APPROVAL"):
            for p in e.get("matched_policies") or []:
                if p not in _NOISE_POLICIES and not str(p).startswith("tool_class:"):
                    policies[p] += 1
            for r in (e.get("reasons") or [])[:1]:
                reasons[str(r)[:110]] += 1
            flagged.append(e)

    would_block = decisions.get("BLOCK", 0)
    would_approve = decisions.get("REQUIRE_APPROVAL", 0)
    friction = would_block + would_approve

    tools = []
    for name, c in sorted(by_tool.items(), key=lambda kv: -sum(kv[1].values())):
        n = sum(c.values())
        tools.append({
            "tool": name,
            "calls": n,
            "would_allow": c.get("ALLOW", 0),
            "would_require_approval": c.get("REQUIRE_APPROVAL", 0),
            "would_block": c.get("BLOCK", 0),
        })

    return {
        "calls": total,
        "sessions": len(sessions),
        "would_allow": decisions.get("ALLOW", 0),
        "would_require_approval": would_approve,
        "would_block": would_block,
        "friction_rate": round(friction / total, 4) if total else 0.0,
        "by_tool": tools,
        "top_policies": policies.most_common(top),
        "top_reasons": reasons.most_common(top),
        "examples": [
            {
                "timestamp": e.get("timestamp"),
                "session_id": e.get("session_id"),
                "tool": e.get("tool_name"),
                "would_decide": e.get("decision"),
                "risk_score": e.get("risk_score"),
                "reason": (e.get("reasons") or [""])[0],
                "arguments": e.get("arguments"),
            }
            for e in flagged[:top]
        ],
    }


def _pct(n: int, d: int) -> str:
    return f"{100.0 * n / d:.1f}%" if d else "n/a"


def render_text(s: Dict[str, Any]) -> str:
    n = s["calls"]
    if not n:
        return (
            "No shadow-mode events found.\n"
            "Start the engine with AEGOTRAX_ENFORCEMENT=shadow and send some traffic, "
            "or point --log at the right file (use --include-enforce for enforce-mode logs)."
        )
    out = [
        "Aegotrax shadow report — what the policy WOULD have done (nothing was enforced)",
        "-" * 78,
        f"Tool calls evaluated : {n}   (sessions: {s['sessions']})",
        f"Would allow          : {s['would_allow']:>6}  {_pct(s['would_allow'], n)}",
        f"Would need approval  : {s['would_require_approval']:>6}  {_pct(s['would_require_approval'], n)}",
        f"Would block          : {s['would_block']:>6}  {_pct(s['would_block'], n)}",
        f"Friction rate        : {s['friction_rate'] * 100:.1f}%  (approval + block)",
        "",
        "By tool",
        f"  {'tool':<24}{'calls':>7}{'allow':>8}{'approval':>10}{'block':>7}",
    ]
    for t in s["by_tool"]:
        out.append(
            f"  {t['tool']:<24}{t['calls']:>7}{t['would_allow']:>8}"
            f"{t['would_require_approval']:>10}{t['would_block']:>7}"
        )
    if s["top_policies"]:
        out += ["", "Rules that fired most"]
        out += [f"  {c:>5}  {p}" for p, c in s["top_policies"]]
    if s["top_reasons"]:
        out += ["", "Most common reasons"]
        out += [f"  {c:>5}  {r}" for r, c in s["top_reasons"]]
    if s["examples"]:
        out += ["", "Examples (arguments are redacted if audit redaction is on)"]
        for e in s["examples"]:
            out.append(f"  [{e['would_decide']}] {e['tool']} risk={e['risk_score']} — {e['reason'][:90]}")
    out += [
        "",
        "Read this as: friction_rate is the share of your real calls a human would have",
        "been asked about (or that would have failed). If it is high, tune policy.yaml",
        "(trusted_domains, tool_classes, keywords) before turning enforcement on.",
    ]
    return "\n".join(out)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Summarise Aegotrax shadow-mode audit events.")
    ap.add_argument("--log", default=settings.audit_log, help="audit log path (JSON lines)")
    ap.add_argument("--since", default=None, help="ISO timestamp / date lower bound")
    ap.add_argument("--top", type=int, default=10)
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--include-enforce", action="store_true",
                    help="also count events written in enforce mode")
    args = ap.parse_args(argv)

    summary = summarize(
        load_events(args.log), since=args.since,
        include_enforce=args.include_enforce, top=args.top,
    )
    if args.json:
        print(json.dumps(summary, indent=2, ensure_ascii=False))
    else:
        print(render_text(summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
