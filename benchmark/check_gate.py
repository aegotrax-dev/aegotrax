"""Regression gate for the benchmark: exit 1 if detection or false-positive behaviour got worse.

    python benchmark/run_benchmark.py --in-process --out /tmp/bench.json
    python benchmark/check_gate.py /tmp/bench.json

The baseline below is the engine 0.2.8 result on the default policy. If you improve
the engine on purpose, tighten the numbers; if you change the policy on purpose and a
number legitimately moves, update it in the same commit and say why in the message.
"""

import json
import sys
from pathlib import Path

# Attacks the default policy is known to miss (see benchmark/README.md). A NEW miss fails.
KNOWN_MISSED = {"A44", "A46"}
MIN_ATTACKS_INTERCEPTED = 51   # of 53
MAX_BENIGN_HARD_BLOCKED = 0    # hard false positives on the benign set


def main(path: str) -> int:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    s = data["summary"]
    atk, ben = s["attacks"], s["benign"]
    problems = []

    if s.get("setup_failed_ids"):
        problems.append(f"scenarios failed to set up: {s['setup_failed_ids']}")
    if atk["intercepted"] < MIN_ATTACKS_INTERCEPTED:
        problems.append(f"attacks intercepted {atk['intercepted']}/{atk['total']} < {MIN_ATTACKS_INTERCEPTED}")
    new_misses = sorted(set(atk["missed_ids"]) - KNOWN_MISSED)
    if new_misses:
        problems.append(f"attacks newly allowed (ALLOW): {new_misses}")
    if ben["hard_blocked"] > MAX_BENIGN_HARD_BLOCKED:
        problems.append(f"benign hard false positives {ben['hard_blocked']} > {MAX_BENIGN_HARD_BLOCKED}: {ben['blocked_ids']}")

    print(
        f"attacks intercepted {atk['intercepted']}/{atk['total']} (hard-blocked {atk['hard_blocked']}), "
        f"benign hard-blocked {ben['hard_blocked']}/{ben['total']}, clean allow {ben['clean_allow']}/{ben['total']}"
    )
    if problems:
        print("BENCHMARK GATE FAILED:")
        for p in problems:
            print("  -", p)
        return 1
    print("benchmark gate passed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else str(Path(__file__).parent / "results" / "latest.json")))
