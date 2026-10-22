"""Print a Markdown table of every rule's test results (for the CI job summary)."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from dac import DATA_DIR  # noqa: E402
from dac.engine import load_detection, load_events, rule_paths, run  # noqa: E402


def main() -> int:
    benign = {p: load_events(p) for p in sorted(DATA_DIR.glob("*/benign.*"))}
    benign_events = sum(len(e) for e in benign.values())
    rows, failures = [], 0
    for path in rule_paths():
        detection = load_detection(path)
        attack = load_events(next(detection.data_dir.glob("attack.*")))
        alerts = run(detection, attack)
        noisy = [p.parent.name for p, events in benign.items() if run(detection, events)]
        if detection.is_correlation:
            detected = f"{len(alerts)} alert(s) from {len(attack)} events"
            ok = bool(alerts)
        else:
            detected = f"{len(alerts)}/{len(attack)} events"
            ok = len(alerts) == len(attack)
        ok = ok and not noisy
        failures += not ok
        status = "pass" if ok else "**FAIL**"
        fired_on = ", ".join(noisy) or "none"
        rows.append(f"| `{detection.stem}` | {detected} | {fired_on} | {status} |")
    print(f"### Detection tests: {len(rows) - failures}/{len(rows)} rules pass\n")
    print(f"Benign corpus: {benign_events} events in {len(benign)} files.\n")
    print("| Rule | Recorded attack detected | Fired on benign | Result |")
    print("|---|---|---|---|")
    print("\n".join(rows))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
