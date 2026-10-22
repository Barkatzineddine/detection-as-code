"""Generate the ATT&CK Navigator layer and the README coverage table from the rules.

    python tools/coverage.py          # write docs/attack-navigator-layer.json and README.md
    python tools/coverage.py --check  # fail if either is out of date

Technique names and tactics come from the ATT&CK data bundled with pySigma, so a rule
tagged with a technique that no longer exists fails here (and in ``sigma check``).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

import yaml
from sigma.data import mitre_attack

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from dac import ATTACK_STIX_URL  # noqa: E402
from dac.engine import load_detection, rule_paths  # noqa: E402

LAYER = ROOT / "docs" / "attack-navigator-layer.json"
README = ROOT / "README.md"
START, END = "<!-- coverage:start -->", "<!-- coverage:end -->"
TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution", "persistence",
    "privilege-escalation", "stealth", "defense-impairment", "credential-access", "discovery",
    "lateral-movement", "collection", "command-and-control", "exfiltration", "impact",
]  # fmt: skip


def techniques_of(rule) -> list[str]:
    return [
        t.name.upper() for t in rule.tags if t.namespace == "attack" and re.match(r"t\d", t.name)
    ]


def logsource_of(detection) -> str:
    rule = detection.primary
    if detection.is_correlation:
        rule = detection.collection.rules[0]
    source = rule.logsource
    parts = [p for p in (source.product, source.category, source.service) if p]
    return " / ".join(parts)


def sample_sources() -> dict[str, list[str]]:
    """Map each rule to the datasets its attack sample was extracted from."""
    manifest = yaml.safe_load((ROOT / "tests" / "data" / "sources.yml").read_text("utf-8"))
    out = {}
    for rule, kinds in manifest["samples"].items():
        names = [s["source"] for s in kinds.get("attack", [])]
        urls = [manifest["sources"][n]["url"] for n in dict.fromkeys(names)]
        out[rule] = [f"[{Path(u).name.split('.')[0]}]({u})" for u in urls]
    return out


def build_layer(detections) -> dict:
    names = mitre_attack.mitre_attack_techniques
    by_technique = defaultdict(list)
    for detection in detections:
        for technique in techniques_of(detection.primary):
            by_technique[technique].append(detection.primary.title)
    entries = []
    for technique, titles in sorted(by_technique.items()):
        entries.append({
            "techniqueID": technique,
            "score": len(titles),
            "comment": "; ".join(titles),
            "enabled": True,
            "metadata": [{"name": "rule", "value": title} for title in titles],
            "showSubtechniques": False,
        })  # fmt: skip
    # Expand the parent of every covered sub-technique so the coverage is visible.
    parents = sorted({t.split(".")[0] for t in by_technique if "." in t} - set(by_technique))
    entries += [{"techniqueID": p, "showSubtechniques": True} for p in parents]
    unknown = [t for t in by_technique if t not in names]
    if unknown:
        raise SystemExit(f"Unknown ATT&CK techniques in rules: {unknown}")
    return {
        "name": "detection-as-code coverage",
        "versions": {
            "attack": str(mitre_attack.mitre_attack_version).split(".")[0],
            "navigator": "5.1.0",
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": (
            f"{len(detections)} Sigma rules from github.com/Barkatzineddine/detection-as-code, "
            "each tested against a recorded attack. Score = number of rules."
        ),
        "sorting": 3,
        "layout": {"layout": "side", "showID": True, "showName": True},
        "hideDisabled": False,
        "techniques": entries,
        "gradient": {"colors": ["#c6dbef", "#08519c"], "minValue": 0, "maxValue": 3},
        "legendItems": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }


def build_table(detections) -> str:
    names = mitre_attack.mitre_attack_techniques
    tactics_of = mitre_attack.mitre_attack_techniques_tactics_mapping
    samples = sample_sources()
    rows = []
    for detection in detections:
        rule = detection.primary
        techniques = techniques_of(rule)
        tactics = {t for tech in techniques for t in tactics_of.get(tech, [])}
        first_tactic = min((TACTIC_ORDER.index(t) for t in tactics), default=99)
        attack = ", ".join(
            f"[{t}](https://attack.mitre.org/techniques/{t.replace('.', '/')}/) {names[t]}"
            for t in techniques
        )
        rule_link = f"[{rule.title}]({detection.path.relative_to(ROOT).as_posix()})"
        playbook = f"[playbook](playbooks/{detection.stem}.md)"
        data = ", ".join(samples.get(detection.stem, []))
        level = rule.level.name.lower()
        cells = [rule_link, attack, logsource_of(detection), level, data, playbook]
        row = "| " + " | ".join(cells) + " |"
        rows.append((first_tactic, detection.stem, row))
    rows.sort()
    per_tactic = defaultdict(set)
    for detection in detections:
        for technique in techniques_of(detection.primary):
            for tactic in tactics_of.get(technique, []):
                per_tactic[tactic].add(detection.stem)
    summary = " · ".join(
        f"{t.replace('-', ' ').title()} **{len(per_tactic[t])}**"
        for t in TACTIC_ORDER
        if per_tactic[t]
    )
    techniques = {t for d in detections for t in techniques_of(d.primary)}
    header = [
        f"{len(detections)} rules, {len(techniques)} ATT&CK techniques "
        f"(ATT&CK v{str(mitre_attack.mitre_attack_version).split('.')[0]}). "
        "Rules per tactic: " + summary + ".",
        "",
        "| Rule | ATT&CK | Log source | Level | Recorded attack | Triage |",
        "|---|---|---|---|---|---|",
    ]
    return "\n".join(header + [r for _, _, r in rows])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--check", action="store_true", help="compare instead of writing")
    args = parser.parse_args()
    mitre_attack.set_url(ATTACK_STIX_URL)
    detections = [load_detection(p) for p in rule_paths()]
    layer = json.dumps(build_layer(detections), indent=2) + "\n"
    readme = README.read_text(encoding="utf-8")
    if START not in readme or END not in readme:
        raise SystemExit(f"README.md must contain {START} and {END}")
    before, rest = readme.split(START, 1)
    after = rest.split(END, 1)[1]
    new_readme = f"{before}{START}\n{build_table(detections)}\n{END}{after}"
    current_layer = LAYER.read_text(encoding="utf-8") if LAYER.exists() else ""
    if args.check:
        stale = [
            p.name
            for p, new, old in ((LAYER, layer, current_layer), (README, new_readme, readme))
            if new != old
        ]
        if stale:
            print("Out of date, run python tools/coverage.py:", ", ".join(stale))
            return 1
        print("Coverage table and Navigator layer are up to date")
        return 0
    LAYER.parent.mkdir(exist_ok=True)
    LAYER.write_text(layer, encoding="utf-8", newline="\n")
    README.write_text(new_readme, encoding="utf-8", newline="\n")
    print(f"Wrote {LAYER.relative_to(ROOT)} and the README coverage table")
    return 0


if __name__ == "__main__":
    sys.exit(main())
