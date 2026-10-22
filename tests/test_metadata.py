"""Repository conventions that keep every detection reviewable and actionable."""

from __future__ import annotations

import re

import pytest
from sigma.rule import SigmaLevel, SigmaStatus

from dac import DATA_DIR, PLAYBOOKS_DIR, RULES_DIR
from dac.engine import load_detection, rule_paths

DETECTIONS = [load_detection(path) for path in rule_paths()]
PLAYBOOK_SECTIONS = ["## What it means", "## Investigate", "## False positives", "## Respond"]
FILE_PREFIX = {
    "process_creation": "proc_creation_win_",
    "process_access": "proc_access_win_",
    "registry_set": "registry_set_win_",
    "wmi_event": "wmi_event_win_",
    "security": "win_security_",
    "sshd": "lnx_sshd_",
}


def test_rule_count_is_in_scope():
    assert 15 <= len(DETECTIONS) <= 20


@pytest.mark.parametrize("detection", DETECTIONS, ids=lambda d: d.stem)
def test_rule_metadata(detection):
    rule = detection.primary
    assert rule.title and len(rule.title) <= 110
    assert rule.id, "every rule needs a UUID"
    assert rule.description and rule.author and rule.date
    assert rule.status in (SigmaStatus.TEST, SigmaStatus.STABLE)
    assert rule.level in (SigmaLevel.MEDIUM, SigmaLevel.HIGH, SigmaLevel.CRITICAL)
    assert rule.references, "cite the documentation the rule is based on"
    assert rule.falsepositives, "state the expected false positives, even if none"
    techniques = [t for t in rule.tags if t.namespace == "attack" and re.match(r"t\d{4}", t.name)]
    assert techniques, "map the rule to at least one ATT&CK technique"


def test_rule_ids_are_unique():
    ids = [str(r.id) for d in DETECTIONS for r in d.collection.rules]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("detection", DETECTIONS, ids=lambda d: d.stem)
def test_file_name_follows_log_source(detection):
    source = detection.collection.rules[0].logsource
    key = source.category or source.service
    assert detection.stem.startswith(FILE_PREFIX[key])


@pytest.mark.parametrize("detection", DETECTIONS, ids=lambda d: d.stem)
def test_playbook_exists_with_required_sections(detection):
    playbook = PLAYBOOKS_DIR / f"{detection.stem}.md"
    assert playbook.exists(), f"missing {playbook.name}"
    text = playbook.read_text(encoding="utf-8")
    assert text.startswith(f"# {detection.primary.title}")
    for section in PLAYBOOK_SECTIONS:
        assert section in text, f"{playbook.name} lacks '{section}'"
    assert detection.path.relative_to(RULES_DIR.parent).as_posix() in text, "link the rule"


def test_no_orphan_samples_or_playbooks():
    stems = {d.stem for d in DETECTIONS}
    samples = {p.name for p in DATA_DIR.iterdir() if p.is_dir() and p.name != "_baseline"}
    playbooks = {p.stem for p in PLAYBOOKS_DIR.glob("*.md") if p.stem != "README"}
    assert samples == stems
    assert playbooks == stems
