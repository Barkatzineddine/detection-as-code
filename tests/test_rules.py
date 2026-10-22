"""Every rule must fire on its recorded attack and stay silent on every benign sample."""

from __future__ import annotations

import pytest

from dac import DATA_DIR
from dac.engine import load_detection, load_events, rule_paths, run

DETECTIONS = [load_detection(path) for path in rule_paths()]
BENIGN_SAMPLES = sorted(DATA_DIR.glob("*/benign.*"))


def _sample(detection, kind):
    found = sorted(detection.data_dir.glob(f"{kind}.*"))
    assert found, f"{detection.stem}: no {kind} sample in {detection.data_dir}"
    return found[0]


@pytest.mark.parametrize("detection", DETECTIONS, ids=lambda d: d.stem)
def test_detects_recorded_attack(detection):
    events = load_events(_sample(detection, "attack"))
    alerts = run(detection, events)
    if detection.is_correlation:
        # The sample is the attacker's whole session; the threshold must be crossed.
        assert alerts, f"{detection.stem}: correlation did not trigger on {len(events)} events"
    else:
        # Attack samples only hold the malicious events, so every one of them must match.
        assert len(alerts) == len(events), (
            f"{detection.stem}: matched {len(alerts)} of {len(events)} attack events"
        )


@pytest.mark.parametrize("benign", BENIGN_SAMPLES, ids=lambda p: p.parent.name)
@pytest.mark.parametrize("detection", DETECTIONS, ids=lambda d: d.stem)
def test_silent_on_benign_activity(detection, benign):
    alerts = run(detection, load_events(benign))
    assert not alerts, f"{detection.stem} fired on {benign.parent.name}: {alerts[:3]}"
