"""Detection-as-code toolkit: run, convert and map Sigma rules."""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "rules"
DATA_DIR = ROOT / "tests" / "data"
PLAYBOOKS_DIR = ROOT / "playbooks"
PIPELINES_DIR = ROOT / "pipelines"

# ATT&CK data used for technique names and tactics, pinned so that coverage output only
# changes when this line does (pySigma would otherwise fetch the latest release).
ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "c2494b29dd268c46a5d0ea0990553e4327cd2253/enterprise-attack/enterprise-attack-20.0.json"
)
