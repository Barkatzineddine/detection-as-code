"""Rebuild the test samples in tests/data/ from the public datasets they come from.

Every sample is extracted, not written by hand. ``tests/data/sources.yml`` pins each
dataset (URL at a fixed commit + SHA-256) and says which events to keep for each rule.
This script downloads the archives into ``.cache/datasets``, verifies their hashes, reads
the events straight from the archive, and writes:

* ``tests/data/<rule>/attack.json`` / ``benign.json`` for Windows (one JSON list of events),
* ``tests/data/<rule>/attack.log`` / ``benign.log`` for Linux (the raw syslog lines).

Two edits are made to recorded Windows events, both documented in tests/data/README.md:
collector metadata that no rule uses (NXLog's rendered ``Message``, transport fields) is
dropped, and long Base64 blobs (the encoded Empire stagers) are cut to 48 characters. The
detections never depend on payload content, and a full stager would make antivirus
quarantine the repository.

    python tools/build_samples.py           # write the samples
    python tools/build_samples.py --check   # fail if the committed samples differ
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import sys
import tarfile
import urllib.request
import zipfile
from collections.abc import Iterator
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from dac.sshd import parse_line  # noqa: E402

DATA = ROOT / "tests" / "data"
CACHE = ROOT / ".cache" / "datasets"

# Collector (NXLog / Logstash) metadata that is not part of the Windows event itself.
DROPPED_FIELDS = {
    "@version", "AccountName", "AccountType", "Category", "Domain", "ERROR_EVT_UNRESOLVED",
    "EventReceivedTime", "EventTime",
    "ExecutionProcessID", "Keywords", "Message", "Opcode", "OpcodeValue", "ProviderGuid",
    "Severity", "SeverityValue", "SourceModuleName", "SourceModuleType", "Task", "ThreadID",
    "UserID", "Version", "host", "port", "tags",
}  # fmt: skip
BASE64_BLOB = re.compile(r"([A-Za-z0-9+/]{48})[A-Za-z0-9+/]{52,}={0,2}")
TRUNCATED = "[...truncated]"


def fetch(source: dict) -> Path:
    path = CACHE / source["url"].rsplit("/", 1)[1]
    if not path.exists():
        CACHE.mkdir(parents=True, exist_ok=True)
        if not source["url"].startswith("https://"):
            raise ValueError(f"refusing non-HTTPS source {source['url']}")
        with urllib.request.urlopen(source["url"], timeout=120) as response:  # noqa: S310
            path.write_bytes(response.read())
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != source["sha256"]:
        raise ValueError(f"{path.name}: SHA-256 {digest} does not match sources.yml")
    return path


def archive_lines(path: Path) -> Iterator[str]:
    """Yield the lines of every JSON file inside the archive, without extracting it."""
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as archive:
            for name in archive.namelist():
                if name.endswith(".json") and "__MACOSX" not in name:
                    with archive.open(name) as member:
                        yield from io.TextIOWrapper(member, encoding="utf-8")
    elif path.name.endswith(".tar.gz"):
        with tarfile.open(path) as archive:
            for member in archive:
                if member.name.endswith(".json") and "__MACOSX" not in member.name:
                    yield from io.TextIOWrapper(archive.extractfile(member), encoding="utf-8")
    else:
        yield from path.read_text(encoding="utf-8").splitlines()


def matches(event: dict, where: dict) -> bool:
    """Small selector language: ``field``, ``field|contains``, ``|startswith``, ``|endswith``,
    ``|re``; a list means any of the values. ``not`` holds a selector that must not match."""
    for key, expected in where.items():
        if key == "not":
            if any(matches(event, w) for w in _as_list(expected)):
                return False
            continue
        name, _, op = key.partition("|")
        actual = event.get(name)
        if actual is None:
            return False
        actual = str(actual).lower()
        if not any(_compare(actual, str(value).lower(), op) for value in _as_list(expected)):
            return False
    return True


def _compare(actual: str, value: str, op: str) -> bool:
    if op == "contains":
        return value in actual
    if op == "startswith":
        return actual.startswith(value)
    if op == "endswith":
        return actual.endswith(value)
    if op == "re":
        return re.search(value, actual, re.IGNORECASE) is not None
    return actual == value


def _as_list(value):
    return value if isinstance(value, list) else [value]


def clean(event: dict) -> dict:
    out = {}
    for key, value in event.items():
        if key in DROPPED_FIELDS:
            continue
        if key == "EventID":
            value = int(value)
        if isinstance(value, str):
            value = BASE64_BLOB.sub(lambda m: m.group(1) + TRUNCATED, value)
        out[key] = value
    return dict(sorted(out.items()))


def select_windows(spec: dict, path: Path) -> list[dict]:
    seen, picked = set(), []
    for line in archive_lines(path):
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not matches(event, spec["where"]):
            continue
        event = clean(event)
        key = tuple(str(event.get(f)) for f in spec.get("distinct", []))
        if spec.get("distinct"):
            if key in seen:
                continue
            seen.add(key)
        picked.append(event)
        if len(picked) == spec.get("limit", 1_000):
            break
    return picked


def select_syslog(spec: dict, path: Path, year: int) -> list[str]:
    picked = []
    for line in archive_lines(path):
        event = parse_line(line, year)
        if event and matches(event, spec["where"]):
            picked.append(line.rstrip("\r\n"))
    return picked


def build(manifest: dict) -> dict[Path, str]:
    """Return {output path: content} for every sample described in the manifest."""
    sources = manifest["sources"]
    outputs: dict[Path, str] = {}
    for rule, kinds in manifest["samples"].items():
        for kind in ("attack", "benign"):
            selections = kinds.get(kind, [])
            if not selections:
                continue
            first = sources[selections[0]["source"]]
            if first["format"] == "syslog":
                lines = []
                for spec in selections:
                    source = sources[spec["source"]]
                    lines += select_syslog(spec, fetch(source), source["syslog_year"])
                    if not lines:
                        raise ValueError(f"{rule}/{kind}: selection matched nothing: {spec}")
                outputs[DATA / rule / f"{kind}.log"] = "\n".join(lines) + "\n"
                meta = {"syslog_year": first["syslog_year"]}
                outputs[DATA / rule / "meta.json"] = json.dumps(meta, indent=2) + "\n"
            else:
                events = []
                for spec in selections:
                    found = select_windows(spec, fetch(sources[spec["source"]]))
                    if not found:
                        raise ValueError(f"{rule}/{kind}: selection matched nothing: {spec}")
                    events += found
                text = json.dumps(events, indent=2, ensure_ascii=False)
                outputs[DATA / rule / f"{kind}.json"] = text + "\n"
    return outputs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--check", action="store_true", help="compare instead of writing")
    args = parser.parse_args()
    manifest = yaml.safe_load((DATA / "sources.yml").read_text(encoding="utf-8"))
    outputs = build(manifest)
    stale = []
    for path, content in outputs.items():
        current = path.read_text(encoding="utf-8") if path.exists() else None
        if current == content:
            continue
        if args.check:
            stale.append(path.relative_to(ROOT).as_posix())
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8", newline="\n")
    if stale:
        print("Samples differ from what sources.yml produces:", *stale, sep="\n  ")
        return 1
    print(f"{len(outputs)} sample files {'verified' if args.check else 'written'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
