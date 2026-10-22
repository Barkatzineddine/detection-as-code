"""Evaluate Sigma rules against recorded events.

Rules are compiled with pySigma's SQLite backend (the engine behind Zircolite) and run
against an in-memory SQLite table built from the events. Columns are declared
``TEXT COLLATE NOCASE`` so that string comparison is case-insensitive, as Sigma requires.

The same processing pipelines a SIEM conversion would use scope each rule to its log
source: ``sysmon`` turns a category such as ``process_creation`` into ``EventID: 1`` on the
Sysmon channel, ``windows-logsources`` adds the ``Channel`` of Security/System rules, and
``pipelines/sshd-logsource.yml`` restricts Linux SSH rules to ``process: sshd``. A rule is
therefore only ever matched against events of its own type.
"""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.pipelines.sysmon import sysmon_pipeline
from sigma.pipelines.windows import windows_logsource_pipeline
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule

from dac import DATA_DIR, PIPELINES_DIR, RULES_DIR
from dac.sshd import parse_lines

TABLE = "logs"
_MISSING_COLUMN = re.compile(r"no such column: (?:\w+\.)?(.+)$")


def logsource_pipeline() -> ProcessingPipeline:
    """Pipelines that turn Sigma log sources into field conditions.

    Pipelines keep state while converting a rule, so a fresh one is built for each use.
    """
    return sysmon_pipeline() + windows_logsource_pipeline() + sshd_logsource_pipeline()


def sshd_logsource_pipeline() -> ProcessingPipeline:
    path = PIPELINES_DIR / "sshd-logsource.yml"
    return ProcessingPipeline.from_yaml(path.read_text(encoding="utf-8"))


@dataclass
class Detection:
    """One rule file: a Sigma rule, or a correlation rule with the rules it builds on."""

    path: Path
    collection: SigmaCollection
    primary: SigmaRule | SigmaCorrelationRule
    queries: list[str] = field(default_factory=list)

    @property
    def stem(self) -> str:
        return self.path.stem

    @property
    def is_correlation(self) -> bool:
        return isinstance(self.primary, SigmaCorrelationRule)

    @property
    def data_dir(self) -> Path:
        return DATA_DIR / self.stem


def load_detection(path: Path) -> Detection:
    text = path.read_text(encoding="utf-8")
    collection = SigmaCollection.from_yaml(text)
    collection.resolve_rule_references()
    # A correlation file holds its base rules and the correlation; the correlation is the
    # detection that alerts, the base rules only feed it.
    correlations = [r for r in collection.rules if isinstance(r, SigmaCorrelationRule)]
    primary = correlations[0] if correlations else collection.rules[0]
    # Conversion rewrites the rules it processes (log source, added conditions), so it runs
    # on a separate copy and ``collection`` keeps the rule as written.
    backend = sqliteBackend(processing_pipeline=logsource_pipeline())
    queries = backend.convert(SigmaCollection.from_yaml(text))
    return Detection(path=path, collection=collection, primary=primary, queries=queries)


def rule_paths(root: Path = RULES_DIR) -> list[Path]:
    return sorted(root.rglob("*.yml"))


def load_events(path: Path) -> list[dict]:
    """Load a sample file: Windows events as JSON, Linux SSH logs as raw syslog lines."""
    if path.suffix == ".json":
        return json.loads(path.read_text(encoding="utf-8"))
    meta = json.loads((path.parent / "meta.json").read_text(encoding="utf-8"))
    return parse_lines(path.read_text(encoding="utf-8").splitlines(), year=meta["syslog_year"])


def build_database(events: list[dict]) -> sqlite3.Connection:
    """Create an in-memory table with one row per event and one column per field."""
    columns: dict[str, str] = {}  # lower-case name -> name as first seen
    for event in events:
        for key in event:
            columns.setdefault(key.lower(), key)
    # Correlations need a ``timestamp`` column; Windows events carry ``@timestamp``.
    columns.setdefault("timestamp", "timestamp")
    names = list(columns.values())
    db = sqlite3.connect(":memory:")
    db.execute(f"CREATE TABLE {TABLE} ({', '.join(_column(n) for n in names)})")
    rows = []
    for event in events:
        lowered = {k.lower(): v for k, v in event.items()}
        lowered.setdefault("timestamp", lowered.get("@timestamp"))
        rows.append([_cell(lowered.get(n.lower())) for n in names])
    placeholders = ", ".join("?" for _ in names)
    # TABLE is a constant and every value is a bound parameter.
    db.executemany(f"INSERT INTO {TABLE} VALUES ({placeholders})", rows)  # noqa: S608
    return db


def run(detection: Detection, events: list[dict]) -> list[dict]:
    """Return the alerts the detection raises on ``events``."""
    db = build_database(events)
    try:
        alerts = []
        for query in detection.queries:
            alerts.extend(_execute(db, query))
        return alerts
    finally:
        db.close()


def _execute(db: sqlite3.Connection, query: str) -> list[dict]:
    # A rule may reference a field the sample does not have: add it as an empty column,
    # the same way Zircolite and the backend's own runtime do.
    for _ in range(64):
        try:
            cursor = db.execute(query)
        except sqlite3.OperationalError as error:
            missing = _MISSING_COLUMN.search(str(error))
            if not missing:
                raise
            db.execute(f"ALTER TABLE {TABLE} ADD COLUMN {_column(missing.group(1))}")
            continue
        names = [d[0] for d in cursor.description]
        return [dict(zip(names, row, strict=True)) for row in cursor.fetchall()]
    raise RuntimeError("too many missing columns")


def _column(name: str) -> str:
    return '"' + name.strip('`"').replace('"', '""') + '" TEXT COLLATE NOCASE'


def _cell(value):
    if value is None or isinstance(value, (str, int, float)):
        return value
    return json.dumps(value)
