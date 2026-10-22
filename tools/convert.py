"""Convert every rule to SIEM queries with pySigma backends.

    python tools/convert.py [--out build/conversions]

Writes one file per rule and target, plus ``<target>.json`` (all queries of a target) and
``index.md`` (what was generated, and what could not be). CI publishes the folder as the
``siem-queries`` artifact.

Targets:
  wazuh           Lucene for the Wazuh indexer (wazuh-alerts-*), Wazuh decoder field names
  elastic-lucene  Lucene / KQL-compatible query on ECS fields (Winlogbeat, Filebeat)
  elastic-eql     Event Query Language, supports the correlation rules
  elastic-esql    ES|QL, supports the correlation rules
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from sigma.backends.elasticsearch import EqlBackend, ESQLBackend, LuceneBackend
from sigma.backends.opensearch import OpensearchLuceneBackend
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.pipelines.elasticsearch.windows import ecs_windows
from sigma.pipelines.sysmon import sysmon_pipeline
from sigma.processing.pipeline import ProcessingPipeline

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from dac.engine import logsource_pipeline, rule_paths, sshd_logsource_pipeline  # noqa: E402
from dac.pipelines import ecs_sshd_pipeline, wazuh_pipeline  # noqa: E402


def _ecs() -> ProcessingPipeline:
    return sysmon_pipeline() + ecs_windows() + sshd_logsource_pipeline() + ecs_sshd_pipeline()


@dataclass(frozen=True)
class Target:
    name: str
    description: str
    backend: type
    pipeline: Callable[[], ProcessingPipeline]
    extension: str
    correlations: bool


TARGETS = [
    Target(
        "wazuh",
        "Wazuh indexer (wazuh-alerts-*), Lucene",
        OpensearchLuceneBackend,
        lambda: logsource_pipeline() + wazuh_pipeline(),
        "lucene",
        False,
    ),
    Target("elastic-lucene", "Elastic, Lucene on ECS", LuceneBackend, _ecs, "lucene", False),
    Target("elastic-eql", "Elastic, EQL on ECS", EqlBackend, _ecs, "eql", True),
    Target("elastic-esql", "Elastic, ES|QL on ECS", ESQLBackend, _ecs, "esql", True),
]


def convert(target: Target, path: Path) -> tuple[SigmaCollection, list[str], str]:
    """Return the parsed rule, its queries and a note for anything not converted."""
    collection = SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))
    is_correlation = any(isinstance(r, SigmaCorrelationRule) for r in collection.rules)
    note = ""
    if is_correlation and not target.correlations:
        # Lucene has no aggregation: export the base event query and state the threshold.
        correlation = next(r for r in collection.rules if isinstance(r, SigmaCorrelationRule))
        base_rules = [r for r in collection.rules if r is not correlation]
        for rule in base_rules:
            rule._output = True  # base rules of a correlation are otherwise not emitted
        queries = target.backend(processing_pipeline=target.pipeline()).convert(
            SigmaCollection(base_rules)
        )
        condition = correlation.condition
        operators = {"GTE": ">=", "GT": ">", "LTE": "<=", "LT": "<", "EQ": "="}
        counted = f"distinct {condition.fieldref} values" if condition.fieldref else "events"
        note = (
            f"Lucene cannot aggregate: alert when this query returns "
            f"{operators[condition.op.name]} {condition.count} {counted} for the same "
            f"{', '.join(correlation.group_by)} within {correlation.timespan.spec}."
        )
        return collection, queries, note
    collection.resolve_rule_references()
    queries = target.backend(processing_pipeline=target.pipeline()).convert(collection)
    return collection, queries, note


def _primary(collection: SigmaCollection):
    correlations = [r for r in collection.rules if isinstance(r, SigmaCorrelationRule)]
    return correlations[0] if correlations else collection.rules[0]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out", type=Path, default=ROOT / "build" / "conversions")
    args = parser.parse_args()
    index = ["# SIEM queries generated from the Sigma rules", ""]
    index += ["| Rule | " + " | ".join(t.name for t in TARGETS) + " |"]
    index += ["|---|" + "---|" * len(TARGETS)]
    rows: dict[str, list[str]] = {}
    for target in TARGETS:
        folder = args.out / target.name
        folder.mkdir(parents=True, exist_ok=True)
        bundle = {}
        for path in rule_paths():
            collection, queries, note = convert(target, path)
            rule = _primary(collection)
            header = [f"# {rule.title}", f"# Source: {path.relative_to(ROOT).as_posix()}"]
            if note:
                header.append(f"# {note}")
            text = "\n".join(header) + "\n" + "\n\n".join(queries) + "\n"
            (folder / f"{path.stem}.{target.extension}").write_text(text, encoding="utf-8")
            bundle[path.stem] = {
                "title": rule.title,
                "id": str(rule.id),
                "level": rule.level.name.lower() if rule.level else None,
                "queries": queries,
                "note": note or None,
            }
            rows.setdefault(path.stem, []).append("base query + threshold" if note else "yes")
        (args.out / f"{target.name}.json").write_text(
            json.dumps(bundle, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
    index += [f"| `{stem}` | " + " | ".join(cells) + " |" for stem, cells in rows.items()]
    index += ["", "Targets:", ""] + [f"- `{t.name}`: {t.description}" for t in TARGETS]
    (args.out / "index.md").write_text("\n".join(index) + "\n", encoding="utf-8")
    print(f"{len(rows)} rules converted to {len(TARGETS)} targets in {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
