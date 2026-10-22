"""Run the generated Wazuh queries against a real OpenSearch, the engine of the Wazuh indexer.

The SQLite harness proves the Sigma logic; this proves the conversion. Every sample event is
indexed in the shape the Wazuh decoders give it (``data.win.eventdata.commandLine``,
``data.srcip``, ``full_log``...), then each rule's Lucene query from tools/convert.py must
return all of its attack events and none of the benign ones.

Wazuh's index template maps strings as case-sensitive keywords, while Sigma matching is
case-insensitive. The check therefore runs twice: on an index with a lowercase normalizer
(the semantics the rules are written for, which must pass), and on a case-sensitive index
(reported, to show which rules depend on the case of the logged values).

    python tools/verify_wazuh.py --url http://localhost:9200 --queries build/conversions
"""

from __future__ import annotations

import argparse
import contextlib
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from dac import DATA_DIR  # noqa: E402
from dac.engine import load_events  # noqa: E402
from dac.pipelines import WAZUH_SSHD_FIELDS, WAZUH_WINDOWS_SYSTEM_FIELDS  # noqa: E402

INDEX = "wazuh-alerts-verify"


def request(url: str, method: str = "GET", body=None, ndjson: bool = False):
    data = None
    headers = {}
    if body is not None:
        data = body.encode() if ndjson else json.dumps(body).encode()
        headers["Content-Type"] = "application/x-ndjson" if ndjson else "application/json"
    if not url.startswith(("http://", "https://")):
        raise ValueError(url)
    req = urllib.request.Request(url, data=data, method=method, headers=headers)  # noqa: S310
    with urllib.request.urlopen(req, timeout=60) as response:  # noqa: S310
        return json.loads(response.read() or b"{}")


def wazuh_document(event: dict, sample: str, raw_line: str | None) -> dict:
    """Shape one sample event like a wazuh-alerts document."""
    doc: dict = {"sample": sample}
    if raw_line is not None:  # Linux, decoded by dac.sshd
        doc["full_log"] = raw_line
        for field, target in WAZUH_SSHD_FIELDS.items():
            if field in event and field != "message":
                _put(doc, target, str(event[field]))
        return doc
    for key, value in event.items():
        if key.startswith("@") or isinstance(value, (dict, list)):
            continue
        target = WAZUH_WINDOWS_SYSTEM_FIELDS.get(key)
        if target is None:
            target = "data.win.eventdata." + key[0].lower() + key[1:]
        _put(doc, target, str(value))
    return doc


def _put(doc: dict, dotted: str, value: str) -> None:
    *parents, leaf = dotted.split(".")
    for part in parents:
        doc = doc.setdefault(part, {})
    doc[leaf] = value


def load_samples() -> list[dict]:
    docs = []
    for path in sorted(DATA_DIR.glob("*/*.*")):
        if path.stem not in ("attack", "benign"):
            continue
        sample = f"{path.parent.name}/{path.stem}"
        events = load_events(path)
        if path.suffix == ".log":
            lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line]
            docs += [wazuh_document(e, sample, line) for e, line in zip(events, lines, strict=True)]
        else:
            docs += [wazuh_document(e, sample, None) for e in events]
    return docs


def create_index(url: str, case_sensitive: bool) -> None:
    keyword = {"type": "keyword"} if case_sensitive else {"type": "keyword", "normalizer": "lc"}
    body = {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
            "analysis": {"normalizer": {"lc": {"type": "custom", "filter": ["lowercase"]}}},
        },
        "mappings": {
            # Wazuh's template stores event fields as keywords; never guess dates or numbers.
            "date_detection": False,
            "numeric_detection": False,
            "dynamic_templates": [
                {"strings": {"match_mapping_type": "string", "mapping": keyword}},
            ],
        },
    }
    with contextlib.suppress(urllib.error.HTTPError):  # first run: nothing to delete
        request(f"{url}/{INDEX}", "DELETE")
    request(f"{url}/{INDEX}", "PUT", body)


def count(url: str, query: str, sample: str) -> int:
    body = {
        "query": {
            "bool": {
                "must": [{"query_string": {"query": query}}],
                "filter": [{"term": {"sample": sample}}],
            }
        }
    }
    return request(f"{url}/{INDEX}/_count", "POST", body)["count"]


def check(url: str, queries: dict, samples: dict[str, int]) -> list[tuple[str, str, str]]:
    """Return (rule, sample, problem) for every mismatch."""
    problems = []
    benign = [s for s in samples if s.endswith("/benign")]
    for rule, spec in queries.items():
        query = " OR ".join(f"({q})" for q in spec["queries"])
        attack = f"{rule}/attack"
        hits = count(url, query, attack)
        if spec["note"]:  # correlation: only the base query is exported
            if hits == 0:
                problems.append((rule, attack, "base query matched nothing"))
            continue
        if hits != samples[attack]:
            problems.append((rule, attack, f"matched {hits} of {samples[attack]}"))
        problems += [
            (rule, s, f"matched {n} benign events") for s in benign if (n := count(url, query, s))
        ]
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--url", default="http://localhost:9200")
    parser.add_argument("--queries", type=Path, default=ROOT / "build" / "conversions")
    parser.add_argument("--summary", type=Path, help="append a Markdown report to this file")
    args = parser.parse_args()
    queries = json.loads((args.queries / "wazuh.json").read_text(encoding="utf-8"))
    docs = load_samples()
    samples: dict[str, int] = {}
    for doc in docs:
        samples[doc["sample"]] = samples.get(doc["sample"], 0) + 1

    results = {}
    for case_sensitive in (False, True):
        create_index(args.url, case_sensitive)
        bulk = "".join(
            json.dumps({"index": {"_index": INDEX}}) + "\n" + json.dumps(d) + "\n" for d in docs
        )
        response = request(f"{args.url}/_bulk?refresh=true", "POST", bulk, ndjson=True)
        if response.get("errors"):
            failed = [i["index"] for i in response["items"] if "error" in i["index"]]
            reasons = {json.dumps(i["error"])[:400] for i in failed}
            raise SystemExit(f"{len(failed)} documents rejected:\n" + "\n".join(reasons))
        results[case_sensitive] = check(args.url, queries, samples)

    version = request(args.url)["version"]["number"]
    lines = [
        f"### Wazuh queries on OpenSearch {version}",
        "",
        f"{len(queries)} queries, {len(docs)} indexed sample events.",
        "",
        "| Index mapping | Mismatches |",
        "|---|---|",
        f"| lowercase keywords (Sigma semantics, must pass) | {len(results[False])} |",
        f"| case-sensitive keywords (Wazuh default template) | {len(results[True])} |",
    ]
    for label, problems in (("Must pass", results[False]), ("Case-sensitive", results[True])):
        if problems:
            lines += ["", f"**{label}:**", ""]
            lines += [f"- `{rule}` on `{sample}`: {what}" for rule, sample, what in problems]
    report = "\n".join(lines) + "\n"
    print(report)
    if args.summary:
        with args.summary.open("a", encoding="utf-8") as handle:
            handle.write(report)
    return 1 if results[False] else 0


if __name__ == "__main__":
    sys.exit(main())
