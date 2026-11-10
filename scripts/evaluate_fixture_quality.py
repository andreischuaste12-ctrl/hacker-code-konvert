"""Compare normalized findings with a corpus's expected candidates.

An expected entry names a rule and a file, and optionally a line. Entries without a line match any
finding of that rule in that file. ``known_gaps`` lists vulnerable patterns the rules are known to
miss: they are reported, they are not counted as detected, and the measurement fails if one of them
starts being detected so that the corpus and the documentation are updated together.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

Key = tuple[str, str, int | None]


def _key(entry: dict[str, Any]) -> Key:
    return (entry["rule_id"], entry["path"], entry.get("line"))


def _matches(observed: set[Key], key: Key) -> set[Key]:
    rule, path, line = key
    return {item for item in observed if item[:2] == (rule, path) and line in (None, item[2])}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--findings", required=True)
    parser.add_argument("--expected", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    findings_payload = json.loads(Path(args.findings).read_text(encoding="utf-8"))
    expected_payload = json.loads(Path(args.expected).read_text(encoding="utf-8"))
    observed: set[Key] = {
        (item["sources"][0]["rule_id"], item["location"]["path"], item["location"].get("start_line"))
        for item in findings_payload["findings"]
    }
    expected = {_key(item) for item in expected_payload["expected"]}
    gaps = {_key(item) for item in expected_payload.get("known_gaps", [])}

    explained: set[Key] = set()
    detected = set()
    for key in expected:
        matched = _matches(observed, key)
        explained |= matched
        if matched:
            detected.add(key)
    gaps_detected = {key for key in gaps if _matches(observed, key)}
    for key in gaps_detected:
        explained |= _matches(observed, key)
    unexpected = observed - explained
    missed = expected - detected

    true_positives = len(detected)
    false_positives = len(unexpected)
    false_negatives = len(missed)
    reported = true_positives + false_positives
    patterns = len(expected) + len(gaps)
    per_rule: dict[str, dict[str, int]] = {}
    for rule in sorted({key[0] for key in expected | unexpected}):
        per_rule[rule] = {
            "true_positives": sum(1 for key in detected if key[0] == rule),
            "false_positives": sum(1 for key in unexpected if key[0] == rule),
            "false_negatives": sum(1 for key in missed if key[0] == rule),
        }
    metrics: dict[str, Any] = {
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "precision": true_positives / reported if reported else 1.0,
        "recall": true_positives / len(expected) if expected else 1.0,
        "per_rule": per_rule,
    }
    if gaps:
        metrics["known_gaps"] = len(gaps)
        metrics["known_gaps_now_detected"] = len(gaps_detected)
        # Recall over every vulnerable pattern in the corpus, including the documented misses.
        metrics["recall_including_known_gaps"] = true_positives / patterns
    Path(args.output).write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(metrics, sort_keys=True))
    return 0 if not (false_positives or false_negatives or gaps_detected) else 1


if __name__ == "__main__":
    raise SystemExit(main())
