from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--findings", required=True)
    parser.add_argument("--expected", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    findings_payload = json.loads(Path(args.findings).read_text(encoding="utf-8"))
    expected_payload = json.loads(Path(args.expected).read_text(encoding="utf-8"))
    observed = {
        (item["sources"][0]["rule_id"], item["location"]["path"]) for item in findings_payload["findings"]
    }
    expected = {(item["rule_id"], item["path"]) for item in expected_payload["expected"]}
    true_positives = len(observed & expected)
    false_positives = len(observed - expected)
    false_negatives = len(expected - observed)
    precision = true_positives / len(observed) if observed else 1.0
    recall = true_positives / len(expected) if expected else 1.0
    metrics = {
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "precision": precision,
        "recall": recall,
    }
    Path(args.output).write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(metrics, sort_keys=True))
    return 0 if false_positives == 0 and false_negatives == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
