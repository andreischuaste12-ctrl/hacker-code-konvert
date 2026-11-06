from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def test_fixture_quality_measurement(tmp_path: Path) -> None:
    findings = tmp_path / "findings.json"
    expected = tmp_path / "expected.json"
    output = tmp_path / "quality.json"
    findings.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "sources": [{"rule_id": "hck.synthetic.rule"}],
                        "location": {"path": "vulnerable.py"},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    expected.write_text(
        json.dumps({"expected": [{"rule_id": "hck.synthetic.rule", "path": "vulnerable.py"}]}),
        encoding="utf-8",
    )
    result = subprocess.run(
        [
            sys.executable,
            "scripts/evaluate_fixture_quality.py",
            "--findings",
            str(findings),
            "--expected",
            str(expected),
            "--output",
            str(output),
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=10,
    )

    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    assert json.loads(output.read_text(encoding="utf-8")) == {
        "false_negatives": 0,
        "false_positives": 0,
        "precision": 1.0,
        "recall": 1.0,
        "true_positives": 1,
    }
