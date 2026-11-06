from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from importlib.resources import files
from pathlib import Path

import pytest

from hacker_code_konvert.inventory import build_inventory, stage_scan_files
from hacker_code_konvert.sandbox import bubblewrap_supported
from hacker_code_konvert.semgrep_adapter import normalize_semgrep, run_semgrep


def test_malformed_or_escaping_paths_are_not_preserved() -> None:
    payload = {
        "results": [
            {
                "check_id": "synthetic.rule",
                "path": "../../outside.py",
                "start": {"line": 1},
                "end": {"line": 1},
                "extra": {"message": "Synthetic result", "severity": "WARNING", "metadata": {}},
            }
        ]
    }
    findings = normalize_semgrep(payload, "test")
    assert findings[0]["location"]["path"] == "unknown"


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {},
        {"results": ["not-an-object"]},
        {"results": [{"extra": []}]},
    ],
)
def test_malformed_semgrep_output_is_rejected(payload: object) -> None:
    with pytest.raises(TypeError):
        normalize_semgrep(payload, "test")  # type: ignore[arg-type]


def test_sandbox_target_prefix_is_removed() -> None:
    payload = {
        "results": [
            {
                "check_id": "synthetic.rule",
                "path": "/target/package/module.py",
                "start": {"line": 1},
                "end": {"line": 1},
                "extra": {"message": "Synthetic result", "severity": "INFO", "metadata": {}},
            }
        ]
    }
    findings = normalize_semgrep(payload, "test")
    assert findings[0]["location"]["path"] == "package/module.py"


@pytest.mark.integration
def test_bundled_semgrep_rules_ignore_target_suppressions() -> None:
    executable = shutil.which("semgrep")
    if not executable:
        pytest.skip("Semgrep is required")
    fixture = Path(__file__).parent / "fixtures/python"
    inventory = build_inventory(fixture)
    rules = Path(str(files("hacker_code_konvert").joinpath("data/python-security.yml")))
    with tempfile.TemporaryDirectory() as temporary:
        staged = Path(temporary) / "target"
        home = Path(temporary) / "home"
        home.mkdir()
        stage_scan_files(fixture, inventory, staged, max_file_bytes=1_000_000)
        result = subprocess.run(
            [
                executable,
                "--config",
                str(rules),
                "--json",
                "--metrics=off",
                "--disable-version-check",
                "--no-git-ignore",
                "--disable-nosem",
                ".",
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=60,
            cwd=staged,
            env={**os.environ, "HOME": str(home), "SEMGREP_SEND_METRICS": "off"},
        )
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    findings = normalize_semgrep(json.loads(result.stdout), "test")
    observed = {(item["sources"][0]["rule_id"], item["location"]["path"]) for item in findings}
    assert observed == {("hck.python.dangerous-eval", "vulnerable.py")}


@pytest.mark.integration
def test_semgrep_runs_inside_networkless_sandbox() -> None:
    if not shutil.which("semgrep") or not bubblewrap_supported():
        pytest.skip("Semgrep and usable bubblewrap namespaces are required")
    fixture = Path(__file__).parent / "fixtures/python"
    inventory = build_inventory(fixture)
    result = run_semgrep(
        fixture,
        inventory,
        timeout_seconds=60,
        memory_bytes=1024 * 1024 * 1024,
        output_bytes=5_000_000,
        max_file_bytes=1_000_000,
    )
    assert result.status == "completed", result.errors
    observed = {(item["sources"][0]["rule_id"], item["location"]["path"]) for item in result.findings}
    assert observed == {("hck.python.dangerous-eval", "vulnerable.py")}
