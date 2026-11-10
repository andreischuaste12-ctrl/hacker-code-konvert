from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from hacker_code_konvert.cli import main
from hacker_code_konvert.inventory import build_inventory, stage_neutral_files
from hacker_code_konvert.provenance import rules_metadata
from hacker_code_konvert.sarif import render_sarif
from hacker_code_konvert.scope import load_scope


def test_validate_success_and_module_entry(tmp_path: Path) -> None:
    path = tmp_path / "findings.json"
    path.write_text('{"findings": []}')
    assert main(["validate", str(path)]) == 0
    result = subprocess.run(
        [sys.executable, "-m", "hacker_code_konvert", "--version"], capture_output=True, check=True
    )
    assert result.stdout.strip() == b"0.2.0"


def test_neutral_staging_preserves_hostile_paths(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    for name in ("back\\slash.py", "invisible\u202e.py", os.fsdecode(b"invalid\xff.py")):
        (root / name).write_text("eval(input())")
    inventory = build_inventory(root)
    mapping = stage_neutral_files(root, inventory, tmp_path / "staged", max_file_bytes=1000)
    assert set(mapping.values()) == set(inventory.scan_files)
    assert all(name.startswith("f") and name.isascii() for name in mapping)


def test_rules_manifest_covers_twelve_classes() -> None:
    rules = rules_metadata()
    assert rules["count"] == 33
    assert len(rules["sha256"]) == 64


def test_scope_expiration_and_wrong_root(tmp_path: Path) -> None:
    path = tmp_path / "scope.json"
    record = {
        "repository": str(tmp_path),
        "responsible": "Andrei",
        "authorization_reference": "example",
        "valid_from": "2020-01-01T00:00:00+00:00",
        "valid_until": "2090-01-01T00:00:00+00:00",
    }
    path.write_text(json.dumps(record))
    assert load_scope(path, tmp_path)["sha256"]
    record["valid_until"] = "2021-01-01T00:00:00+00:00"
    path.write_text(json.dumps(record))
    with pytest.raises(ValueError, match="inactive"):
        load_scope(path, tmp_path)


def test_sarif_failed_run_is_explicit() -> None:
    sarif = render_sarif({"complete": False}, [])
    assert sarif["version"] == "2.1.0"
    assert not sarif["runs"][0]["invocations"][0]["executionSuccessful"]


def test_sarif_conforms_to_oasis_schema() -> None:
    import jsonschema

    schema = json.loads((Path(__file__).parent / "data/sarif.schema.json").read_text())
    jsonschema.validate(render_sarif({"complete": True}, []), schema)


@pytest.mark.integration
def test_php_profile_fixtures(require_semgrep, require_sandbox) -> None:
    from hacker_code_konvert.semgrep_adapter import DEFAULT_MEMORY_BYTES, run_semgrep

    root = Path(__file__).parent / "fixtures/php"
    result = run_semgrep(
        root,
        build_inventory(root),
        timeout_seconds=60,
        memory_bytes=DEFAULT_MEMORY_BYTES,
        output_bytes=1000000,
        max_file_bytes=100000,
    )
    assert result.status == "completed", result.errors
    expected = json.loads((root / "expected.json").read_text())["expected"]
    assert {(f["sources"][0]["rule_id"], f["location"]["path"]) for f in result.findings} == {
        (f["rule_id"], f["path"]) for f in expected
    }


@pytest.mark.integration
def test_hostile_filename_roundtrip_in_scanner(tmp_path: Path, require_semgrep, require_sandbox) -> None:
    from hacker_code_konvert.semgrep_adapter import DEFAULT_MEMORY_BYTES, run_semgrep

    names = {"back\\slash.py", "evil\u202e.py", os.fsdecode(b"bad\xff.py")}
    for name in names:
        (tmp_path / name).write_text("eval(input())")
    result = run_semgrep(
        tmp_path,
        build_inventory(tmp_path),
        timeout_seconds=60,
        memory_bytes=DEFAULT_MEMORY_BYTES,
        output_bytes=1000000,
        max_file_bytes=100000,
    )
    assert result.status == "completed", result.errors
    assert {f["location"]["original_path"] for f in result.findings} == names


def test_rule_hash_changes_with_rule_bytes(tmp_path: Path, monkeypatch) -> None:
    directory = tmp_path / "data"
    directory.mkdir()
    rules = directory / "semgrep-rules.yml"
    rules.write_text("rules:\n  - id: hck.test.one\n")
    monkeypatch.setattr("hacker_code_konvert.provenance.files", lambda _: tmp_path)
    before = rules_metadata()
    rules.write_text("rules:\n  - id: hck.test.two\n")
    after = rules_metadata()
    assert before["sha256"] != after["sha256"]
    assert before["ids"] != after["ids"]
