from __future__ import annotations

import json
import os
import shutil
import zipfile
from pathlib import Path

import pytest

from hacker_code_konvert.external import run_external
from hacker_code_konvert.inventory import build_inventory


def run(name: str, root: Path, database: Path | None = None):
    return run_external(
        name,
        root,
        build_inventory(root),
        database=database,
        timeout_seconds=60,
        memory_bytes=16 * 1024**3,
        output_bytes=1000000,
        max_file_bytes=100000,
    )


@pytest.mark.integration
def test_gitleaks_ignores_target_configuration_and_never_copies_git(tmp_path: Path, require_sandbox):
    if not shutil.which("gitleaks"):
        if os.environ.get("HCK_REQUIRE_INTEGRATION") == "1":
            pytest.fail("External scanner is required in CI")
        pytest.skip("Optional Gitleaks binary is required")
    secret = "synthetic_DO_NOT_USE_123456"
    (tmp_path / "config.txt").write_text(f'api_key = "{secret}"')
    (tmp_path / ".gitleaksignore").write_text("*")
    (tmp_path / ".gitleaks.toml").write_text("rules = []")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git/config").write_text('[diff "danger"]\ntextconv = touch /tmp/HCK_MUST_NOT_EXIST')
    result = run("gitleaks", tmp_path)
    assert result.status == "completed", result.errors
    assert result.findings
    assert secret not in json.dumps(result.to_dict())
    assert not Path("/tmp/HCK_MUST_NOT_EXIST").exists()


@pytest.mark.integration
def test_osv_uses_synthetic_local_database_without_network(tmp_path: Path, require_sandbox):
    if not shutil.which("osv-scanner"):
        if os.environ.get("HCK_REQUIRE_INTEGRATION") == "1":
            pytest.fail("External scanner is required in CI")
        pytest.skip("Optional OSV binary is required")
    root = tmp_path / "repository"
    root.mkdir()
    (root / "package-lock.json").write_text(
        json.dumps(
            {
                "name": "fixture",
                "lockfileVersion": 2,
                "packages": {"node_modules/hck-synthetic": {"version": "1.0.0"}},
            }
        )
    )
    database = tmp_path / "database"
    (database / "osv-scalibr/npm").mkdir(parents=True)
    vulnerability = {
        "id": "HCK-TEST-0001",
        "modified": "2026-01-01T00:00:00Z",
        "affected": [{"package": {"name": "hck-synthetic", "ecosystem": "npm"}, "versions": ["1.0.0"]}],
    }
    with zipfile.ZipFile(database / "osv-scalibr/npm/all.zip", "w") as archive:
        archive.writestr("HCK-TEST-0001.json", json.dumps(vulnerability))
    result = run("osv-scanner", root, database)
    assert result.status == "completed", result.errors
    assert result.findings
    assert result.findings[0]["sources"][0]["rule_id"] == "HCK-TEST-0001"


def test_missing_external_binary_fails_closed(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("hacker_code_konvert.external.shutil.which", lambda _: None)
    assert run("gitleaks", tmp_path).status == "unavailable"


def test_osv_requires_explicit_database(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("hacker_code_konvert.external.shutil.which", lambda _: "/usr/bin/true")
    assert run("osv-scanner", tmp_path).status == "unavailable"
