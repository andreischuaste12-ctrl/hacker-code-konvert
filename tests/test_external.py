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


@pytest.mark.integration
def test_vendor_secret_rules_cover_seven_synthetic_formats(tmp_path: Path, require_sandbox):
    if not shutil.which("gitleaks"):
        pytest.fail("Gitleaks binary required for security regression")
    import hashlib

    token = hashlib.sha256(b"HCK-PUBLIC-SYNTHETIC-NOT-A-CREDENTIAL").hexdigest()
    samples = {
        "aws.env": 'aws_access_key_id = "'
        + "AKIA"
        + __import__("base64").b32encode(hashlib.sha256(b"public synthetic id").digest()).decode()[:16]
        + '"',
        "github.env": 'GITHUB_TOKEN="' + "ghp_" + token[:36] + '"',
        "stripe.env": 'STRIPE_KEY="' + "sk_live_" + token[:32] + '"',
        "slack.env": 'SLACK_TOKEN="' + "xoxb-" + "123456789012-987654321098-" + token[:24] + '"',
        "key.pem": "-----BEGIN PRIVATE KEY-----\n" + token * 3 + "\n-----END PRIVATE KEY-----",
        "settings.json": json.dumps({"api_key": token}),
        "generic.env": 'PASSWORD="' + token + '"',
    }
    for name, value in samples.items():
        (tmp_path / name).write_text(value)
    result = run("gitleaks", tmp_path)
    assert result.status == "completed", result.errors
    observed = {f["location"]["original_path"] for f in result.findings}
    assert observed == set(samples)
    for secret in (token, "ghp_" + token[:36], "sk_live_" + token[:32]):
        assert secret not in json.dumps(result.to_dict())


@pytest.mark.integration
def test_osv_accepts_fixed_python_requirements_and_maps_cvss(tmp_path: Path, require_sandbox):
    if not shutil.which("osv-scanner"):
        pytest.fail("OSV binary required for security regression")
    root = tmp_path / "repo"
    root.mkdir()
    (root / "requirements-dev.txt").write_text("hck-synthetic==1.0.0\n")
    database = tmp_path / "db"
    ecosystem = database / "osv-scalibr/PyPI"
    ecosystem.mkdir(parents=True)
    vuln = {
        "id": "HCK-PYPI-TEST",
        "modified": "2026-01-01T00:00:00Z",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "affected": [{"package": {"name": "hck-synthetic", "ecosystem": "PyPI"}, "versions": ["1.0.0"]}],
    }
    with zipfile.ZipFile(ecosystem / "all.zip", "w") as archive:
        archive.writestr("HCK-PYPI-TEST.json", json.dumps(vuln))
    result = run("osv-scanner", root, database)
    assert result.status == "completed", result.errors
    assert result.findings[0]["severity"] == "critical"
    assert result.findings[0]["location"]["path"] == "requirements-dev.txt"
    assert result.database["archives"][0]["sha256"]
