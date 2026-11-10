from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from hacker_code_konvert.cli import main
from hacker_code_konvert.database import database_metadata, osv_severity
from hacker_code_konvert.inventory import build_inventory
from hacker_code_konvert.provenance import translate_paths
from hacker_code_konvert.semgrep_adapter import normalize_semgrep


def test_snapshot_selects_only_scanner_inputs_and_caps_total(tmp_path: Path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_bytes(b"x" * 8)
    (root / "other.py").write_bytes(b"x" * 8)
    (root / "data.bin").write_bytes(b"x" * 10000)
    inventory = build_inventory(root, snapshot=tmp_path / "capture", scanner="semgrep", max_total_bytes=10)
    assert sum(p.stat().st_size for p in (tmp_path / "capture").iterdir()) <= 10
    assert inventory.incomplete
    assert all(p.suffix == ".py" for p in (tmp_path / "capture").iterdir())
    (root / "requirements-dev.txt").write_text("synthetic==1.0.0")
    inventory = build_inventory(root, snapshot=tmp_path / "deps", scanner="osv-scanner")
    assert inventory.manifests == ["requirements-dev.txt"]
    assert inventory.regular_files == ["requirements-dev.txt"]


def test_deep_repository_produces_incomplete_report_without_recursion(tmp_path: Path):
    root = tmp_path / "repo"
    root.mkdir()
    directories = []
    directory = root
    try:
        for _ in range(1100):
            directory = directory / "d"
            directory.mkdir()
            directories.append(directory)
        out = tmp_path / "report"
        assert main(["scan", str(root), "--output", str(out), "--authorized", "--scanner", "inventory"]) == 3
        run = json.loads((out / "run.json").read_text())
        assert not run["complete"]
        assert "depth" in run["inventory"]["skipped"][0]["reason"]
    finally:
        for directory in reversed(directories):
            directory.rmdir()


def test_database_digest_age_and_tamper(tmp_path: Path):
    archive = tmp_path / "npm/all.zip"
    archive.parent.mkdir()
    archive.write_bytes(b"synthetic database")
    missing, warnings = database_metadata(tmp_path)
    assert warnings and missing["archives"][0]["sha256"]
    record = archive.with_name("provenance.json")
    provenance = {
        "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        "retrieved_at": (datetime.now(UTC) - timedelta(days=40)).isoformat(),
    }
    record.write_text(json.dumps(provenance))
    old, warnings = database_metadata(tmp_path)
    assert "exceeds 30 days" in warnings[0]
    assert old["manifest_sha256"] == missing["manifest_sha256"]
    archive.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="does not match"):
        database_metadata(tmp_path)


@pytest.mark.parametrize(
    "vector,level",
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "critical"),
        ("9.1", "critical"),
        ("7.0", "high"),
        ("5.0", "medium"),
        ("2.0", "low"),
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "critical"),
    ],
)
def test_osv_severity_uses_cvss(vector, level):
    severity, risk = osv_severity({"severity": [{"score": vector}]})
    assert severity == level and risk["severity_assessed"]


def test_unscored_advisory_is_explicit_and_unicode_path_is_preserved():
    severity, risk = osv_severity({"severity": [{"score": "bad"}, {"score": "100"}]})
    assert severity == "informational" and not risk["severity_assessed"]
    assert osv_severity({"database_specific": {"severity": "HIGH"}})[0] == "high"
    finding = normalize_semgrep({"results": [{"path": "f000000.py"}]}, "test")[0]
    translate_paths([finding], {"f000000.py": "módulo.py"})
    assert finding["location"]["path"] == finding["location"]["display_path"] == "módulo.py"


@pytest.mark.parametrize("timestamp", ["2000-01-01", "2999-01-01T00:00:00+00:00"])
def test_database_rejects_unreliable_provenance_dates(tmp_path: Path, timestamp):
    archive = tmp_path / "all.zip"
    archive.write_bytes(b"synthetic")
    archive.with_name("provenance.json").write_text(
        json.dumps({"sha256": hashlib.sha256(archive.read_bytes()).hexdigest(), "retrieved_at": timestamp})
    )
    with pytest.raises(ValueError):
        database_metadata(tmp_path)


def test_database_rejects_empty_symlinked_and_oversized_records(tmp_path: Path):
    with pytest.raises(ValueError, match="no ecosystem"):
        database_metadata(tmp_path)
    external = tmp_path / "source"
    external.write_bytes(b"synthetic")
    archive = tmp_path / "all.zip"
    archive.symlink_to(external)
    with pytest.raises(ValueError, match="symbolic"):
        database_metadata(tmp_path)
    archive.unlink()
    archive.write_bytes(b"synthetic")
    archive.with_name("provenance.json").write_bytes(b"x" * 65537)
    with pytest.raises(ValueError, match="oversized"):
        database_metadata(tmp_path)


@pytest.mark.parametrize(
    "score",
    [
        "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:L",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        "CVSS:3.1/broken",
        "nan",
        "-1",
    ],
)
def test_cvss_edge_cases_are_bounded(score):
    severity, risk = osv_severity({"severity": [{"score": score}]})
    assert severity in ("informational", "low", "medium", "high", "critical")
    if risk["severity_assessed"]:
        assert 0 <= risk["cvss_score"] <= 10


@pytest.mark.integration
def test_extended_taint_sources_and_nonsecurity_hashes(tmp_path: Path, require_semgrep, require_sandbox):
    from hacker_code_konvert.semgrep_adapter import DEFAULT_MEMORY_BYTES, run_semgrep

    (tmp_path / "app.py").write_text("""
import os, subprocess, hashlib
from flask import request
os.popen(request.form['command'])
subprocess.Popen(request.get_json()['command'], shell=True)
conn.execute('SELECT * FROM users WHERE id=' + request.POST['id'])
hashlib.md5(b'cache-key', usedforsecurity=False)
hashlib.sha1(b'cache-key', usedforsecurity=False)
hashlib.new('md5', input().encode())
""")
    result = run_semgrep(
        tmp_path,
        build_inventory(tmp_path),
        timeout_seconds=60,
        memory_bytes=DEFAULT_MEMORY_BYTES,
        output_bytes=1000000,
        max_file_bytes=100000,
    )
    assert result.status == "completed", result.errors
    assert {f["sources"][0]["rule_id"] for f in result.findings} == {
        "hck.python.shell-system",
        "hck.python.shell-subprocess",
        "hck.python.sql-injection",
        "hck.python.weak-hash",
    }
    assert not any(f["location"]["start_line"] in (7, 8) for f in result.findings)


def test_recent_database_no_warning_and_sarif_version(tmp_path: Path):
    from hacker_code_konvert import __version__
    from hacker_code_konvert.sarif import render_sarif

    archive = tmp_path / "all.zip"
    archive.write_bytes(b"synthetic")
    archive.with_name("provenance.json").write_text(
        json.dumps(
            {
                "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                "retrieved_at": (datetime.now(UTC) - timedelta(seconds=5)).isoformat(),
            }
        )
    )
    assert database_metadata(tmp_path)[1] == []
    result = render_sarif({"complete": True}, [])
    assert result["runs"][0]["tool"]["driver"]["version"] == __version__


def test_release_build_cannot_write_and_admin_bypass_requires_pr():
    workflow = Path(".github/workflows/release.yml").read_text()
    build = workflow.split("  build:", 1)[1].split("  attest-release:", 1)[0]
    assert "contents: write" not in build
    assert "id-token: write" not in build
    assert "persist-credentials: false" in build
    rules = json.loads(Path("examples/main-ruleset.json").read_text())
    assert rules["bypass_actors"] == [
        {"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "pull_request"}
    ]


def test_osv_rejects_unpinned_requirements(tmp_path: Path, monkeypatch):
    import zipfile

    from hacker_code_konvert.external import run_external

    root = tmp_path / "repo"
    root.mkdir()
    (root / "requirements.txt").write_text("package>=1.0\n")
    database = tmp_path / "db"
    database.mkdir()
    with zipfile.ZipFile(database / "all.zip", "w"):
        pass
    monkeypatch.setattr("hacker_code_konvert.external.shutil.which", lambda _: "/bin/true")
    result = run_external(
        "osv-scanner",
        root,
        build_inventory(root),
        database=database,
        timeout_seconds=1,
        memory_bytes=1024**3,
        output_bytes=10000,
        max_file_bytes=10000,
    )
    # Nothing could be analyzed, which is a coverage gap rather than a crash of the whole scan.
    assert result.status == "partial_coverage"
    assert "unpinned" in result.errors[0]
    assert not result.findings
