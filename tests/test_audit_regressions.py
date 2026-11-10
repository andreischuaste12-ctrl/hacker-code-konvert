from __future__ import annotations

import hashlib
import json
import subprocess

import pytest
from test_reporting import _run

from hacker_code_konvert.cli import _git_revision, main
from hacker_code_konvert.database import database_metadata
from hacker_code_konvert.inventory import ScopeError, build_inventory
from hacker_code_konvert.reporting import write_artifacts
from hacker_code_konvert.semgrep_adapter import DEFAULT_MEMORY_BYTES, run_semgrep


@pytest.mark.integration
def test_contextual_escaping_does_not_hide_insecure_flows(tmp_path, require_semgrep, require_sandbox):
    (tmp_path / "app.php").write_text('''<?php
$id = esc_sql($_GET['id']);
$wpdb->get_results("SELECT * FROM users WHERE id = " . $id);
echo '<a href="' . esc_attr($_GET['url']) . '">open</a>';
echo '<a href="' . esc_url($_GET['safe']) . '">open</a>';
echo '<input value="' . esc_attr($_GET['email']) . '">';
''')
    (tmp_path / "app.py").write_text('''import requests
import urllib.parse
from flask import request
requests.get('http://' + urllib.parse.quote(request.args['host']))
requests.get('https://example.invalid', params={'q': request.args['q']})
''')
    result = run_semgrep(
        tmp_path, build_inventory(tmp_path), timeout_seconds=60,
        memory_bytes=DEFAULT_MEMORY_BYTES, output_bytes=1000000, max_file_bytes=100000,
    )
    assert result.status == "completed", result.errors
    matches = {(f["sources"][0]["rule_id"], f["location"]["start_line"]) for f in result.findings}
    assert matches == {
        ("hck.php.sql-injection", 3), ("hck.php.unsafe-url-attribute", 4),
        ("hck.python.server-side-request-forgery", 4),
    }


def test_interrupted_overwrite_invalidates_previous_run(tmp_path, monkeypatch):
    import hacker_code_konvert.reporting as reporting

    write_artifacts(tmp_path, _run(), [])
    original = reporting._atomic_write

    def fail(path, content):
        if path.name == "results.sarif":
            raise OSError("synthetic full disk")
        original(path, content)

    monkeypatch.setattr(reporting, "_atomic_write", fail)
    with pytest.raises(OSError):
        write_artifacts(tmp_path, _run(run_id="new"), [])
    assert not (tmp_path / "run.json").exists()
    monkeypatch.setattr(reporting, "_atomic_write", original)
    write_artifacts(tmp_path, _run(run_id="retry"), [])
    assert json.loads((tmp_path / "run.json").read_text())["run_id"] == "retry"


@pytest.mark.parametrize("name", ["credentials.env", "key.pem", "data.json", "notes.txt", "unknown"])
def test_lfs_objects_are_required_for_secret_coverage(tmp_path, name):
    (tmp_path / name).write_text(
        "version https://git-lfs.github.com/spec/v1\noid sha256:" + "a" * 64 + "\nsize 300\n"
    )
    inventory = build_inventory(tmp_path, scanner="gitleaks")
    assert inventory.incomplete
    assert inventory.skipped[0].path == name


def test_capture_bounds_links_and_deadline(tmp_path):
    for index in range(25):
        (tmp_path / str(index)).symlink_to("/missing")
    with pytest.raises(ScopeError, match="entry count"):
        build_inventory(tmp_path, max_files=1)
    with pytest.raises(ScopeError, match="time limit"):
        build_inventory(tmp_path, timeout_seconds=0)


@pytest.mark.parametrize("record", [{}, [], {"retrieved_at": 23}, {"retrieved_at": "invalid"}])
def test_bad_database_provenance_has_controlled_error(tmp_path, record):
    (tmp_path / "all.zip").write_bytes(b"synthetic")
    if isinstance(record, dict):
        record["sha256"] = hashlib.sha256(b"synthetic").hexdigest()
    (tmp_path / "provenance.json").write_text(json.dumps(record))
    with pytest.raises(ValueError):
        database_metadata(tmp_path)


def test_invalid_database_produces_incomplete_cli_report(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "requirements.txt").write_text("requests==2.32.5\n")
    db = tmp_path / "db"
    db.mkdir()
    (db / "all.zip").write_bytes(b"synthetic")
    (db / "provenance.json").write_text("[]")
    monkeypatch.setattr("hacker_code_konvert.external.shutil.which", lambda _: "/bin/true")
    out = tmp_path / "report"
    assert main([
        "scan", str(root), "--authorized", "--scanner", "osv-scanner",
        "--offline-database", str(db), "--output", str(out),
    ]) == 3
    assert json.loads((out / "run.json").read_text())["complete"] is False


def test_real_worktree_revision_and_untrusted_pointer(tmp_path):
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run([
        "git", "-C", str(repo), "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
        "commit", "-qm", "initial", "--allow-empty",
    ], check=True)
    linked = tmp_path / "linked"
    subprocess.run(["git", "-C", str(repo), "worktree", "add", "--detach", str(linked)],
                   check=True, capture_output=True)
    assert _git_revision(linked) == _git_revision(repo)
    subprocess.run(["git", "-C", str(linked), "switch", "-c", "linked-branch"],
                   check=True, capture_output=True)
    assert _git_revision(linked) == _git_revision(repo)
    (linked / ".git").write_text("gitdir: /etc\n")
    assert _git_revision(linked) is None
