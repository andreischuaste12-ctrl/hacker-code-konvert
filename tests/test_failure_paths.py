from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from hacker_code_konvert.cli import main
from hacker_code_konvert.inventory import build_inventory
from hacker_code_konvert.models import ScannerResult
from hacker_code_konvert.sandbox import CommandResult
from hacker_code_konvert.semgrep_adapter import run_semgrep


@pytest.mark.parametrize(
    ("command", "status"),
    [
        (CommandResult(0, b"", b"", 1, timed_out=True), "timeout"),
        (CommandResult(0, b"", b"", 1, output_limited=True), "output_limited"),
        (CommandResult(9, b"", b"failure", 1), "failed"),
        (CommandResult(0, b"not json", b"", 1), "malformed_output"),
    ],
)
def test_scanner_process_failure_results(tmp_path: Path, monkeypatch, command, status):
    monkeypatch.setattr("hacker_code_konvert.semgrep_adapter.semgrep_executable", lambda: "/bin/true")
    monkeypatch.setattr("hacker_code_konvert.semgrep_adapter.semgrep_version", lambda _: "test")
    monkeypatch.setattr("hacker_code_konvert.semgrep_adapter.run_limited", lambda *a, **k: command)
    (tmp_path / "app.py").write_text("x = 1\n")
    result = run_semgrep(
        tmp_path,
        build_inventory(tmp_path),
        timeout_seconds=5,
        memory_bytes=1024**3,
        output_bytes=10000,
        max_file_bytes=10000,
    )
    assert result.status == status
    assert result.errors


def test_invalid_findings_make_cli_run_incomplete(tmp_path: Path, monkeypatch):
    root = tmp_path / "repo"
    root.mkdir()
    monkeypatch.setattr(
        "hacker_code_konvert.cli.run_semgrep",
        lambda *a, **k: ScannerResult("semgrep", "test", "completed", findings=[{}]),
    )
    output = tmp_path / "report"
    assert main(["scan", str(root), "--output", str(output), "--authorized"]) == 3
    assert json.loads((output / "run.json").read_text())["scanner"]["status"] == "invalid_findings"


def test_fifo_is_skipped(tmp_path: Path):
    os.mkfifo(tmp_path / "file.py")
    inventory = build_inventory(tmp_path)
    assert inventory.skipped[0].reason == "non-regular file not scanned"


def test_unreadable_directory_recorded(tmp_path: Path, monkeypatch):
    (tmp_path / "locked").mkdir()
    (tmp_path / "locked/app.py").write_text("eval(input())\n")
    original_open = os.open

    def denied(path, *args, **kwargs):
        if path == "locked":
            raise PermissionError("synthetic denial")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr("hacker_code_konvert.snapshot.os.open", denied)
    inventory = build_inventory(tmp_path)
    assert inventory.skipped[0].reason == "unreadable directory: PermissionError"
    assert inventory.incomplete


def test_root_warning_and_real_scope_record(tmp_path: Path, monkeypatch):
    root = tmp_path / "repo"
    root.mkdir()
    scope = tmp_path / "scope.json"
    scope.write_text(
        json.dumps(
            {
                "repository": str(root),
                "responsible": "owner",
                "authorization_reference": "written permission",
                "valid_from": "2020-01-01T00:00:00Z",
                "valid_until": "2090-01-01T00:00:00Z",
            }
        )
    )
    output = tmp_path / "out"
    monkeypatch.setattr("hacker_code_konvert.cli.os.geteuid", lambda: 0)
    assert (
        main(
            ["scan", str(root), "--output", str(output), "--scope-file", str(scope), "--scanner", "inventory"]
        )
        == 0
    )
    result = json.loads((output / "run.json").read_text())
    assert result["authorization"]["sha256"]
    assert any("root" in limitation for limitation in result["limitations"])


def test_scan_invalid_root_and_write_failure(tmp_path: Path, monkeypatch):
    assert main(["scan", str(tmp_path / "missing"), "--output", str(tmp_path / "out"), "--authorized"]) == 2
    monkeypatch.setattr(
        "hacker_code_konvert.cli.write_artifacts",
        lambda *a: (_ for _ in ()).throw(OSError("synthetic disk full")),
    )
    assert (
        main(
            [
                "scan",
                str(tmp_path),
                "--output",
                str(tmp_path.parent / "out"),
                "--authorized",
                "--scanner",
                "inventory",
            ]
        )
        == 2
    )


def test_unknown_scanner_version_is_recorded(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        "hacker_code_konvert.cli.run_semgrep", lambda *a, **k: ScannerResult("semgrep", None, "completed")
    )
    output = tmp_path.parent / (tmp_path.name + "-out")
    assert main(["scan", str(tmp_path), "--output", str(output), "--authorized"]) == 0
    assert "version could not be determined" in (output / "report.md").read_text()


def test_sandbox_isolation_construction_failure(tmp_path: Path, monkeypatch):
    monkeypatch.setattr("hacker_code_konvert.semgrep_adapter.semgrep_executable", lambda: "/bin/true")
    monkeypatch.setattr("hacker_code_konvert.semgrep_adapter.semgrep_version", lambda _: "test")
    monkeypatch.setattr(
        "hacker_code_konvert.semgrep_adapter.build_bubblewrap_command",
        lambda *a, **k: (_ for _ in ()).throw(OSError("denied")),
    )
    (tmp_path / "app.py").write_text("x = 1\n")
    result = run_semgrep(
        tmp_path,
        build_inventory(tmp_path),
        timeout_seconds=1,
        memory_bytes=1024**3,
        output_bytes=10000,
        max_file_bytes=1000,
    )
    assert result.status == "failed"
    assert "isolation failed" in result.errors[0]
