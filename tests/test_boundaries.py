from __future__ import annotations

import json
import runpy
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from hypothesis import given
from hypothesis import strategies as st

from hacker_code_konvert.cli import _git_revision, _read_git_file, main
from hacker_code_konvert.inventory import ScopeError, _copy_regular_file, resolve_repository
from hacker_code_konvert.provenance import translate_paths
from hacker_code_konvert.reporting import _atomic_write
from hacker_code_konvert.sarif import render_sarif
from hacker_code_konvert.scope import load_scope
from hacker_code_konvert.seccomp import filter_file
from hacker_code_konvert.semgrep_adapter import normalize_semgrep, semgrep_version


def test_module_entry_is_covered(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["hck", "--version"])
    with pytest.raises(SystemExit) as error:
        runpy.run_module("hacker_code_konvert", run_name="__main__")
    assert error.value.code == 0


@given(st.binary(max_size=8000))
def test_git_revision_only_returns_object_ids(data: bytes):
    import re
    import tempfile

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / ".git").mkdir()
        (root / ".git/HEAD").write_bytes(data)
        revision = _git_revision(root)
        assert revision is None or re.fullmatch("[0-9a-f]{40}", revision)


def test_read_git_file_io_errors(tmp_path: Path, monkeypatch):
    path = tmp_path / "HEAD"
    path.write_bytes(b"head")
    monkeypatch.setattr("hacker_code_konvert.cli.os.fdopen", lambda *a, **k: (_ for _ in ()).throw(OSError()))
    assert _read_git_file(path, 10) is None


@pytest.mark.parametrize("failure", ["missing", "init", "rule", "export", "network"])
def test_seccomp_preparation_fails_closed(monkeypatch, failure):
    library = MagicMock()
    library.seccomp_init.return_value = 0 if failure == "init" else 1
    library.seccomp_syscall_resolve_name.return_value = 1
    library.seccomp_rule_add.return_value = -1 if failure == "rule" else 0
    library.seccomp_rule_add_array.return_value = -1 if failure == "network" else 0
    library.seccomp_export_bpf.return_value = -1 if failure == "export" else 0
    monkeypatch.setattr(
        "hacker_code_konvert.seccomp.ctypes.util.find_library",
        lambda _: None if failure == "missing" else "fake",
    )
    monkeypatch.setattr("hacker_code_konvert.seccomp.ctypes.CDLL", lambda *a, **k: library)
    with pytest.raises(OSError):
        filter_file()


def test_sarif_with_hostile_filename_validates():
    import jsonschema

    finding = normalize_semgrep({"results": [{"path": "f000000.py"}]}, "test")[0]
    translate_paths([finding], {"f000000.py": "back\\slash\u202e.py"})
    schema = json.loads((Path(__file__).parent / "data/sarif.schema.json").read_text())
    result = render_sarif({"complete": True}, [finding])
    jsonschema.validate(result, schema)
    assert (
        "%5C"
        in result["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    )
    with pytest.raises(ValueError):
        translate_paths([finding], {})


@pytest.mark.parametrize("data", [b"x" * 65537, b"{}", b'{"repository":"/wrong"}'])
def test_scope_missing_fields_and_oversize(tmp_path: Path, data):
    path = tmp_path / "scope.json"
    path.write_bytes(data)
    with pytest.raises(ScopeError):
        load_scope(path, tmp_path)


def test_scope_wrong_repository(tmp_path: Path):
    record = {
        "repository": "/wrong",
        "responsible": "owner",
        "authorization_reference": "reference",
        "valid_from": "2020-01-01T00:00:00Z",
        "valid_until": "2090-01-01T00:00:00Z",
    }
    path = tmp_path / "scope.json"
    path.write_text(json.dumps(record))
    with pytest.raises(ScopeError, match="does not match"):
        load_scope(path, tmp_path)


def test_copy_refuses_parent_symlink_and_escape(tmp_path: Path):
    root = tmp_path / "root"
    root.mkdir()
    (tmp_path / "outside").mkdir()
    (root / "link").symlink_to(tmp_path / "outside", target_is_directory=True)
    with pytest.raises(ScopeError):
        _copy_regular_file(root, "link/file.py", tmp_path / "output", 100)
    with pytest.raises(ScopeError):
        _copy_regular_file(root, "../file.py", tmp_path / "output", 100)
    file = tmp_path / "not-a-directory"
    file.write_text("x")
    with pytest.raises(ScopeError):
        resolve_repository(file)


def test_atomic_write_removes_temporary_on_failure(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(Path, "replace", lambda *a: (_ for _ in ()).throw(OSError("synthetic")))
    with pytest.raises(OSError):
        _atomic_write(tmp_path / "report", "content")
    assert list(tmp_path.iterdir()) == []


def test_semgrep_version_failed_and_missing(monkeypatch):
    monkeypatch.setattr(
        "hacker_code_konvert.semgrep_adapter.subprocess.run", lambda *a, **k: (_ for _ in ()).throw(OSError())
    )
    assert semgrep_version("/absent") is None


def test_positive_integer_arguments_reject_zero(tmp_path: Path):
    with pytest.raises(SystemExit):
        main(["scan", str(tmp_path), "--output", "/tmp/example", "--timeout", "0"])


def test_probe_and_descriptor_errors(tmp_path: Path, monkeypatch):
    from hacker_code_konvert.inventory import _opened_path_is_within, _probe_file

    assert _probe_file(tmp_path / "absent") == "unreadable"
    monkeypatch.setattr(
        "hacker_code_konvert.inventory.os.readlink", lambda *a: (_ for _ in ()).throw(OSError())
    )
    assert _opened_path_is_within(999, tmp_path)


def test_staging_file_type_and_size_changes(tmp_path: Path):
    import os

    os.mkfifo(tmp_path / "fifo")
    with pytest.raises(ScopeError, match="changed type"):
        _copy_regular_file(tmp_path, "fifo", tmp_path / "out", 10)
    (tmp_path / "big").write_bytes(b"123456")
    with pytest.raises(ScopeError, match="size limit"):
        _copy_regular_file(tmp_path, "big", tmp_path / "out", 2)


def test_missing_bubblewrap_and_version_errors(monkeypatch):
    import subprocess

    from hacker_code_konvert import sandbox

    monkeypatch.setattr(sandbox.shutil, "which", lambda _: None)
    assert not sandbox.bubblewrap_supported()
    assert sandbox.bubblewrap_version() is None
    with pytest.raises(sandbox.SandboxUnavailable):
        sandbox.bubblewrap_path()
    monkeypatch.setattr(sandbox, "bubblewrap_path", lambda: "/usr/bin/bwrap")
    monkeypatch.setattr(
        sandbox.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess([], 1, stdout=b"")
    )
    assert sandbox.bubblewrap_version() is None
    monkeypatch.setattr(sandbox.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(OSError()))
    assert sandbox.bubblewrap_version() is None


def test_semgrep_failed_version_and_empty_relative_path(monkeypatch):
    import subprocess

    from hacker_code_konvert.semgrep_adapter import _safe_relative_path

    monkeypatch.setattr(
        "hacker_code_konvert.semgrep_adapter.subprocess.run",
        lambda *a, **k: subprocess.CompletedProcess([], 1, stdout=b""),
    )
    assert semgrep_version("/bin/true") is None
    assert _safe_relative_path("") == "unknown"
    assert _safe_relative_path("/elsewhere") == "unknown"


def test_external_empty_input_and_malformed_output(tmp_path: Path, monkeypatch):
    from hacker_code_konvert.external import run_external
    from hacker_code_konvert.inventory import build_inventory
    from hacker_code_konvert.sandbox import CommandResult

    options = dict(timeout_seconds=5, memory_bytes=1024**3, output_bytes=1000, max_file_bytes=1000)
    monkeypatch.setattr("hacker_code_konvert.external.shutil.which", lambda _: "/bin/true")
    assert (
        run_external("gitleaks", tmp_path, build_inventory(tmp_path), **options).status == "partial_coverage"
    )
    (tmp_path / "config.txt").write_text("safe")
    monkeypatch.setattr(
        "hacker_code_konvert.external.run_limited", lambda *a, **k: CommandResult(0, b"{}", b"", 1)
    )
    assert run_external("gitleaks", tmp_path, build_inventory(tmp_path), **options).status == "failed"
    monkeypatch.setattr(
        "hacker_code_konvert.external.run_limited", lambda *a, **k: CommandResult(2, b"", b"failed", 1)
    )
    assert run_external("gitleaks", tmp_path, build_inventory(tmp_path), **options).status == "failed"
