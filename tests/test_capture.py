from __future__ import annotations

import os
from pathlib import Path

import pytest

from hacker_code_konvert.cgroups import delegated_tasks
from hacker_code_konvert.inventory import ScopeError, build_inventory, stage_neutral_files


def test_single_pass_capture_is_independent_of_later_source_changes(tmp_path: Path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".git").mkdir()
    (root / "nested").mkdir()
    (root / "nested/a.py").write_text("eval(input())")
    (root / "badlink.py").symlink_to("/etc/passwd")
    os.mkfifo(root / "fifo.py")
    (root / "vendor").mkdir()
    (root / "vendor/.git").write_text("gitdir: elsewhere")
    (root / "vendor/x.py").write_text("not in scope")
    (root / "big.py").write_bytes(b"x" * 101)
    (root / "lfs.py").write_bytes(b"version https://git-lfs.github.com/spec/v1\n")
    (root / "package-lock.json").write_text("{}")
    inventory = build_inventory(root, snapshot=tmp_path / "capture", max_file_bytes=100)
    assert inventory.scan_files == ["nested/a.py"]
    assert inventory.manifests == ["package-lock.json"]
    assert len(inventory.skipped) == 5
    (root / "nested/a.py").write_text("modified")
    mapping = stage_neutral_files(root, inventory, tmp_path / "stage", max_file_bytes=100)
    assert (tmp_path / "stage" / next(iter(mapping))).read_text() == "eval(input())"
    assert "snapshot_root" not in inventory.to_dict()


def test_capture_file_count_and_unreadable_entry(tmp_path: Path, monkeypatch):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "a.py").write_text("x")
    with pytest.raises(ScopeError):
        build_inventory(root, snapshot=tmp_path / "capture", max_files=0)
    original_open = os.open

    def denied(path, *args, **kwargs):
        if path == "a.py":
            raise PermissionError()
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr("hacker_code_konvert.snapshot.os.open", denied)
    inventory = build_inventory(root, snapshot=tmp_path / "denied")
    assert len(inventory.skipped) == 1


def test_cgroups_optional_or_invalid(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("HCK_CGROUP_PARENT", raising=False)
    with delegated_tasks() as path:
        assert path is None
    monkeypatch.setenv("HCK_CGROUP_PARENT", str(tmp_path))
    with pytest.raises(OSError), delegated_tasks():
        pass


def test_delegated_cgroup_configuration_and_cleanup(tmp_path: Path, monkeypatch):
    parent = tmp_path / "delegated"
    parent.mkdir()
    (parent / "cgroup.controllers").write_text("pids")
    monkeypatch.setenv("HCK_CGROUP_PARENT", str(parent))
    # Emulate only the delegated filesystem, not kernel PID-limit semantics.
    monkeypatch.setattr(Path, "is_relative_to", lambda self, other: True)
    original_rmdir = Path.rmdir

    def remove(path):
        if path.name.startswith("hck-"):
            for entry in path.iterdir():
                entry.unlink()
        original_rmdir(path)

    monkeypatch.setattr(Path, "rmdir", remove)
    monkeypatch.setenv("HCK_TASKS_MAX", "32")
    with delegated_tasks() as procs:
        assert procs is not None
        assert (procs.parent / "pids.max").read_text() == "32"
    assert list(parent.iterdir()) == [parent / "cgroup.controllers"]
    for count in ("0", "5000"):
        monkeypatch.setenv("HCK_TASKS_MAX", count)
        with pytest.raises(ValueError), delegated_tasks():
            pass


def test_capture_detects_in_place_growth(tmp_path: Path, monkeypatch):
    import stat
    from types import SimpleNamespace

    root = tmp_path / "repo"
    root.mkdir()
    (root / "grow.py").write_bytes(b"x" * 11)
    monkeypatch.setattr(
        "hacker_code_konvert.snapshot.os.fstat", lambda _: SimpleNamespace(st_mode=stat.S_IFREG, st_size=1)
    )
    inventory = build_inventory(root, snapshot=tmp_path / "capture", max_file_bytes=10)
    assert inventory.skipped[0].reason == "file grew beyond size limit"
    monkeypatch.setattr(
        "hacker_code_konvert.snapshot.os.fstat", lambda _: SimpleNamespace(st_mode=stat.S_IFIFO, st_size=0)
    )
    inventory = build_inventory(root, snapshot=tmp_path / "fifo", max_file_bytes=10)
    assert "unreadable entry" in inventory.skipped[0].reason
