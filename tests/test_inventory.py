from __future__ import annotations

import os
from pathlib import Path

import pytest

from hacker_code_konvert.inventory import (
    ScopeError,
    build_inventory,
    resolve_repository,
    stage_scan_files,
    validate_output_path,
)


def test_inventory_does_not_follow_symlinks_or_nested_repositories(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    (root / "app.py").write_text("print('safe')\n", encoding="utf-8")
    (root / "requirements.txt").write_text("example==1.0\n", encoding="utf-8")
    outside = tmp_path / "outside.py"
    outside.write_text("raise RuntimeError\n", encoding="utf-8")
    (root / "escape.py").symlink_to(outside)
    nested = root / "vendor"
    nested.mkdir()
    (nested / ".git").mkdir()
    (nested / "hidden.py").write_text("eval('x')\n", encoding="utf-8")

    inventory = build_inventory(resolve_repository(root))

    assert inventory.scan_files == ["app.py"]
    assert inventory.manifests == ["requirements.txt"]
    reasons = {item.path: item.reason for item in inventory.skipped}
    assert reasons["escape.py"] == "symbolic link not followed"
    assert reasons["vendor"] == "nested repository or submodule not traversed"


def test_lfs_pointer_is_reported_as_unavailable(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    (root / "model.py").write_text(
        "version https://git-lfs.github.com/spec/v1\noid sha256:" + "a" * 64 + "\nsize 42\n",
        encoding="utf-8",
    )
    inventory = build_inventory(root)
    assert inventory.scan_files == []
    assert inventory.skipped[0].reason == "Git LFS pointer; content unavailable"


def test_output_must_be_outside_repository(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    with pytest.raises(ScopeError):
        validate_output_path(root.resolve(), root / "reports")


def test_staging_copies_only_selected_regular_files(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    (root / "app.py").write_text("print('safe')\n", encoding="utf-8")
    (root / ".semgrepignore").write_text("app.py\n", encoding="utf-8")
    inventory = build_inventory(root)
    staged = tmp_path / "staged"
    stage_scan_files(root, inventory, staged, max_file_bytes=1_000_000)
    assert (staged / "app.py").is_file()
    # The only ignore file in the staged tree is the tool-owned empty one, never the target's.
    assert (staged / ".semgrepignore").read_bytes() == b""


def test_unreadable_python_file_is_reported_as_skipped_not_selected(tmp_path: Path) -> None:
    if os.geteuid() == 0:
        pytest.skip("file permissions do not restrict the superuser")
    root = tmp_path / "repository"
    root.mkdir()
    (root / "ok.py").write_text("x = 1\n", encoding="utf-8")
    locked = root / "locked.py"
    locked.write_text("eval('x')\n", encoding="utf-8")
    locked.chmod(0o000)
    try:
        inventory = build_inventory(root)
    finally:
        locked.chmod(0o600)
    assert inventory.scan_files == ["ok.py"]
    assert {item.path: item.reason for item in inventory.skipped}[
        "locked.py"
    ] == "file not readable by the analyzer"


def test_output_validation_rules(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    root = root.resolve()

    fresh = tmp_path / "fresh"
    assert validate_output_path(root, fresh) == fresh.resolve()

    empty = tmp_path / "empty"
    empty.mkdir()
    assert validate_output_path(root, empty) == empty.resolve()

    previous = tmp_path / "previous"
    previous.mkdir()
    for name in ("run.json", "findings.json", "report.md"):
        (previous / name).write_text("{}", encoding="utf-8")
    assert validate_output_path(root, previous) == previous.resolve()

    unrelated = tmp_path / "unrelated"
    unrelated.mkdir()
    (unrelated / "important.docx").write_text("x", encoding="utf-8")
    with pytest.raises(ScopeError):
        validate_output_path(root, unrelated)

    plain_file = tmp_path / "plain_file"
    plain_file.write_text("x", encoding="utf-8")
    with pytest.raises(ScopeError):
        validate_output_path(root, plain_file)

    with pytest.raises(ScopeError):
        validate_output_path(root, tmp_path)  # an ancestor that contains the repository


def test_staging_rejects_a_file_swapped_for_an_outside_symlink(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    (root / "app.py").write_text("x = 1\n", encoding="utf-8")
    secret = tmp_path / "outside_secret.txt"
    secret.write_text("synthetic outside content\n", encoding="utf-8")
    inventory = build_inventory(resolve_repository(root))

    (root / "app.py").unlink()
    (root / "app.py").symlink_to(secret)

    with pytest.raises(ScopeError):
        stage_scan_files(root.resolve(), inventory, tmp_path / "staged", max_file_bytes=1_000_000)
    assert not (tmp_path / "staged" / "app.py").exists()


def test_staging_enforces_size_limit_even_if_the_file_grew(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    (root / "app.py").write_text("x = 1\n", encoding="utf-8")
    inventory = build_inventory(resolve_repository(root))
    (root / "app.py").write_text("x = '" + "A" * 5000 + "'\n", encoding="utf-8")
    with pytest.raises(ScopeError):
        stage_scan_files(root.resolve(), inventory, tmp_path / "staged", max_file_bytes=1000)
