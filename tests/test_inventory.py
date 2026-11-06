from __future__ import annotations

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
    assert not (staged / ".semgrepignore").exists()
