from __future__ import annotations

import os
from pathlib import Path

import pytest

from hacker_code_konvert.inventory import (
    ScopeError,
    build_inventory,
    resolve_repository,
    stage_neutral_files,
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
    # Content that was not analyzed is a coverage gap, never a silent omission.
    assert inventory.incomplete


def test_empty_git_marker_cannot_hide_a_directory_silently(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    (root / "app").mkdir(parents=True)
    (root / "app/vuln.py").write_text("eval(input())\n", encoding="utf-8")
    (root / "app/.git").write_text("", encoding="utf-8")
    inventory = build_inventory(root)
    assert inventory.scan_files == []
    assert inventory.incomplete
    assert [(item.path, item.reason) for item in inventory.skipped] == [
        ("app", "nested repository or submodule not traversed")
    ]


LFS_POINTER = "version https://git-lfs.github.com/spec/v1\noid sha256:" + "a" * 64 + "\nsize 42\n"


def test_lfs_pointer_is_reported_as_unavailable(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    (root / "model.py").write_text(LFS_POINTER, encoding="utf-8")
    (root / "photo.png").write_text(LFS_POINTER, encoding="utf-8")
    inventory = build_inventory(root)
    assert inventory.scan_files == []
    assert {item.path for item in inventory.skipped} == {"model.py", "photo.png"}
    assert inventory.skipped[0].reason == "Git LFS pointer; content unavailable"
    # The missing source file is a coverage gap.
    assert inventory.incomplete


def test_lfs_pointer_of_a_binary_asset_is_not_a_source_coverage_gap(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    (root / "photo.png").write_text(LFS_POINTER, encoding="utf-8")
    inventory = build_inventory(root, scanner="semgrep")
    assert not inventory.incomplete


@pytest.mark.parametrize(
    "content",
    [
        "version https://git-lfs.github.com/spec/v1\n<?php echo $_GET['x'];\n",
        "version https://git-lfs.github.com/spec/v1\n",
        LFS_POINTER + "<?php system($_GET['c']);\n",
        LFS_POINTER.replace("size 42", "size 42 <?php"),
    ],
)
def test_file_that_only_imitates_an_lfs_pointer_is_still_analyzed(tmp_path: Path, content: str) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    (root / "shell.php").write_text(content, encoding="utf-8")
    inventory = build_inventory(root)
    assert inventory.scan_files == ["shell.php"]
    assert inventory.skipped == []


def test_source_files_are_selected_by_suffix_interpreter_line_or_php_tag(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    php = "<?php echo $_GET['x'];\n"
    for name in ("a.phtml", "b.inc", "c.php5", "d.PHP", "plugin.module"):
        (root / name).write_text(php, encoding="utf-8")
    (root / "short-tag.tpl").write_text("\n  <?= $_GET['x'] ?>\n", encoding="utf-8")
    (root / "run").write_text("#!/usr/bin/env python3\neval(input())\n", encoding="utf-8")
    (root / "tool.pyw").write_text("eval(input())\n", encoding="utf-8")
    (root / "cron").write_text("#!/usr/bin/php\n<?php system($argv[1]);\n", encoding="utf-8")
    (root / "notes.txt").write_text("An example: <?php echo 1; ?>\n", encoding="utf-8")
    (root / "app.js").write_text("eval(location.hash)\n", encoding="utf-8")
    inventory = build_inventory(root, scanner="semgrep")
    assert inventory.scan_files == sorted(
        ["a.phtml", "b.inc", "c.php5", "d.PHP", "plugin.module", "short-tag.tpl", "run", "tool.pyw", "cron"]
    )
    assert inventory.languages == {"PHP": 7, "Python": 2, "JavaScript": 1}
    staged = tmp_path / "staged"
    mapping = stage_neutral_files(root, inventory, staged, max_file_bytes=1_000_000)
    # Every selected file is staged under the canonical suffix of its language.
    assert {Path(name).suffix for name in mapping} == {".php", ".py"}
    assert Path(next(name for name, original in mapping.items() if original == "run")).suffix == ".py"


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
    mapping = stage_neutral_files(root, inventory, staged, max_file_bytes=1_000_000)
    assert mapping == {"f000000.py": "app.py"}
    assert (staged / "f000000.py").read_text(encoding="utf-8") == "print('safe')\n"
    # The only ignore file in the staged tree is the tool-owned empty one, never the target's.
    assert (staged / ".semgrepignore").read_bytes() == b""
    assert sorted(entry.name for entry in staged.iterdir()) == [".semgrepignore", "f000000.py"]


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
    assert {item.path: item.reason for item in inventory.skipped}["locked.py"] == (
        "unreadable entry: PermissionError"
    )
    assert inventory.incomplete


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


def test_staging_rejects_a_captured_file_swapped_for_an_outside_symlink(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    (root / "app.py").write_text("x = 1\n", encoding="utf-8")
    secret = tmp_path / "outside_secret.txt"
    secret.write_text("synthetic outside content\n", encoding="utf-8")
    inventory = build_inventory(resolve_repository(root))
    assert inventory.snapshot_root is not None
    captured = inventory.snapshot_root / inventory.snapshot_paths["app.py"]

    captured.unlink()
    captured.symlink_to(secret)

    with pytest.raises(ScopeError):
        stage_neutral_files(root.resolve(), inventory, tmp_path / "staged", max_file_bytes=1_000_000)
    assert list((tmp_path / "staged").glob("f*")) == []


def test_staging_enforces_size_limit_on_the_captured_copy(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    (root / "app.py").write_text("x = 1\n", encoding="utf-8")
    inventory = build_inventory(resolve_repository(root))
    assert inventory.snapshot_root is not None
    captured = inventory.snapshot_root / inventory.snapshot_paths["app.py"]
    captured.chmod(0o600)
    captured.write_text("x = '" + "A" * 5000 + "'\n", encoding="utf-8")
    with pytest.raises(ScopeError):
        stage_neutral_files(root.resolve(), inventory, tmp_path / "staged", max_file_bytes=1000)


def test_later_changes_to_the_repository_do_not_reach_the_scanner(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    (root / "app.py").write_text("x = 1\n", encoding="utf-8")
    inventory = build_inventory(resolve_repository(root))
    (root / "app.py").write_text("changed after capture\n", encoding="utf-8")
    mapping = stage_neutral_files(root, inventory, tmp_path / "staged", max_file_bytes=1000)
    assert (tmp_path / "staged" / next(iter(mapping))).read_text(encoding="utf-8") == "x = 1\n"


def test_staging_requires_a_captured_snapshot(tmp_path: Path) -> None:
    from hacker_code_konvert.models import Inventory

    with pytest.raises(ScopeError):
        stage_neutral_files(tmp_path, Inventory(scan_files=["a.py"]), tmp_path / "staged", max_file_bytes=1)
