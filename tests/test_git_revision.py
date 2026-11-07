from __future__ import annotations

import os
from pathlib import Path

from hacker_code_konvert.cli import _git_revision

COMMIT = "0123456789abcdef0123456789abcdef01234567"


def _repository(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "repository"
    git_dir = root / ".git"
    git_dir.mkdir(parents=True)
    return root.resolve(), git_dir


def test_detached_head_is_returned(tmp_path: Path) -> None:
    root, git_dir = _repository(tmp_path)
    (git_dir / "HEAD").write_text(f"{COMMIT}\n")
    assert _git_revision(root) == COMMIT


def test_loose_and_packed_references_are_resolved(tmp_path: Path) -> None:
    root, git_dir = _repository(tmp_path)
    (git_dir / "HEAD").write_text("ref: refs/heads/main\n")
    (git_dir / "refs" / "heads").mkdir(parents=True)
    (git_dir / "refs" / "heads" / "main").write_text(f"{COMMIT}\n")
    assert _git_revision(root) == COMMIT

    (git_dir / "refs" / "heads" / "main").unlink()
    (git_dir / "packed-refs").write_text(f"# pack-refs\n{COMMIT} refs/heads/main\n")
    assert _git_revision(root) == COMMIT


def test_reference_cannot_traverse_out_of_git_directory(tmp_path: Path) -> None:
    # A 40-character file outside the repository must never be read into the report.
    root, git_dir = _repository(tmp_path)
    (tmp_path / "outside.txt").write_text("a" * 40)
    for hostile in ("ref: ../../outside.txt", "ref: refs/../../../outside.txt", "ref: /etc/hostname"):
        (git_dir / "HEAD").write_text(hostile + "\n")
        assert _git_revision(root) is None


def test_head_symlink_is_not_followed(tmp_path: Path) -> None:
    root, git_dir = _repository(tmp_path)
    (tmp_path / "outside.txt").write_text("b" * 40)
    (git_dir / "HEAD").symlink_to(tmp_path / "outside.txt")
    assert _git_revision(root) is None


def test_endless_head_is_rejected_without_reading_it_all(tmp_path: Path) -> None:
    # Previously read_text() on /dev/zero exhausted the analyzer's memory.
    root, git_dir = _repository(tmp_path)
    (git_dir / "HEAD").symlink_to("/dev/zero")
    assert _git_revision(root) is None


def test_fifo_head_does_not_block(tmp_path: Path) -> None:
    root, git_dir = _repository(tmp_path)
    os.mkfifo(git_dir / "HEAD")
    assert _git_revision(root) is None


def test_symlinked_git_directory_is_ignored(tmp_path: Path) -> None:
    real = tmp_path / "elsewhere"
    real.mkdir()
    (real / "HEAD").write_text(f"{COMMIT}\n")
    root = tmp_path / "repository"
    root.mkdir()
    (root / ".git").symlink_to(real)
    assert _git_revision(root.resolve()) is None


def test_non_hexadecimal_or_oversized_values_are_rejected(tmp_path: Path) -> None:
    root, git_dir = _repository(tmp_path)
    (git_dir / "HEAD").write_text("SYNTHETIC-NOT-A-HEX-OBJECT-ID-0123456789\n")
    assert _git_revision(root) is None
    (git_dir / "HEAD").write_text("x" * 100_000)
    assert _git_revision(root) is None
