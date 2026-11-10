from __future__ import annotations

import os
import shutil
import stat
import tempfile
import weakref
from pathlib import Path

from hacker_code_konvert.formats import neutral_suffix
from hacker_code_konvert.models import Inventory

LANGUAGE_SUFFIXES = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".java": "Java",
    ".go": "Go",
    ".rs": "Rust",
    ".php": "PHP",
    ".rb": "Ruby",
    ".cs": "C#",
}

MANIFEST_NAMES = {
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "pyproject.toml",
    "requirements.txt",
    "poetry.lock",
    "Pipfile.lock",
    "pom.xml",
    "build.gradle",
    "go.mod",
    "go.sum",
    "Cargo.toml",
    "Cargo.lock",
    "composer.json",
    "composer.lock",
    "Gemfile",
    "Gemfile.lock",
}

# Files the CLI itself writes; an output directory may already contain only these.
ARTIFACT_NAMES = frozenset({"run.json", "findings.json", "report.md", "results.sarif"})
# Semgrep falls back to built-in ignore patterns (such as tests/ and test/) when the scanned
# root has no .semgrepignore. The staged tree always carries this tool-owned, empty file so
# repository content can never be skipped silently and no built-in default applies.
SEMGREP_IGNORE_NAME = ".semgrepignore"
COPY_CHUNK_BYTES = 64 * 1024


class ScopeError(ValueError):
    pass


def resolve_repository(path: str | Path) -> Path:
    root = Path(path).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ScopeError("repository path must be a directory")
    return root


def validate_output_path(root: Path, output: str | Path) -> Path:
    destination = Path(output).expanduser().resolve(strict=False)
    if destination == root or destination.is_relative_to(root):
        raise ScopeError("output directory must be outside the analyzed repository")
    if destination.exists():
        if not destination.is_dir():
            raise ScopeError("output path exists and is not a directory")
        unrelated = sorted(entry.name for entry in destination.iterdir() if entry.name not in ARTIFACT_NAMES)
        if unrelated:
            raise ScopeError(
                "output directory must be new, empty, or contain only previous Hacker Code Konvert "
                "artifacts (run.json, findings.json, report.md, results.sarif)"
            )
    return destination


def build_inventory(
    root: Path,
    *,
    max_file_bytes: int = 1_000_000,
    max_files: int = 10_000,
    snapshot: Path | None = None,
    scanner: str = "all",
    max_total_bytes: int = 256 * 1024**2,
    max_depth: int = 64,
) -> Inventory:
    """Inventory the repository and capture the selected files in one descriptor-relative pass.

    ``snapshot`` is the private directory that receives the captured bytes. When it is omitted a
    temporary one is created and removed together with the returned inventory.
    """
    from hacker_code_konvert.snapshot import capture

    if snapshot is not None:
        return capture(root, snapshot, max_file_bytes, max_files, scanner, max_total_bytes, max_depth)
    owner = Path(tempfile.mkdtemp(prefix="hck-capture-"))
    try:
        inventory = capture(
            root, owner / "files", max_file_bytes, max_files, scanner, max_total_bytes, max_depth
        )
    except BaseException:
        shutil.rmtree(owner, ignore_errors=True)
        raise
    weakref.finalize(inventory, shutil.rmtree, owner, True)
    return inventory


def _opened_path_is_within(descriptor: int, root: Path) -> bool:
    """Confirm, where the platform allows it, that an open descriptor still lives under root."""
    try:
        opened = Path(os.readlink(f"/proc/self/fd/{descriptor}"))
    except OSError:
        return True  # No /proc: rely on the checks made before opening.
    return opened.is_relative_to(root)


def _copy_regular_file(root: Path, relative: str, target: Path, max_file_bytes: int) -> None:
    parts = Path(relative).parts
    if not parts or any(part in ("..", ".") for part in parts) or Path(relative).is_absolute():
        raise ScopeError("invalid staging path")
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        descriptor = os.open(
            parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory
        )
    except OSError as error:
        raise ScopeError(f"file could not be opened safely during staging: {relative!r}") from error
    finally:
        os.close(directory)
    with os.fdopen(descriptor, "rb", closefd=True) as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode):
            raise ScopeError(f"file changed type during staging: {relative}")
        if not _opened_path_is_within(stream.fileno(), root):
            raise ScopeError(f"file escaped repository during staging: {relative}")
        if opened.st_size > max_file_bytes:
            raise ScopeError(f"file exceeded size limit during staging: {relative}")
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        copied = 0
        with target.open("xb") as output:
            while chunk := stream.read(COPY_CHUNK_BYTES):
                copied += len(chunk)
                if copied > max_file_bytes:
                    raise ScopeError(f"file exceeded size limit during staging: {relative}")
                output.write(chunk)
    target.chmod(0o400)


def stage_neutral_files(
    root: Path, inventory: Inventory, destination: Path, *, max_file_bytes: int
) -> dict[str, str]:
    """Copy the selected source files from the private capture under neutral, canonical names."""
    if inventory.snapshot_root is None:
        raise ScopeError("inventory has no captured snapshot to stage from")
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    mapping = {}
    for index, relative in enumerate(inventory.scan_files):
        name = f"f{index:06d}{neutral_suffix(relative, inventory.source_languages.get(relative))}"
        _copy_regular_file(
            inventory.snapshot_root, inventory.snapshot_paths[relative], destination / name, max_file_bytes
        )
        mapping[name] = relative
    # Tool-owned, empty ignore file: disables Semgrep's built-in default ignores without ever
    # importing patterns from the analyzed repository.
    ignore_file = destination / SEMGREP_IGNORE_NAME
    ignore_file.write_bytes(b"")
    ignore_file.chmod(0o400)
    destination.chmod(0o500)
    return mapping
