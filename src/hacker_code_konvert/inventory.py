from __future__ import annotations

import os
import stat
from pathlib import Path

from hacker_code_konvert.formats import dependency_file
from hacker_code_konvert.models import Inventory, SkippedEntry

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

SCANNABLE_SUFFIXES = {".py", ".php"}
LFS_HEADER = b"version https://git-lfs.github.com/spec/v1"
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
                "artifacts (run.json, findings.json, report.md)"
            )
    return destination


def _relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def _probe_file(path: Path) -> str:
    """Classify a regular file as ``ok``, ``lfs``, or ``unreadable`` without following symlinks."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return "unreadable"
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            header = stream.read(len(LFS_HEADER))
            if header != LFS_HEADER:
                return "ok"
            return "lfs" if os.fstat(stream.fileno()).st_size <= 1024 else "ok"
    except OSError:
        return "unreadable"


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
    if snapshot is not None:
        from hacker_code_konvert.snapshot import capture

        return capture(root, snapshot, max_file_bytes, max_files, scanner, max_total_bytes, max_depth)
    inventory = Inventory()
    pending = [root]

    while pending:
        directory = pending.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as error:
            inventory.skipped.append(
                SkippedEntry(_relative(root, directory), f"unreadable directory: {error.__class__.__name__}")
            )
            continue

        for entry in entries:
            path = Path(entry.path)
            relative = _relative(root, path)
            if relative == ".git" or relative.startswith(".git/"):
                continue
            try:
                mode = entry.stat(follow_symlinks=False).st_mode
            except OSError as error:
                inventory.skipped.append(
                    SkippedEntry(relative, f"unreadable entry: {error.__class__.__name__}")
                )
                continue

            if stat.S_ISLNK(mode):
                inventory.skipped.append(SkippedEntry(relative, "symbolic link not followed"))
                continue

            if stat.S_ISDIR(mode):
                if (path / ".git").exists():
                    inventory.skipped.append(
                        SkippedEntry(relative, "nested repository or submodule not traversed")
                    )
                    continue
                pending.append(path)
                continue

            if not stat.S_ISREG(mode):
                inventory.skipped.append(SkippedEntry(relative, "non-regular file not scanned"))
                continue

            resolved = path.resolve(strict=True)
            if not resolved.is_relative_to(root):
                inventory.skipped.append(SkippedEntry(relative, "resolved path escapes repository root"))
                continue

            size = resolved.stat().st_size
            inventory.files_seen += 1
            inventory.bytes_seen += size
            if inventory.files_seen > max_files:
                raise ScopeError(f"repository exceeds maximum file count ({max_files})")

            if path.name in MANIFEST_NAMES or dependency_file(path.name):
                inventory.manifests.append(relative)
            language = LANGUAGE_SUFFIXES.get(path.suffix.lower())
            if language:
                inventory.languages[language] = inventory.languages.get(language, 0) + 1

            if size > max_file_bytes:
                inventory.skipped.append(SkippedEntry(relative, f"file exceeds {max_file_bytes} byte limit"))
                continue
            probe = _probe_file(resolved)
            if probe == "lfs":
                inventory.skipped.append(SkippedEntry(relative, "Git LFS pointer; content unavailable"))
                continue
            if probe == "unreadable":
                inventory.skipped.append(SkippedEntry(relative, "file not readable by the analyzer"))
                continue
            inventory.regular_files.append(relative)
            if path.suffix.lower() in SCANNABLE_SUFFIXES:
                inventory.scan_files.append(relative)

    inventory.manifests.sort()
    inventory.scan_files.sort()
    inventory.skipped.sort(key=lambda item: item.path)
    if (root / ".gitattributes").exists():
        inventory.limitations.append(
            "Git attributes are reported but filters are not executed by the analyzer."
        )
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


def stage_scan_files(root: Path, inventory: Inventory, destination: Path, *, max_file_bytes: int) -> None:
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    for relative in inventory.scan_files:
        _copy_regular_file(root, relative, destination / relative, max_file_bytes)

    # Tool-owned, empty ignore file: disables Semgrep's built-in default ignores without
    # ever importing patterns from the analyzed repository.
    ignore_file = destination / SEMGREP_IGNORE_NAME
    ignore_file.write_bytes(b"")
    ignore_file.chmod(0o400)

    for directory, subdirectories, _ in os.walk(destination, topdown=False):
        for name in subdirectories:
            (Path(directory) / name).chmod(0o500)
    destination.chmod(0o500)


def stage_neutral_files(
    root: Path, inventory: Inventory, destination: Path, *, max_file_bytes: int
) -> dict[str, str]:
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    mapping = {}
    for index, relative in enumerate(inventory.scan_files):
        name = f"f{index:06d}{Path(relative).suffix.lower()}"
        source_root = inventory.snapshot_root or root
        source_relative = inventory.snapshot_paths[relative] if inventory.snapshot_root else relative
        _copy_regular_file(source_root, source_relative, destination / name, max_file_bytes)
        mapping[name] = relative
    (destination / SEMGREP_IGNORE_NAME).write_bytes(b"")
    destination.chmod(0o500)
    return mapping
