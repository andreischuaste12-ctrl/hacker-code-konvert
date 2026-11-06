from __future__ import annotations

import os
import shutil
import stat
from pathlib import Path

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

SCANNABLE_SUFFIXES = {".py"}
LFS_HEADER = b"version https://git-lfs.github.com/spec/v1"


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
    return destination


def _relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def _is_lfs_pointer(path: Path) -> bool:
    try:
        if path.stat().st_size > 1024:
            return False
        with path.open("rb") as stream:
            return stream.read(len(LFS_HEADER)) == LFS_HEADER
    except OSError:
        return False


def build_inventory(root: Path, *, max_file_bytes: int = 1_000_000, max_files: int = 10_000) -> Inventory:
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

            if path.name in MANIFEST_NAMES:
                inventory.manifests.append(relative)
            language = LANGUAGE_SUFFIXES.get(path.suffix.lower())
            if language:
                inventory.languages[language] = inventory.languages.get(language, 0) + 1

            if size > max_file_bytes:
                inventory.skipped.append(SkippedEntry(relative, f"file exceeds {max_file_bytes} byte limit"))
                continue
            if _is_lfs_pointer(resolved):
                inventory.skipped.append(SkippedEntry(relative, "Git LFS pointer; content unavailable"))
                continue
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


def stage_scan_files(root: Path, inventory: Inventory, destination: Path, *, max_file_bytes: int) -> None:
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    for relative in inventory.scan_files:
        source = root / relative
        source_stat = source.lstat()
        if stat.S_ISLNK(source_stat.st_mode) or not stat.S_ISREG(source_stat.st_mode):
            raise ScopeError(f"file changed type during staging: {relative}")
        resolved = source.resolve(strict=True)
        if not resolved.is_relative_to(root):
            raise ScopeError(f"file escaped repository during staging: {relative}")
        if resolved.stat().st_size > max_file_bytes:
            raise ScopeError(f"file exceeded size limit during staging: {relative}")
        target = destination / relative
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copyfile(resolved, target)
        target.chmod(0o400)

    for directory, subdirectories, _ in os.walk(destination, topdown=False):
        for name in subdirectories:
            (Path(directory) / name).chmod(0o500)
    destination.chmod(0o500)
