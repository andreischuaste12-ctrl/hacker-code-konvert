"""One-pass descriptor-relative inventory and capture of selected regular files."""

from __future__ import annotations

import os
import stat
import time
from pathlib import Path

from hacker_code_konvert.formats import (
    SOURCE_LANGUAGES,
    SOURCE_SNIFF_BYTES,
    dependency_file,
    is_lfs_pointer,
    neutral_suffix,
    source_language,
)
from hacker_code_konvert.inventory import LANGUAGE_SUFFIXES, MANIFEST_NAMES, ScopeError
from hacker_code_konvert.models import Inventory, SkippedEntry

READ_CHUNK_BYTES = 65536
NESTED_REPOSITORY = "nested repository or submodule not traversed"


def _gap(inventory: Inventory, relative: str, reason: str) -> None:
    """Record content the scanner will not see. Every such entry makes the run incomplete."""
    inventory.skipped.append(SkippedEntry(relative, reason))
    inventory.incomplete = True


def capture(
    root: Path,
    destination: Path,
    max_file_bytes: int,
    max_files: int,
    scanner: str = "all",
    max_total_bytes: int = 256 * 1024**2,
    max_depth: int = 64,
    timeout_seconds: float = 60,
) -> Inventory:
    inventory = Inventory()
    inventory.snapshot_root = destination
    destination.mkdir(mode=0o700)

    deadline = time.monotonic() + timeout_seconds
    # Count every visited entry, including links, ignored directories and devices.
    remaining_entries = max_files * 2

    def names_for(descriptor: int) -> list[str]:
        names: list[str] = []
        with os.scandir(descriptor) as entries:
            for entry in entries:
                if time.monotonic() >= deadline:
                    raise ScopeError("repository capture exceeded its time limit")
                if len(names) >= remaining_entries:
                    raise ScopeError("repository exceeds maximum traversal entry count")
                names.append(entry.name)
        return sorted(names)

    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        initial_names = names_for(directory)
    except BaseException:
        os.close(directory)
        raise
    stack = [(directory, "", iter(initial_names), 0)]
    total_bytes = 0
    directory_count = 0
    try:
        while stack:
            if time.monotonic() >= deadline:
                raise ScopeError("repository capture exceeded its time limit")
            directory, prefix, names, depth = stack[-1]
            try:
                name = next(names)
            except StopIteration:
                os.close(directory)
                stack.pop()
                continue
            remaining_entries -= 1
            if remaining_entries < 0:
                raise ScopeError("repository exceeds maximum traversal entry count")
            if name == ".git":
                # Only reachable at the root: a directory holding .git is never entered below.
                continue
            relative = f"{prefix}/{name}" if prefix else name
            descriptor = None
            try:
                metadata = os.stat(name, dir_fd=directory, follow_symlinks=False)
                if stat.S_ISLNK(metadata.st_mode):
                    inventory.skipped.append(SkippedEntry(relative, "symbolic link not followed"))
                    continue
                if stat.S_ISDIR(metadata.st_mode):
                    try:
                        descriptor = os.open(
                            name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory
                        )
                        entries = names_for(descriptor)
                    except OSError as error:
                        _gap(inventory, relative, f"unreadable directory: {type(error).__name__}")
                        continue
                    if ".git" in entries:
                        # The content is not analyzed, so the run cannot be complete: otherwise an
                        # empty file named .git would hide a whole directory from every scanner.
                        _gap(inventory, relative, NESTED_REPOSITORY)
                        continue
                    directory_count += 1
                    if depth >= max_depth or directory_count > max_files:
                        _gap(inventory, relative, "directory depth/count limit")
                        continue
                    stack.append((descriptor, relative, iter(entries), depth + 1))
                    descriptor = None
                    continue
                if not stat.S_ISREG(metadata.st_mode):
                    inventory.skipped.append(SkippedEntry(relative, "non-regular file not scanned"))
                    continue
                descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
                opened = os.fstat(descriptor)
                if not stat.S_ISREG(opened.st_mode):
                    raise OSError("file changed type")
                inventory.files_seen += 1
                inventory.bytes_seen += opened.st_size
                if inventory.files_seen > max_files:
                    raise ScopeError(f"repository exceeds maximum file count ({max_files})")
                dependency = dependency_file(name)
                if name in MANIFEST_NAMES or dependency:
                    inventory.manifests.append(relative)

                # Classify by suffix first; otherwise look at the first bytes so a script without a
                # recognized suffix is still selected. Dependency-only runs never need the content.
                head = b""
                language = source_language(name)
                if language is None and scanner != "osv-scanner":
                    head = os.read(descriptor, SOURCE_SNIFF_BYTES)
                    language = source_language(name, head)
                label = (
                    SOURCE_LANGUAGES[language][0]
                    if language
                    else LANGUAGE_SUFFIXES.get(Path(name).suffix.lower())
                )
                if label:
                    inventory.languages[label] = inventory.languages.get(label, 0) + 1

                if scanner == "inventory":
                    inventory.regular_files.append(relative)
                    if language:
                        inventory.scan_files.append(relative)
                        inventory.source_languages[relative] = language
                    continue
                selected = (
                    scanner in ("all", "gitleaks")
                    or (scanner == "semgrep" and language is not None)
                    or (scanner == "osv-scanner" and dependency)
                )
                if not selected:
                    continue
                if opened.st_size > max_file_bytes:
                    _gap(inventory, relative, f"file exceeds {max_file_bytes} byte limit")
                    continue
                if total_bytes + opened.st_size > max_total_bytes:
                    _gap(inventory, relative, "total snapshot byte limit")
                    continue
                # Bound reads even when a concurrent writer grows the file after fstat.
                chunks = [head] if head else []
                size = len(head)
                while size <= max_file_bytes and total_bytes + size <= max_total_bytes:
                    if time.monotonic() >= deadline:
                        raise ScopeError("repository capture exceeded its time limit")
                    chunk = os.read(descriptor, min(READ_CHUNK_BYTES, max_file_bytes + 1 - size))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    size += len(chunk)
                if size > max_file_bytes or total_bytes + size > max_total_bytes:
                    _gap(inventory, relative, "file grew beyond size limit")
                    continue
                data = b"".join(chunks)
                if is_lfs_pointer(data):
                    # The pointer grammar cannot carry code or credentials, but the object it names
                    # is absent. That is a coverage gap when the scanner needed that content.
                    inventory.skipped.append(SkippedEntry(relative, "Git LFS pointer; content unavailable"))
                    if language or dependency or scanner in ("all", "gitleaks"):
                        inventory.incomplete = True
                    continue
                neutral = f"f{len(inventory.snapshot_paths):06d}{neutral_suffix(name, language)}"
                target = destination / neutral
                target.write_bytes(data)
                total_bytes += size
                target.chmod(0o400)
                inventory.snapshot_paths[relative] = neutral
                inventory.regular_files.append(relative)
                if language:
                    inventory.scan_files.append(relative)
                    inventory.source_languages[relative] = language
            except OSError as error:
                _gap(inventory, relative, f"unreadable entry: {type(error).__name__}")
            finally:
                if descriptor is not None:
                    os.close(descriptor)

    finally:
        for descriptor, *_ in stack:
            os.close(descriptor)
    inventory.scan_files.sort()
    inventory.manifests.sort()
    inventory.regular_files.sort()
    inventory.skipped.sort(key=lambda entry: entry.path)
    if ".gitattributes" in inventory.regular_files or (root / ".gitattributes").is_file():
        inventory.limitations.append(
            "Git attributes are reported but filters are not executed by the analyzer."
        )
    return inventory
