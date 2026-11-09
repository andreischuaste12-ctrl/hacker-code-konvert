"""One-pass descriptor-relative inventory and capture of selected regular files."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from hacker_code_konvert.inventory import (
    LANGUAGE_SUFFIXES,
    LFS_HEADER,
    MANIFEST_NAMES,
    SCANNABLE_SUFFIXES,
    ScopeError,
)
from hacker_code_konvert.models import Inventory, SkippedEntry


def capture(root: Path, destination: Path, max_file_bytes: int, max_files: int) -> Inventory:
    inventory = Inventory()
    inventory.snapshot_root = destination
    destination.mkdir(mode=0o700)

    def walk(directory: int, prefix: str) -> None:
        with os.scandir(directory) as entries:
            names = sorted(entry.name for entry in entries)
        for name in names:
            if name == ".git":
                continue
            relative = f"{prefix}/{name}" if prefix else name
            descriptor = None
            try:
                metadata = os.stat(name, dir_fd=directory, follow_symlinks=False)
                if stat.S_ISLNK(metadata.st_mode):
                    inventory.skipped.append(SkippedEntry(relative, "symbolic link not followed"))
                    continue
                if stat.S_ISDIR(metadata.st_mode):
                    descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                    try:
                        os.stat(".git", dir_fd=descriptor, follow_symlinks=False)
                    except FileNotFoundError:
                        walk(descriptor, relative)
                    else:
                        inventory.skipped.append(SkippedEntry(relative, "nested repository not traversed"))
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
                    raise ScopeError("repository exceeds maximum file count")
                if name in MANIFEST_NAMES:
                    inventory.manifests.append(relative)
                language = LANGUAGE_SUFFIXES.get(Path(name).suffix.lower())
                if language:
                    inventory.languages[language] = inventory.languages.get(language, 0) + 1
                if opened.st_size > max_file_bytes:
                    inventory.skipped.append(SkippedEntry(relative, "file exceeds size limit"))
                    continue
                # Bound reads even when a concurrent writer grows the file after fstat.
                chunks = []
                size = 0
                while chunk := os.read(descriptor, min(65536, max_file_bytes + 1 - size)):
                    chunks.append(chunk)
                    size += len(chunk)
                    if size > max_file_bytes:
                        break
                data = b"".join(chunks)
                if size > max_file_bytes:
                    inventory.skipped.append(SkippedEntry(relative, "file grew beyond size limit"))
                    continue
                if size <= 1024 and data.startswith(LFS_HEADER):
                    inventory.skipped.append(SkippedEntry(relative, "Git LFS pointer; content unavailable"))
                    continue
                neutral = f"f{len(inventory.snapshot_paths):06d}{Path(name).suffix.lower()}"
                target = destination / neutral
                target.write_bytes(data)
                target.chmod(0o400)
                inventory.snapshot_paths[relative] = neutral
                inventory.regular_files.append(relative)
                if Path(name).suffix.lower() in SCANNABLE_SUFFIXES:
                    inventory.scan_files.append(relative)
            except OSError as error:
                inventory.skipped.append(SkippedEntry(relative, f"unreadable entry: {type(error).__name__}"))
            finally:
                if descriptor is not None:
                    os.close(descriptor)

    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        walk(directory, "")
    finally:
        os.close(directory)
    inventory.scan_files.sort()
    inventory.manifests.sort()
    inventory.regular_files.sort()
    inventory.skipped.sort(key=lambda entry: entry.path)
    return inventory
