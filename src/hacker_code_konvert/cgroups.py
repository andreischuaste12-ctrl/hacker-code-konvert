"""Optional delegated cgroup-v2 PID limit; never changes the user's parent cgroup."""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def delegated_tasks() -> Iterator[Path | None]:
    parent = os.environ.get("HCK_CGROUP_PARENT")
    if not parent:
        yield None
        return
    root = Path(parent).resolve(strict=True)
    if not root.is_relative_to("/sys/fs/cgroup") or not (root / "cgroup.controllers").is_file():
        raise OSError("HCK_CGROUP_PARENT must be a delegated cgroup-v2 directory")
    count = int(os.environ.get("HCK_TASKS_MAX", "64"))
    if count < 4 or count > 4096:
        raise ValueError("HCK_TASKS_MAX must be between 4 and 4096")
    child = root / f"hck-{uuid.uuid4().hex}"
    child.mkdir()
    try:
        (child / "pids.max").write_text(str(count))
        yield child / "cgroup.procs"
    finally:
        child.rmdir()
