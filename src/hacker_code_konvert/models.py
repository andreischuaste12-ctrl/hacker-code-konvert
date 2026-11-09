from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class SkippedEntry:
    path: str
    reason: str


@dataclass
class Inventory:
    incomplete: bool = False
    snapshot_root: Path | None = None
    snapshot_paths: dict[str, str] = field(default_factory=dict)
    regular_files: list[str] = field(default_factory=list)
    files_seen: int = 0
    bytes_seen: int = 0
    languages: dict[str, int] = field(default_factory=dict)
    manifests: list[str] = field(default_factory=list)
    scan_files: list[str] = field(default_factory=list)
    skipped: list[SkippedEntry] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result.pop("snapshot_root", None)
        result.pop("snapshot_paths", None)
        return result


@dataclass
class ScannerResult:
    name: str
    version: str | None
    status: str
    findings: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_ms: int = 0
    command: list[str] = field(default_factory=list)
    # Facts about the isolation that was actually applied; empty when no sandbox was started.
    sandbox: dict[str, Any] = field(default_factory=dict)
    # Files the scanner reported as analyzed, used to prove coverage; None when not applicable.
    files_scanned: int | None = None
    input_hashes: dict[str, str] = field(default_factory=dict)
    database: dict[str, Any] = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
