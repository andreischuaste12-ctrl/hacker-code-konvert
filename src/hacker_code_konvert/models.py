from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class SkippedEntry:
    path: str
    reason: str


@dataclass
class Inventory:
    files_seen: int = 0
    bytes_seen: int = 0
    languages: dict[str, int] = field(default_factory=dict)
    manifests: list[str] = field(default_factory=list)
    scan_files: list[str] = field(default_factory=list)
    skipped: list[SkippedEntry] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


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

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
