from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hacker_code_konvert import __version__
from hacker_code_konvert.inventory import (
    SCANNABLE_SUFFIXES,
    ScopeError,
    build_inventory,
    resolve_repository,
    validate_output_path,
)
from hacker_code_konvert.models import ScannerResult
from hacker_code_konvert.reporting import write_artifacts
from hacker_code_konvert.schema import ValidationError, validate_findings
from hacker_code_konvert.semgrep_adapter import run_semgrep
from hacker_code_konvert.textsafety import strip_unsafe_characters

COMPLETE_STATUSES = frozenset({"completed"})
OBJECT_ID = re.compile(r"[0-9a-f]{40}")
GIT_REFERENCE = re.compile(r"refs/[A-Za-z0-9._/-]{1,200}")
MAX_GIT_FILE_BYTES = 4096
MAX_PACKED_REFS_BYTES = 1_048_576


def _positive_integer(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be greater than zero")
    return parsed


def _read_git_file(path: Path, limit: int) -> str | None:
    """Read a small regular file from an untrusted .git directory without following symlinks."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                return None
            data = stream.read(limit + 1)
    except OSError:
        return None
    if len(data) > limit:
        return None
    try:
        return data.decode("ascii")
    except UnicodeDecodeError:
        return None


def _git_revision(root: Path) -> str | None:
    """Return the checked-out commit id, treating the analyzed .git directory as untrusted.

    The value is only returned when it is a 40-character hexadecimal object id, every file is
    a bounded regular file inside .git, and no symlink is followed.
    """
    git_dir = root / ".git"
    try:
        if git_dir.is_symlink() or not git_dir.is_dir():
            return None
        git_root = git_dir.resolve(strict=True)
    except OSError:
        return None

    head = _read_git_file(git_dir / "HEAD", MAX_GIT_FILE_BYTES)
    if head is None:
        return None
    head = head.strip()
    if OBJECT_ID.fullmatch(head):
        return head
    if not head.startswith("ref: "):
        return None

    reference = head[5:].strip()
    parts = reference.split("/")
    if not GIT_REFERENCE.fullmatch(reference):
        return None
    if any(part in ("", ".", "..") or part.startswith(".") for part in parts):
        return None
    loose = git_dir / reference
    try:
        if not loose.resolve(strict=False).is_relative_to(git_root):
            return None
    except OSError:
        return None

    value = _read_git_file(loose, MAX_GIT_FILE_BYTES)
    if value is not None:
        value = value.strip()
        return value if OBJECT_ID.fullmatch(value) else None

    packed = _read_git_file(git_dir / "packed-refs", MAX_PACKED_REFS_BYTES)
    if packed is not None:
        for line in packed.splitlines():
            if line.endswith(f" {reference}"):
                candidate = line.split(" ", 1)[0]
                return candidate if OBJECT_ID.fullmatch(candidate) else None
    return None


def _printable(value: str) -> str:
    return " ".join(strip_unsafe_characters(value).split())


def _scan(args: argparse.Namespace) -> int:
    if not args.authorized:
        print("error: --authorized is required to confirm the repository is in scope", file=sys.stderr)
        return 2
    started_at = datetime.now(UTC)
    started_monotonic = time.monotonic()
    try:
        root = resolve_repository(args.repository)
        output = validate_output_path(root, args.output)
        inventory = build_inventory(
            root,
            max_file_bytes=args.max_file_bytes,
            max_files=args.max_files,
        )
    except (OSError, ScopeError) as error:
        print(f"error: {_printable(str(error))}", file=sys.stderr)
        return 2

    if args.scanner == "semgrep":
        scanner = run_semgrep(
            root,
            inventory,
            timeout_seconds=args.timeout,
            memory_bytes=args.memory_mb * 1024 * 1024,
            output_bytes=args.max_output_bytes,
            max_file_bytes=args.max_file_bytes,
        )
    else:
        scanner = ScannerResult(name="inventory", version=__version__, status="completed")

    try:
        validate_findings(scanner.findings)
    except ValidationError as error:
        scanner.status = "invalid_findings"
        scanner.errors.append(str(error))
        scanner.findings = []

    vulnerability_scan_performed = scanner.name != "inventory" and scanner.status in (
        "completed",
        "partial_coverage",
    )
    limitations = [
        "Only Python source files are supported by the initial Semgrep profile.",
        "Scanner results are candidates and have not received human validation.",
        "The analyzer does not execute target application code or dynamic tests.",
    ]
    if scanner.name == "inventory":
        limitations.append(
            "No vulnerability scanner was selected: this run is an inventory only, and the absence of "
            "findings has no security meaning."
        )
    skipped_python = [
        entry for entry in inventory.skipped if Path(entry.path).suffix.lower() in SCANNABLE_SUFFIXES
    ]
    if skipped_python:
        limitations.append(
            f"{len(skipped_python)} Python file(s) were skipped and not analyzed; "
            "see inventory.skipped in run.json for each reason."
        )
    if scanner.name == "semgrep" and scanner.version is None:
        limitations.append("The Semgrep version could not be determined; the run is harder to reproduce.")
    limitations.extend(inventory.limitations)
    complete = scanner.status in COMPLETE_STATUSES
    if not complete:
        limitations.append("The selected scanner did not complete; this run is incomplete.")

    sandboxed = bool(scanner.sandbox)
    run: dict[str, Any] = {
        "schema_version": "1.0",
        "run_id": str(uuid.uuid4()),
        "started_at": started_at.isoformat(),
        "duration_ms": int((time.monotonic() - started_monotonic) * 1000),
        "revision": _git_revision(root),
        "analysis_profile": "repository",
        "scope": {"repository": root.name, "authorized": True},
        "vulnerability_scan_performed": vulnerability_scan_performed,
        "controls": {
            "network": "disabled" if sandboxed else "not_used",
            "ai_processing": "disabled",
            "target_execution": "disabled",
            "scanner_input": "isolated staged copy" if sandboxed else "not_applicable",
            "scanner_isolation": scanner.sandbox or None,
            "raw_scanner_artifacts_retained": False,
        },
        "limits": {
            "timeout_seconds": args.timeout,
            "memory_mb": args.memory_mb,
            "max_output_bytes": args.max_output_bytes,
            "max_file_bytes": args.max_file_bytes,
            "max_files": args.max_files,
        },
        "inventory": inventory.to_dict(),
        "scanner": scanner.to_dict(),
        "limitations": limitations,
        "complete": complete,
    }
    try:
        write_artifacts(output, run, scanner.findings)
    except OSError as error:
        print(f"error: could not write report artifacts: {_printable(str(error))}", file=sys.stderr)
        return 2
    print(f"report: {output / 'report.md'}")
    if scanner.name == "inventory":
        print("status: inventory only (no vulnerability scanner was run)")
    else:
        print(f"status: {'complete' if complete else 'incomplete'}")
    if not complete:
        for error in scanner.errors:
            print(f"scanner error: {_printable(error)}", file=sys.stderr)
    return 0 if complete else 3


def _validate(args: argparse.Namespace) -> int:
    try:
        payload = json.loads(Path(args.file).read_text(encoding="utf-8"))
        findings = payload.get("findings") if isinstance(payload, dict) else payload
        if not isinstance(findings, list):
            raise ValidationError("input must be a finding list or an object containing 'findings'")
        validate_findings(findings)
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError, ValidationError) as error:
        print(f"invalid: {_printable(str(error))}", file=sys.stderr)
        return 2
    print(f"valid: {len(findings)} finding(s)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hck", description="Local defensive repository analysis")
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="inventory and analyze an authorized repository")
    scan.add_argument("repository")
    scan.add_argument("--output", required=True)
    scan.add_argument(
        "--authorized", action="store_true", help="confirm the repository is authorized and in scope"
    )
    scan.add_argument(
        "--scanner",
        choices=("semgrep", "inventory"),
        default="semgrep",
        help="semgrep (default) runs the isolated vulnerability scanner; "
        "inventory only lists files and never reports on vulnerabilities",
    )
    scan.add_argument("--timeout", type=_positive_integer, default=60)
    scan.add_argument("--memory-mb", type=_positive_integer, default=4096)
    scan.add_argument("--max-output-bytes", type=_positive_integer, default=5_000_000)
    scan.add_argument("--max-file-bytes", type=_positive_integer, default=1_000_000)
    scan.add_argument("--max-files", type=_positive_integer, default=10_000)
    scan.set_defaults(handler=_scan)

    validate = subparsers.add_parser("validate", help="validate normalized findings JSON")
    validate.add_argument("file")
    validate.set_defaults(handler=_validate)
    return parser


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.handler(args)
