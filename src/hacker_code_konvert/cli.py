from __future__ import annotations

import argparse
import json
import os
import platform
import re
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from hacker_code_konvert import __version__
from hacker_code_konvert.formats import SOURCE_LANGUAGES, source_language
from hacker_code_konvert.inventory import (
    ScopeError,
    build_inventory,
    resolve_repository,
    validate_output_path,
)
from hacker_code_konvert.models import ScannerResult
from hacker_code_konvert.provenance import rules_metadata
from hacker_code_konvert.reporting import write_artifacts
from hacker_code_konvert.sandbox import PROCESS_LIMIT_ABSENT
from hacker_code_konvert.schema import REVIEWED_STATUSES, ValidationError, validate_findings
from hacker_code_konvert.scope import load_scope
from hacker_code_konvert.semgrep_adapter import run_semgrep
from hacker_code_konvert.textsafety import strip_unsafe_characters

COMPLETE_STATUSES = frozenset({"completed"})
OBJECT_ID = re.compile(r"[0-9a-f]{40}")
GIT_REFERENCE = re.compile(r"refs/[A-Za-z0-9._/-]{1,200}")
MAX_GIT_FILE_BYTES = 4096
MAX_PACKED_REFS_BYTES = 1_048_576
MAX_FINDINGS_FILE_BYTES = 64 * 1024**2
DEFAULT_MAX_FILE_BYTES = 1_000_000
# Lockfiles of real projects routinely exceed the source-file limit.
DEFAULT_MAX_LOCKFILE_BYTES = 32 * 1024**2
SUPPORTED_LANGUAGE_NAMES = frozenset(label for label, _ in SOURCE_LANGUAGES.values())


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
    if not args.authorized and not args.scope_file:
        print("error: --authorized is required to confirm the repository is in scope", file=sys.stderr)
        return 2
    if args.memory_mb is None:
        args.memory_mb = 16384 if args.scanner in ("gitleaks", "osv-scanner") else 4096
    if args.max_file_bytes is None:
        args.max_file_bytes = (
            DEFAULT_MAX_LOCKFILE_BYTES if args.scanner == "osv-scanner" else DEFAULT_MAX_FILE_BYTES
        )
    started_at = datetime.now(UTC)
    started_monotonic = time.monotonic()
    try:
        root = resolve_repository(args.repository)
        scope = load_scope(Path(args.scope_file), root) if args.scope_file else None
        output = validate_output_path(root, args.output)
        inventory = build_inventory(
            root,
            max_file_bytes=args.max_file_bytes,
            max_files=args.max_files,
            snapshot=getattr(args, "snapshot_root", None),
            scanner=args.scanner,
            max_total_bytes=args.max_total_bytes,
            max_depth=args.max_depth,
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
    elif args.scanner in ("gitleaks", "osv-scanner"):
        from hacker_code_konvert.external import run_external

        scanner = run_external(
            args.scanner,
            root,
            inventory,
            database=Path(args.offline_database) if args.offline_database else None,
            timeout_seconds=args.timeout,
            memory_bytes=args.memory_mb * 1024 * 1024,
            output_bytes=args.max_output_bytes,
            max_file_bytes=args.max_file_bytes,
            max_database_age_days=args.max_database_age_days,
        )
    else:
        scanner = ScannerResult(name="inventory", version=__version__, status="completed")

    if inventory.incomplete and scanner.status == "completed":
        scanner.status = "partial_coverage"
        scanner.errors.append("Inventory/capture limits or unreadable entries left coverage gaps.")
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
        "The bundled profile covers selected Python and WordPress/PHP patterns, not all vulnerabilities.",
        "Scanner results are candidates and have not received human validation.",
        "The analyzer does not execute target application code or dynamic tests.",
    ]
    if scanner.name == "inventory":
        limitations.append(
            "No vulnerability scanner was selected: this run is an inventory only, and the absence of "
            "findings has no security meaning."
        )
    skipped_sources = [entry for entry in inventory.skipped if source_language(entry.path)]
    if skipped_sources:
        limitations.append(
            f"{len(skipped_sources)} supported source file(s) were skipped and not analyzed; "
            "see inventory.skipped in run.json for each reason."
        )
    if scanner.name == "semgrep":
        limitations.append(
            "Source files are selected by suffix, by an interpreter line, or by a PHP opening tag at "
            "the start of the file. Code kept in any other file is not analyzed."
        )
        unsupported = sorted(
            (label, count)
            for label, count in inventory.languages.items()
            if label not in SUPPORTED_LANGUAGE_NAMES
        )
        if unsupported:
            listed = ", ".join(f"{label} ({count})" for label, count in unsupported)
            limitations.append(
                f"Source files in languages without bundled rules were not analyzed: {listed}."
            )
    if scanner.sandbox.get("process_limit") == PROCESS_LIMIT_ABSENT:
        limitations.append(
            "No process-count limit was enforced inside the sandbox; a scanner could exhaust the "
            "process table for the duration of the timeout."
        )
    if scanner.sandbox.get("seccomp_unresolved_syscalls"):
        limitations.append(
            "The installed libseccomp cannot express every denied system call: "
            + ", ".join(scanner.sandbox["seccomp_unresolved_syscalls"])
            + "."
        )
    if scanner.name == "semgrep" and scanner.version is None:
        limitations.append("The Semgrep version could not be determined; the run is harder to reproduce.")
    if os.geteuid() == 0:
        limitations.append("Analyzer is running as root; host container security remains relevant.")
    limitations.extend(scanner.limitations)
    limitations.extend(inventory.limitations)
    complete = scanner.status in COMPLETE_STATUSES
    if not complete:
        limitations.append("The selected scanner did not complete; this run is incomplete.")

    sandboxed = bool(scanner.sandbox)
    run: dict[str, Any] = {
        "schema_version": "1.0",
        "rules_applied": rules_metadata(scanner.name) if scanner.name != "inventory" else None,
        "runtime": {"python": platform.python_version()},
        "authorization": scope,
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
            "max_total_bytes": args.max_total_bytes,
            "max_depth": args.max_depth,
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
        for message in scanner.errors:
            print(f"scanner error: {_printable(message)}", file=sys.stderr)
    return 0 if complete else 3


def _load_reviewed_findings(args: argparse.Namespace) -> list[dict[str, Any]]:
    """Read the findings document once, validate it, and verify the review signature over those bytes.

    Using one read for the schema check, the signature check and every later step removes the
    window in which the file could be replaced after it was verified.
    """
    with Path(args.file).open("rb") as stream:
        data = stream.read(MAX_FINDINGS_FILE_BYTES + 1)
    if len(data) > MAX_FINDINGS_FILE_BYTES:
        raise ValidationError("findings document exceeds the size limit")
    payload = json.loads(data.decode("utf-8"))
    findings = payload.get("findings") if isinstance(payload, dict) else payload
    if not isinstance(findings, list):
        raise ValidationError("input must be a finding list or an object containing 'findings'")
    validate_findings(findings)
    if any(finding["status"] in REVIEWED_STATUSES for finding in findings):
        from hacker_code_konvert.review import verify_review

        if not args.signature or not args.allowed_signers or not args.reviewer:
            raise ValidationError(
                "Findings marked validated, false_positive or accepted_risk record a human decision "
                "and require a signature, allowed signers, and reviewer"
            )
        verify_review(data, Path(args.signature), Path(args.allowed_signers), args.reviewer)
    return cast(list[dict[str, Any]], findings)


_INVALID_INPUT = (
    OSError,
    UnicodeError,
    json.JSONDecodeError,
    RecursionError,
    ValueError,
    subprocess.SubprocessError,
)


def _validate(args: argparse.Namespace) -> int:
    try:
        findings = _load_reviewed_findings(args)
    except _INVALID_INPUT as error:
        print(f"invalid: {_printable(str(error))}", file=sys.stderr)
        return 2
    print(f"valid: {len(findings)} finding(s)")
    return 0


def _draft(args: argparse.Namespace) -> int:
    from hacker_code_konvert.redaction import redact
    from hacker_code_konvert.reporting import _atomic_write, _markdown_text

    try:
        findings = _load_reviewed_findings(args)
    except _INVALID_INPUT as error:
        print(f"invalid: {_printable(str(error))}", file=sys.stderr)
        return 2
    validated = [finding for finding in findings if finding["status"] == "validated"]
    if not validated:
        print("error: no validated findings available", file=sys.stderr)
        return 2
    lines = ["# Private vulnerability disclosure draft", "", "Draft only; no report has been sent.", ""]
    for finding in redact(validated):
        lines.extend(
            [
                f"## {_markdown_text(finding['title'])}",
                f"Impact: {_markdown_text(finding['impact'])}",
                f"Evidence: {_markdown_text(finding['evidence'].get('summary', ''))}",
                f"Remediation: {_markdown_text(finding['remediation'].get('summary', ''))}",
                "",
            ]
        )
    output = Path(args.output)
    if output.exists():
        print("error: disclosure draft output must be new", file=sys.stderr)
        return 2
    _atomic_write(output, "\n".join(lines))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hck", description="Local defensive repository analysis")
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="inventory and analyze an authorized repository")
    scan.add_argument("repository")
    scan.add_argument("--output", required=True)
    scan.add_argument("--scope-file", help="JSON authorization record (JSON is a YAML subset)")
    scan.add_argument(
        "--authorized", action="store_true", help="confirm the repository is authorized and in scope"
    )
    scan.add_argument(
        "--scanner",
        choices=("semgrep", "inventory", "gitleaks", "osv-scanner"),
        default="semgrep",
        help="semgrep (default) runs the isolated vulnerability scanner; "
        "inventory only lists files and never reports on vulnerabilities",
    )
    scan.add_argument("--max-database-age-days", type=_positive_integer, default=30)
    scan.add_argument("--offline-database", help="Explicit pre-downloaded OSV database directory")
    scan.add_argument("--timeout", type=_positive_integer, default=60)
    scan.add_argument("--memory-mb", type=_positive_integer, default=None)
    scan.add_argument("--max-output-bytes", type=_positive_integer, default=5_000_000)
    scan.add_argument(
        "--max-file-bytes",
        type=_positive_integer,
        default=None,
        help="per-file limit; defaults to 1 MB, or 32 MiB for dependency files with osv-scanner",
    )
    scan.add_argument("--max-total-bytes", type=_positive_integer, default=256 * 1024**2)
    scan.add_argument("--max-depth", type=_positive_integer, default=64)
    scan.add_argument("--max-files", type=_positive_integer, default=10_000)
    scan.set_defaults(handler=_scan)

    validate = subparsers.add_parser("validate", help="validate normalized findings JSON")
    validate.add_argument("file")
    validate.add_argument("--signature")
    validate.add_argument("--allowed-signers")
    validate.add_argument("--reviewer")
    validate.set_defaults(handler=_validate)

    report = subparsers.add_parser("report", help="prepare a private disclosure draft")
    reports = report.add_subparsers(dest="report_command", required=True)
    draft = reports.add_parser("draft")
    draft.add_argument("file")
    draft.add_argument("--output", required=True)
    draft.add_argument("--signature", required=True)
    draft.add_argument("--allowed-signers", required=True)
    draft.add_argument("--reviewer", required=True)
    draft.set_defaults(handler=_draft)
    return parser


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)
    parser = build_parser()
    args = parser.parse_args(argv)
    handler = cast(Callable[[argparse.Namespace], int], args.handler)
    if args.command == "scan":
        with tempfile.TemporaryDirectory(prefix="hck-capture-") as directory:
            args.snapshot_root = Path(directory) / "files"
            return handler(args)
    return handler(args)
