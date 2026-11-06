from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hacker_code_konvert import __version__
from hacker_code_konvert.inventory import (
    ScopeError,
    build_inventory,
    resolve_repository,
    validate_output_path,
)
from hacker_code_konvert.models import ScannerResult
from hacker_code_konvert.reporting import write_artifacts
from hacker_code_konvert.schema import ValidationError, validate_findings
from hacker_code_konvert.semgrep_adapter import run_semgrep


def _positive_integer(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be greater than zero")
    return parsed


def _git_revision(root: Path) -> str | None:
    git_dir = root / ".git"
    if not git_dir.is_dir():
        return None
    try:
        head = (git_dir / "HEAD").read_text(encoding="utf-8").strip()
        if not head.startswith("ref: "):
            return head if len(head) == 40 else None
        reference = head[5:]
        loose = git_dir / reference
        if loose.is_file():
            value = loose.read_text(encoding="utf-8").strip()
            return value if len(value) == 40 else None
        packed = git_dir / "packed-refs"
        if packed.is_file():
            for line in packed.read_text(encoding="utf-8").splitlines():
                if line.endswith(f" {reference}"):
                    value = line.split(" ", 1)[0]
                    return value if len(value) == 40 else None
    except (OSError, UnicodeError):
        return None
    return None


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
        print(f"error: {error}", file=sys.stderr)
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

    limitations = [
        "Only Python source files are supported by the initial Semgrep profile.",
        "Scanner results are candidates and have not received human validation.",
        "The analyzer does not execute target application code or dynamic tests.",
    ]
    limitations.extend(inventory.limitations)
    if scanner.status != "completed":
        limitations.append("The selected scanner did not complete; this run is incomplete.")

    run: dict[str, Any] = {
        "schema_version": "1.0",
        "run_id": str(uuid.uuid4()),
        "started_at": started_at.isoformat(),
        "duration_ms": int((time.monotonic() - started_monotonic) * 1000),
        "revision": _git_revision(root),
        "analysis_profile": "repository",
        "scope": {"repository": root.name, "authorized": True},
        "controls": {
            "network": "disabled",
            "ai_processing": "disabled",
            "target_execution": "disabled",
            "scanner_input": "isolated staged copy",
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
        "complete": scanner.status == "completed",
    }
    write_artifacts(output, run, scanner.findings)
    print(f"report: {output / 'report.md'}")
    print(f"status: {'complete' if run['complete'] else 'incomplete'}")
    if not run["complete"]:
        for error in scanner.errors:
            print(f"scanner error: {error}", file=sys.stderr)
    return 0 if run["complete"] else 3


def _validate(args: argparse.Namespace) -> int:
    try:
        payload = json.loads(Path(args.file).read_text(encoding="utf-8"))
        findings = payload.get("findings") if isinstance(payload, dict) else payload
        if not isinstance(findings, list):
            raise ValidationError("input must be a finding list or an object containing 'findings'")
        validate_findings(findings)
    except (OSError, UnicodeError, json.JSONDecodeError, ValidationError) as error:
        print(f"invalid: {error}", file=sys.stderr)
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
    scan.add_argument("--scanner", choices=("inventory", "semgrep"), default="inventory")
    scan.add_argument("--timeout", type=_positive_integer, default=60)
    scan.add_argument("--memory-mb", type=_positive_integer, default=1024)
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
