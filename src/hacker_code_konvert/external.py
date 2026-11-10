"""Offline directory-only adapters. Never copy Git metadata or execute target code."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import shutil
import subprocess
import tempfile
import time
from importlib.resources import files
from pathlib import Path
from typing import Any

from hacker_code_konvert.database import database_metadata, fixed_versions, osv_severity
from hacker_code_konvert.findings import candidate, clean_text, deduplicated
from hacker_code_konvert.formats import dependency_file, neutral_suffix
from hacker_code_konvert.inventory import ScopeError, _copy_regular_file
from hacker_code_konvert.models import Inventory, ScannerResult
from hacker_code_konvert.provenance import translate_paths
from hacker_code_konvert.sandbox import (
    CommandResult,
    SandboxUnavailable,
    build_bubblewrap_command,
    run_limited,
    sandbox_metadata,
)
from hacker_code_konvert.schema import validate_findings
from hacker_code_konvert.semgrep_adapter import MAX_LISTED_PATHS, _error_excerpt, _safe_relative_path

GITLEAKS_CONFIG = "gitleaks.toml"
CANARY_NAME = "hck-canary.env"
CANARY_RULE = "hck-secret-assignment"
# OSV-Scanner exit statuses: 0 no vulnerability, 1 vulnerabilities found, 128 no package found.
OSV_RESULT_STATUSES = (0, 1)
OSV_NO_PACKAGES = 128
PINNED_REQUIREMENT = re.compile(
    r"[A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_,.-]+\])?\s*==\s*[A-Za-z0-9_.!+-]+\s*(?:;[^\\]*)?(?:\s+--hash=\S+)*\s*\\?"
)
MALFORMED = (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError, KeyError, RecursionError)


class _Run:
    """State shared by the steps of one external scanner run."""

    def __init__(self, name: str, timeout_seconds: int, memory_bytes: int, output_bytes: int) -> None:
        self.name = name
        self.memory_bytes = memory_bytes
        self.output_bytes = output_bytes
        self.timeout_seconds = timeout_seconds
        self.deadline = time.monotonic() + timeout_seconds
        self.version: str | None = None
        self.sandbox: dict[str, Any] = {}
        self.command: list[str] = []
        self.duration_ms = 0

    def result(self, status: str, **fields: Any) -> ScannerResult:
        return ScannerResult(
            name=self.name,
            version=self.version,
            status=status,
            sandbox=self.sandbox,
            command=self.command,
            duration_ms=self.duration_ms,
            **fields,
        )

    def execute(
        self,
        binary: str,
        arguments: list[str],
        stage: Path,
        rules: Path | None,
        binds: tuple[tuple[Path, str], ...],
    ) -> CommandResult:
        remaining = int(self.deadline - time.monotonic())
        if remaining <= 0:
            return CommandResult(returncode=-1, stdout=b"", stderr=b"", duration_ms=0, timed_out=True)
        wrapped = build_bubblewrap_command(
            [str(Path(binary).resolve()), *arguments],
            staged_root=stage,
            rules_file=rules,
            read_only_binds=binds,
        )
        self.sandbox = sandbox_metadata()
        result = run_limited(
            wrapped,
            timeout_seconds=remaining,
            memory_bytes=self.memory_bytes,
            output_bytes=self.output_bytes,
        )
        self.duration_ms += result.duration_ms
        return result

    def stopped(self, result: CommandResult) -> ScannerResult | None:
        """Result for a run that hit a limit, or None when the process ended on its own."""
        if result.timed_out:
            return self.result(
                "timeout", errors=[f"{self.name} exceeded the {self.timeout_seconds} second limit."]
            )
        if result.output_limited:
            return self.result(
                "output_limited", errors=[f"{self.name} exceeded the {self.output_bytes} byte output limit."]
            )
        return None


def _probe_version(name: str, binary: str) -> str | None:
    try:
        completed = subprocess.run(
            [binary, "version" if name == "gitleaks" else "--version"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=15,
            check=False,
            cwd="/",
            env={"PATH": "/usr/bin:/bin"},
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return _error_excerpt(completed.stdout) if completed.returncode == 0 else None


def _listed(paths: list[str]) -> str:
    shown = ", ".join(ascii(path) for path in paths[:MAX_LISTED_PATHS])
    remaining = len(paths) - MAX_LISTED_PATHS
    return f"{shown} (and {remaining} more)" if remaining > 0 else shown


def _input_hashes(stage: Path, mapping: dict[str, str]) -> dict[str, str]:
    return {key: hashlib.sha256((stage / key).read_bytes()).hexdigest() for key in mapping}


def _finish(findings: list[dict[str, Any]], mapping: dict[str, str]) -> list[dict[str, Any]]:
    translate_paths(findings, mapping)
    unique = deduplicated(findings)
    validate_findings(unique)
    return unique


def run_external(
    name: str,
    root: Path,
    inventory: Inventory,
    *,
    database: Path | None = None,
    timeout_seconds: int,
    memory_bytes: int,
    output_bytes: int,
    max_file_bytes: int,
    max_database_age_days: int = 30,
) -> ScannerResult:
    binary = shutil.which(name)
    if not binary:
        return ScannerResult(name=name, version=None, status="unavailable", errors=[f"{name} is required"])
    if name == "osv-scanner" and (database is None or not database.is_dir()):
        return ScannerResult(
            name=name,
            version=None,
            status="unavailable",
            errors=["An explicitly prepared offline database directory is required"],
        )
    if inventory.snapshot_root is None:
        return ScannerResult(
            name=name, version=None, status="failed", errors=["The inventory holds no captured snapshot"]
        )
    run = _Run(name, timeout_seconds, memory_bytes, output_bytes)
    run.version = _probe_version(name, binary)
    try:
        with tempfile.TemporaryDirectory(prefix="hck-external-") as temporary:
            stage = Path(temporary) / "target"
            stage.mkdir(mode=0o700)
            if name == "gitleaks":
                return _run_gitleaks(run, binary, inventory, stage, max_file_bytes)
            assert database is not None
            return _run_osv(run, binary, inventory, stage, database, max_file_bytes, max_database_age_days)
    except (OSError, ScopeError, SandboxUnavailable, ValueError) as error:
        return run.result(
            "failed", errors=[f"Isolated {name} failed: {_error_excerpt(str(error).encode())}"]
        )


def _copy_from_snapshot(inventory: Inventory, original: str, target: Path, max_file_bytes: int) -> None:
    assert inventory.snapshot_root is not None
    _copy_regular_file(inventory.snapshot_root, inventory.snapshot_paths[original], target, max_file_bytes)


def _run_gitleaks(
    run: _Run, binary: str, inventory: Inventory, stage: Path, max_file_bytes: int
) -> ScannerResult:
    selected = [path for path in inventory.regular_files if path in inventory.snapshot_paths]
    if not selected:
        return run.result(
            "partial_coverage", errors=["No supported input files selected"], files_submitted=0
        )
    mapping: dict[str, str] = {}
    for index, original in enumerate(selected):
        neutral = f"f{index:06d}{neutral_suffix(original)}"
        _copy_from_snapshot(inventory, original, stage / neutral, max_file_bytes)
        mapping[neutral] = original
    # Tool-owned inputs. The ignore file is empty, and the canary is a synthetic credential that
    # the bundled rule must report: its absence means rules or traversal did not run as expected.
    (stage / ".gitleaksignore").write_bytes(b"")
    (stage / CANARY_NAME).write_text(f'api_key = "hck_canary_{secrets.token_hex(16)}"\n', encoding="ascii")
    config = Path(str(files("hacker_code_konvert").joinpath(f"data/{GITLEAKS_CONFIG}"))).resolve()
    arguments = [
        "dir",
        "/target",
        "--redact=100",
        "--config",
        f"/rules/{GITLEAKS_CONFIG}",
        "-i",
        "/target/.gitleaksignore",
        # Inline "gitleaks:allow" comments belong to the analyzed repository and must not suppress.
        "--ignore-gitleaks-allow",
        "--report-format",
        "json",
        "--report-path",
        "-",
        "--exit-code",
        "0",
        "--no-banner",
    ]
    run.command = [run.name, *arguments]
    result = run.execute(binary, arguments, stage, config, ())
    if stopped := run.stopped(result):
        return stopped
    if result.returncode != 0:
        excerpt = _error_excerpt(result.stderr) or f"process exited with status {result.returncode}."
        return run.result("failed", errors=[f"Isolated gitleaks execution failed: {excerpt}"])
    try:
        payload = json.loads(result.stdout.decode("utf-8"))
        if not isinstance(payload, list):
            raise TypeError("report is not a list")
        canary_seen = False
        findings = []
        for item in payload:
            path = _safe_relative_path(item["File"])
            if path == CANARY_NAME:
                canary_seen = canary_seen or item["RuleID"] == CANARY_RULE
                continue
            start_line = int(item["StartLine"])
            findings.append(
                candidate(
                    rule_id=clean_text(item["RuleID"], 120),
                    path=path,
                    start_line=start_line,
                    end_line=max(start_line, int(item.get("EndLine", start_line))),
                    title="Potential credential detected; value redacted.",
                    severity="high",
                    category="secret",
                    scanner=run.name,
                    version=run.version,
                )
            )
        findings = _finish(findings, mapping)
    except MALFORMED as error:
        return run.result(
            "malformed_output", errors=[f"gitleaks returned an unexpected report: {type(error).__name__}."]
        )
    if not canary_seen:
        return run.result(
            "failed",
            errors=[
                "Gitleaks did not report the tool-owned canary credential, so its rules or its "
                "traversal of the staged files did not run as expected."
            ],
        )
    return run.result(
        "completed",
        findings=findings,
        files_submitted=len(selected),
        coverage={"canary_detected": True},
        limitations=[
            "Gitleaks does not report which files it analyzed. Every captured file was submitted and "
            "a tool-owned canary credential confirmed that the rules ran on the staged tree; vendor "
            "allowlists for file types and placeholder values still apply."
        ],
        input_hashes=_input_hashes(stage, mapping),
    )


def _requirements_state(path: Path) -> str:
    """``pinned`` when every entry has an exact version, ``empty`` without entries, else ``unpinned``."""
    entries = 0
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        value = line.split(" #", 1)[0].strip()
        if not value or value.startswith(("#", "--hash=")):
            continue
        entries += 1
        if not PINNED_REQUIREMENT.fullmatch(value):
            return "unpinned"
    return "pinned" if entries else "empty"


def _osv_arguments(lockfiles: list[str]) -> list[str]:
    arguments = [
        "scan",
        "source",
        "--offline",
        "--local-db-path",
        "/database",
        "--format",
        "json",
        "--no-resolve",
        "--no-call-analysis=all",
        # Every extracted package is listed, which is how coverage of each lockfile is proven.
        "--all-packages",
    ]
    for neutral in lockfiles:
        arguments.extend(["--lockfile", f"/target/{neutral}"])
    return arguments


def _osv_findings(run: _Run, payload: Any) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Findings and the number of packages extracted from each staged lockfile."""
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        raise TypeError("report has no results array")
    findings = []
    packages_by_source: dict[str, int] = {}
    for group in payload["results"]:
        source = _safe_relative_path(group["source"]["path"])
        packages_by_source[source] = packages_by_source.get(source, 0) + len(group["packages"])
        for entry in group["packages"]:
            package = entry["package"]
            name = clean_text(package["name"], 200)
            version = clean_text(package.get("version", "unknown"), 80)
            ecosystem = clean_text(package.get("ecosystem", "unknown"), 60)
            for vulnerability in entry.get("vulnerabilities") or []:
                advisory = clean_text(vulnerability["id"], 120)
                severity, risk = osv_severity(vulnerability)
                fixed = [clean_text(item, 80) for item in fixed_versions(vulnerability, name, ecosystem)]
                aliases = [clean_text(item, 60) for item in vulnerability.get("aliases") or []][:10]
                summary = clean_text(vulnerability.get("summary") or "No summary in the offline database.")
                finding = candidate(
                    rule_id=advisory,
                    path=source,
                    start_line=1,
                    end_line=1,
                    title=f"{advisory}: {name} {version} ({ecosystem}) is affected by a known advisory",
                    severity=severity,
                    category="dependency",
                    scanner=run.name,
                    version=run.version,
                    summary=(
                        f"{name} {version} ({ecosystem}) matches advisory {advisory}"
                        + (f" (aliases: {', '.join(aliases)})" if aliases else "")
                        + f". {summary}"
                    ),
                    remediation=(
                        f"Upgrade {name} to {' or '.join(fixed)} or later, then regenerate the lockfile."
                        if fixed
                        else f"The offline database records no fixed version of {name}; evaluate "
                        "mitigation, replacement or removal."
                    ),
                    source={
                        "package": {"name": name, "version": version, "ecosystem": ecosystem},
                        "aliases": aliases,
                        "fixed_versions": fixed,
                    },
                )
                finding["risk"] = risk
                findings.append(finding)
    return findings, packages_by_source


def _run_osv(
    run: _Run,
    binary: str,
    inventory: Inventory,
    stage: Path,
    database: Path,
    max_file_bytes: int,
    max_database_age_days: int,
) -> ScannerResult:
    declared = [path for path in inventory.manifests if dependency_file(path)]
    problems: list[str] = []
    missing = [path for path in declared if path not in inventory.snapshot_paths]
    if missing:
        problems.append(
            f"{len(missing)} dependency file(s) were not captured and not analyzed "
            f"(see inventory.skipped): {_listed(missing)}."
        )
    notes: list[str] = []
    mapping: dict[str, str] = {}
    for original in declared:
        if original in missing:
            continue
        # Preserve the lockfile basename for parser selection, each in its own neutral directory.
        requirements = Path(original).name.startswith("requirements")
        neutral = f"f{len(mapping):06d}/{'requirements.txt' if requirements else Path(original).name}"
        _copy_from_snapshot(inventory, original, stage / neutral, max_file_bytes)
        state = _requirements_state(stage / neutral) if requirements else "pinned"
        if state != "pinned":
            (stage / neutral).unlink()
            (stage / neutral).parent.rmdir()
            if state == "empty":
                notes.append(f"Requirements file {ascii(original)} declares no dependency.")
            else:
                problems.append(
                    f"Requirements file {ascii(original)} uses unpinned versions, includes or options, "
                    "which cannot be matched offline; it was not analyzed."
                )
            continue
        mapping[neutral] = original
    if not mapping:
        return run.result(
            "partial_coverage",
            errors=[*problems, "No supported dependency file could be analyzed"],
            limitations=notes,
            files_submitted=0,
        )

    metadata, warnings = database_metadata(database, max_database_age_days)
    binds = ((database.resolve(), "/database"),)
    unparsed: set[str] = set()
    run.command = [run.name, *_osv_arguments(["<staged-lockfiles>"])]
    findings: list[dict[str, Any]] = []
    packages: dict[str, int] = {}

    def analyze(lockfiles: list[str]) -> ScannerResult | str | None:
        """Run once. Returns a terminal result, a failure excerpt, or None after merging output."""
        result = run.execute(binary, _osv_arguments(lockfiles), stage, None, binds)
        if stopped := run.stopped(result):
            return stopped
        if result.returncode == OSV_NO_PACKAGES:
            return None
        if result.returncode not in OSV_RESULT_STATUSES:
            return _error_excerpt(result.stderr) or f"process exited with status {result.returncode}."
        batch, counted = _osv_findings(run, json.loads(result.stdout.decode("utf-8")))
        findings.extend(batch)
        packages.update(counted)
        return None

    try:
        outcome = analyze(list(mapping))
        if isinstance(outcome, str) and len(mapping) > 1:
            # One unreadable lockfile makes the scanner reject the whole batch. Analyze each file
            # on its own so the others still produce results and only the failing one is a gap.
            outcome = None
            for neutral, original in mapping.items():
                single = analyze([neutral])
                if isinstance(single, ScannerResult):
                    outcome = single
                    break
                if isinstance(single, str):
                    unparsed.add(original)
                    problems.append(f"osv-scanner could not analyze {ascii(original)}: {single}")
        if isinstance(outcome, ScannerResult):
            return outcome
        if isinstance(outcome, str):
            return run.result(
                "failed", errors=[*problems, f"Isolated osv-scanner execution failed: {outcome}"]
            )
        findings = _finish(findings, mapping)
    except MALFORMED as error:
        return run.result(
            "malformed_output",
            errors=[f"osv-scanner returned an unexpected report: {type(error).__name__}."],
        )

    empty = [
        original
        for neutral, original in mapping.items()
        if not packages.get(neutral) and original not in unparsed
    ]
    if empty:
        problems.append(
            f"osv-scanner extracted no package from {len(empty)} dependency file(s), so they were "
            f"not checked: {_listed(empty)}."
        )
    analyzed = sum(1 for neutral in mapping if packages.get(neutral))
    if not analyzed:
        return run.result(
            "failed",
            errors=problems,
            limitations=[*warnings, *notes],
            files_scanned=0,
            files_submitted=len(mapping),
            database=metadata,
        )
    return run.result(
        "partial_coverage" if problems else "completed",
        findings=findings,
        errors=problems,
        database=metadata,
        limitations=[*warnings, *notes],
        files_scanned=analyzed,
        files_submitted=len(mapping),
        coverage={"packages_evaluated": sum(packages.values())},
        input_hashes=_input_hashes(stage, mapping),
    )
