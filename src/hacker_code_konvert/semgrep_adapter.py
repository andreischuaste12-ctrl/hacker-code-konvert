from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
from collections import Counter
from importlib.resources import files
from pathlib import Path, PurePosixPath
from typing import Any

from hacker_code_konvert.inventory import ScopeError, stage_scan_files
from hacker_code_konvert.models import Inventory, ScannerResult
from hacker_code_konvert.redaction import redact_text
from hacker_code_konvert.sandbox import (
    SandboxUnavailable,
    build_bubblewrap_command,
    run_limited,
    sandbox_metadata,
)
from hacker_code_konvert.schema import validate_findings
from hacker_code_konvert.textsafety import has_unsafe_characters, strip_unsafe_characters

SEVERITY_MAP = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}

SANDBOX_RULES_PATH = "/rules/python-security.yml"
SANDBOX_TARGET_PATH = "/target"
STDERR_WINDOW_BYTES = 8192
STDERR_EXCERPT_CHARS = 1000
MAX_LISTED_PATHS = 5


def semgrep_executable() -> str | None:
    return shutil.which("semgrep")


def semgrep_version(executable: str) -> str | None:
    # Runs outside the sandbox, so it must not reach the network: the version check is disabled both
    # by flag and by environment, otherwise the command can hang or contact the vendor.
    try:
        with tempfile.TemporaryDirectory(prefix="hck-semgrep-home-") as home:
            result = subprocess.run(
                [executable, "--disable-version-check", "--version"],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=False,
                timeout=15,
                cwd=home,
                env={
                    "HOME": home,
                    "PATH": "/usr/local/bin:/usr/bin:/bin",
                    "SEMGREP_SEND_METRICS": "off",
                    "SEMGREP_ENABLE_VERSION_CHECK": "0",
                },
            )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.decode("utf-8", errors="replace").strip() or None


def scanner_arguments(max_file_bytes: int) -> list[str]:
    """Arguments passed to Semgrep inside the sandbox. This is the single source of truth."""
    return [
        "--config",
        SANDBOX_RULES_PATH,
        "--json",
        "--metrics=off",
        "--disable-version-check",
        "--no-git-ignore",
        "--disable-nosem",
        "--jobs",
        "1",
        "--max-target-bytes",
        str(max_file_bytes),
        SANDBOX_TARGET_PATH,
    ]


def recorded_command(arguments: list[str]) -> list[str]:
    """The executed command with environment-specific paths replaced by stable placeholders."""
    placeholders = {SANDBOX_RULES_PATH: "<bundled-python-rules>", SANDBOX_TARGET_PATH: "<staged-target>"}
    return ["semgrep", *(placeholders.get(argument, argument) for argument in arguments)]


def _gate_state() -> dict[str, str]:
    return {
        "authorization_scope": "pass",
        "coherent_claim": "pass",
        "code_applicability": "pass",
        "attacker_control_reachability": "unresolved",
        "vulnerability_mechanism": "unresolved",
        "realistic_impact": "unresolved",
        "environmental_controls": "unresolved",
        "safe_evidence": "pass",
        "human_review": "pending",
    }


def normalize_semgrep(payload: dict[str, Any], version: str | None) -> list[dict[str, Any]]:
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        raise TypeError("Semgrep output must contain a results array")

    findings: list[dict[str, Any]] = []
    for result in payload["results"]:
        if not isinstance(result, dict):
            raise TypeError("Each Semgrep result must be an object")
        start = result.get("start", {})
        end = result.get("end", {})
        extra = result.get("extra", {})
        if not isinstance(start, dict) or not isinstance(end, dict) or not isinstance(extra, dict):
            raise TypeError("Semgrep result fields have invalid types")

        rule_id = strip_unsafe_characters(str(result.get("check_id", "unknown-rule")))
        if "hck." in rule_id:
            rule_id = rule_id[rule_id.index("hck.") :]
        path = _safe_relative_path(result.get("path", "unknown"))
        start_line = int(start.get("line", 1))
        end_line = int(end.get("line", start_line))
        raw_message = str(extra.get("message", "Semgrep candidate requires review."))
        message = redact_text(strip_unsafe_characters(raw_message))
        fingerprint_source = f"{rule_id}\0{path}\0{start_line}\0{end_line}"
        fingerprint = hashlib.sha256(fingerprint_source.encode("utf-8")).hexdigest()
        metadata = extra.get("metadata", {}) if isinstance(extra.get("metadata", {}), dict) else {}
        taxonomy: dict[str, Any] = {}
        if metadata.get("cwe"):
            taxonomy["cwe"] = metadata["cwe"]
        if metadata.get("owasp"):
            taxonomy["owasp"] = metadata["owasp"]

        finding: dict[str, Any] = {
            "id": f"HCK-{fingerprint[:12].upper()}",
            "fingerprint": f"sha256:{fingerprint}",
            "title": message,
            "status": "candidate",
            "analysis_profile": "repository",
            "severity": SEVERITY_MAP.get(str(extra.get("severity", "INFO")).upper(), "informational"),
            "confidence": "medium",
            "confidence_rationale": (
                "The bundled rule matched, but exploitability and reachability are unresolved."
            ),
            "category": "sast",
            "location": {"path": path, "start_line": start_line, "end_line": end_line},
            "threat_model": {
                "attacker": "unconfirmed",
                "required_access": "unconfirmed",
                "conditions": ["Requires contextual source-to-sink review"],
            },
            "evidence": {
                "summary": message,
                "source_to_sink": [],
                "redacted": True,
            },
            "validation": _gate_state(),
            "impact": "Potential security impact requires human validation.",
            "reproduction": {
                "performed": False,
                "reason": "The static MVP does not execute target code; human review is required.",
                "steps": [],
            },
            "remediation": {
                "summary": "Review the affected data flow and apply the framework-specific safe alternative.",
                "verification": "Repeat the local rule and relevant project tests after an approved fix.",
            },
            "sources": [{"type": "scanner", "name": "semgrep", "version": version, "rule_id": rule_id}],
            "review": {
                "human_reviewed": False,
                "reviewer": None,
                "reviewed_at": None,
                "rationale": "Scanner output is a candidate and has not passed contextual review.",
            },
            "disclosure": {"status": "not_applicable", "approved_by": None, "updated_at": None},
        }
        if taxonomy:
            finding["taxonomy"] = taxonomy
        findings.append(finding)

    deduplicated = {finding["fingerprint"]: finding for finding in findings}
    normalized = [deduplicated[key] for key in sorted(deduplicated)]
    validate_findings(normalized)
    return normalized


def _safe_relative_path(value: Any) -> str:
    raw = str(value).replace("\\", "/")
    if has_unsafe_characters(raw) or (len(raw) > 1 and raw[1] == ":" and raw[0].isalpha()):
        return "unknown"
    path = PurePosixPath(raw)
    parts = path.parts
    if parts[:2] == ("/", "target"):
        parts = parts[2:]
    elif parts[:1] == ("target",):
        parts = parts[1:]
    if path.is_absolute() and parts == path.parts:
        return "unknown"
    if not parts or ".." in parts or "." in parts:
        return "unknown"
    return PurePosixPath(*parts).as_posix()


def _listed(paths: list[str]) -> str:
    shown = ", ".join(paths[:MAX_LISTED_PATHS])
    remaining = len(paths) - MAX_LISTED_PATHS
    return f"{shown} (and {remaining} more)" if remaining > 0 else shown


def _error_type(error: dict[str, Any]) -> str:
    kind = error.get("type")
    if isinstance(kind, list) and kind and isinstance(kind[0], str):
        kind = kind[0]
    return strip_unsafe_characters(str(kind or "UnknownError"))[:60]


def coverage_problems(payload: dict[str, Any], expected_files: list[str]) -> list[str]:
    """Compare what Semgrep reports having analyzed with what the inventory selected.

    An empty list proves that every selected file was analyzed without scanner errors. Anything
    else is a coverage gap that must make the run incomplete: absence of findings is only
    meaningful for code the scanner actually analyzed.
    """
    problems: list[str] = []
    paths = payload.get("paths") if isinstance(payload, dict) else None
    scanned_raw = paths.get("scanned") if isinstance(paths, dict) else None
    if not isinstance(scanned_raw, list):
        return ["Semgrep did not report which files it analyzed, so coverage could not be verified."]

    scanned = {_safe_relative_path(item) for item in scanned_raw if isinstance(item, str)}
    missing = sorted(set(expected_files) - scanned)
    if missing:
        problems.append(
            f"Semgrep did not analyze {len(missing)} of {len(expected_files)} "
            f"selected file(s): {_listed(missing)}."
        )

    skipped = paths.get("skipped") if isinstance(paths, dict) else None
    if isinstance(skipped, list) and skipped:
        reasons = Counter(
            strip_unsafe_characters(str(item.get("reason", "unknown")))[:60]
            for item in skipped
            if isinstance(item, dict)
        )
        summary = ", ".join(f"{reason} ({count})" for reason, count in sorted(reasons.items())) or "unknown"
        problems.append(f"Semgrep reported {len(skipped)} skipped file(s): {summary}.")

    errors = payload.get("errors")
    if isinstance(errors, list) and errors:
        entries = [item for item in errors if isinstance(item, dict)]
        types = Counter(_error_type(item) for item in entries)
        affected = sorted(
            {_safe_relative_path(item["path"]) for item in entries if isinstance(item.get("path"), str)}
        )
        type_summary = ", ".join(f"{name} ({count})" for name, count in sorted(types.items())) or "unknown"
        detail = f"; affected files: {_listed(affected)}" if affected else ""
        problems.append(f"Semgrep reported {len(errors)} error(s) during analysis: {type_summary}{detail}.")
    return problems


def _error_excerpt(stderr: bytes) -> str:
    """A short, redacted, single-line excerpt of untrusted scanner stderr."""
    window = stderr[-STDERR_WINDOW_BYTES:].decode("utf-8", errors="replace")
    if len(stderr) > STDERR_WINDOW_BYTES and "\n" in window:
        window = window.split("\n", 1)[1]  # drop a line that may have been cut mid-secret
    cleaned = " ".join(strip_unsafe_characters(redact_text(window)).split())
    return cleaned[-STDERR_EXCERPT_CHARS:]


def run_semgrep(
    root: Path,
    inventory: Inventory,
    *,
    timeout_seconds: int,
    memory_bytes: int,
    output_bytes: int,
    max_file_bytes: int,
) -> ScannerResult:
    executable = semgrep_executable()
    if not executable:
        return ScannerResult(
            name="semgrep",
            version=None,
            status="unavailable",
            errors=["Semgrep is not installed. Install the 'semgrep' optional dependency."],
        )

    version = semgrep_version(executable)
    rules_file = Path(str(files("hacker_code_konvert").joinpath("data/python-security.yml"))).resolve()
    arguments = scanner_arguments(max_file_bytes)
    stable_command = recorded_command(arguments)
    with tempfile.TemporaryDirectory(prefix="hck-stage-") as temporary:
        staged_root = Path(temporary) / "target"
        try:
            stage_scan_files(root, inventory, staged_root, max_file_bytes=max_file_bytes)
        except (OSError, ScopeError) as error:
            return ScannerResult(
                name="semgrep",
                version=version,
                status="failed",
                errors=[_error_excerpt(f"Staging the selected files failed: {error}".encode())],
            )
        try:
            wrapped = build_bubblewrap_command(
                [str(Path(executable).resolve()), *arguments],
                staged_root=staged_root,
                rules_file=rules_file,
            )
            isolation = sandbox_metadata()
            result = run_limited(
                wrapped,
                timeout_seconds=timeout_seconds,
                memory_bytes=memory_bytes,
                output_bytes=output_bytes,
            )
        except (OSError, SandboxUnavailable, ValueError) as error:
            return ScannerResult(
                name="semgrep",
                version=version,
                status="failed",
                errors=[_error_excerpt(f"Scanner isolation failed: {error}".encode())],
            )

    if result.timed_out:
        return ScannerResult(
            name="semgrep",
            version=version,
            status="timeout",
            errors=[f"Semgrep exceeded the {timeout_seconds} second limit."],
            duration_ms=result.duration_ms,
            command=stable_command,
            sandbox=isolation,
        )
    if result.output_limited:
        return ScannerResult(
            name="semgrep",
            version=version,
            status="output_limited",
            errors=[f"Semgrep exceeded the {output_bytes} byte output limit."],
            duration_ms=result.duration_ms,
            command=stable_command,
            sandbox=isolation,
        )
    if result.returncode != 0:
        excerpt = _error_excerpt(result.stderr)
        return ScannerResult(
            name="semgrep",
            version=version,
            status="failed",
            errors=[
                "Isolated Semgrep execution failed: "
                + (excerpt or f"process exited with status {result.returncode}.")
            ],
            duration_ms=result.duration_ms,
            command=stable_command,
            sandbox=isolation,
        )

    try:
        payload = json.loads(result.stdout.decode("utf-8"))
        findings = normalize_semgrep(payload, version)
        problems = coverage_problems(payload, inventory.scan_files)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError, RecursionError) as error:
        return ScannerResult(
            name="semgrep",
            version=version,
            status="malformed_output",
            errors=[f"Semgrep returned invalid JSON: {error.__class__.__name__}."],
            duration_ms=result.duration_ms,
            command=stable_command,
            sandbox=isolation,
        )

    paths = payload.get("paths")
    scanned = paths.get("scanned") if isinstance(paths, dict) else None
    return ScannerResult(
        name="semgrep",
        version=version,
        status="partial_coverage" if problems else "completed",
        findings=findings,
        errors=problems,
        duration_ms=result.duration_ms,
        command=stable_command,
        sandbox=isolation,
        files_scanned=len(scanned) if isinstance(scanned, list) else None,
    )
