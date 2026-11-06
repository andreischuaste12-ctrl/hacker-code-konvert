from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from importlib.resources import files
from pathlib import Path, PurePosixPath
from typing import Any

from hacker_code_konvert.inventory import stage_scan_files
from hacker_code_konvert.models import Inventory, ScannerResult
from hacker_code_konvert.redaction import redact_text
from hacker_code_konvert.sandbox import (
    SandboxUnavailable,
    build_bubblewrap_command,
    run_limited,
)
from hacker_code_konvert.schema import validate_findings

SEVERITY_MAP = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}


def semgrep_executable() -> str | None:
    return shutil.which("semgrep")


def semgrep_version(executable: str) -> str | None:
    try:
        with tempfile.TemporaryDirectory(prefix="hck-semgrep-home-") as home:
            result = subprocess.run(
                [executable, "--version"],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=False,
                timeout=5,
                env={
                    "HOME": home,
                    "PATH": "/usr/local/bin:/usr/bin:/bin",
                    "SEMGREP_SEND_METRICS": "off",
                },
            )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.decode("utf-8", errors="replace").strip()


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

        rule_id = str(result.get("check_id", "unknown-rule"))
        if "hck." in rule_id:
            rule_id = rule_id[rule_id.index("hck.") :]
        path = _safe_relative_path(result.get("path", "unknown"))
        start_line = int(start.get("line", 1))
        end_line = int(end.get("line", start_line))
        message = redact_text(str(extra.get("message", "Semgrep candidate requires review.")))
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
    if any(ord(character) < 32 for character in raw) or re.match(r"^[A-Za-z]:/", raw):
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
    with tempfile.TemporaryDirectory(prefix="hck-stage-") as temporary:
        staged_root = Path(temporary) / "target"
        stage_scan_files(root, inventory, staged_root, max_file_bytes=max_file_bytes)
        scanner_command = [
            str(Path(executable).resolve()),
            "--config",
            "/rules/python-security.yml",
            "--json",
            "--metrics=off",
            "--disable-version-check",
            "--no-git-ignore",
            "--disable-nosem",
            "--max-target-bytes",
            str(max_file_bytes),
            "/target",
        ]
        try:
            wrapped = build_bubblewrap_command(
                scanner_command,
                staged_root=staged_root,
                rules_file=rules_file,
            )
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
                errors=[redact_text(f"Scanner isolation failed: {error}")],
            )

    stable_command = ["semgrep", "--config", "<bundled-python-rules>", "--offline", "<staged-target>"]
    if result.timed_out:
        return ScannerResult(
            name="semgrep",
            version=version,
            status="timeout",
            errors=[f"Semgrep exceeded the {timeout_seconds} second limit."],
            duration_ms=result.duration_ms,
            command=stable_command,
        )
    if result.output_limited:
        return ScannerResult(
            name="semgrep",
            version=version,
            status="output_limited",
            errors=[f"Semgrep exceeded the {output_bytes} byte output limit."],
            duration_ms=result.duration_ms,
            command=stable_command,
        )
    if result.returncode != 0:
        error_text = redact_text(result.stderr.decode("utf-8", errors="replace"))
        return ScannerResult(
            name="semgrep",
            version=version,
            status="failed",
            errors=[
                "Isolated Semgrep execution failed: "
                + (error_text[-2000:] or f"process exited with status {result.returncode}.")
            ],
            duration_ms=result.duration_ms,
            command=stable_command,
        )

    try:
        payload = json.loads(result.stdout.decode("utf-8"))
        findings = normalize_semgrep(payload, version)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as error:
        return ScannerResult(
            name="semgrep",
            version=version,
            status="malformed_output",
            errors=[f"Semgrep returned invalid JSON: {error.__class__.__name__}."],
            duration_ms=result.duration_ms,
            command=stable_command,
        )

    return ScannerResult(
        name="semgrep",
        version=version,
        status="completed",
        findings=findings,
        duration_ms=result.duration_ms,
        command=stable_command,
    )
