"""Offline directory-only adapters. Never copy Git metadata or execute target code."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from importlib.resources import files
from pathlib import Path
from typing import Any

from hacker_code_konvert.database import database_metadata, osv_severity
from hacker_code_konvert.formats import dependency_file
from hacker_code_konvert.inventory import _copy_regular_file
from hacker_code_konvert.models import Inventory, ScannerResult
from hacker_code_konvert.provenance import translate_paths
from hacker_code_konvert.sandbox import build_bubblewrap_command, run_limited, sandbox_metadata
from hacker_code_konvert.semgrep_adapter import _error_excerpt, normalize_semgrep


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
    selected = (
        inventory.regular_files
        if name == "gitleaks"
        else [path for path in inventory.manifests if dependency_file(path)]
    )
    if not selected:
        return ScannerResult(
            name=name, version=None, status="partial_coverage", errors=["No supported input files selected"]
        )
    try:
        version_result = subprocess.run(
            [binary, "version" if name == "gitleaks" else "--version"],
            capture_output=True,
            timeout=15,
            check=False,
            cwd="/",
            env={"PATH": "/usr/bin:/bin"},
        )
        version = _error_excerpt(version_result.stdout) if version_result.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        version = None
    try:
        metadata, warnings = (
            database_metadata(database, max_database_age_days)
            if name == "osv-scanner" and database
            else ({}, [])
        )
        severities = {}
        with tempfile.TemporaryDirectory(prefix="hck-external-") as temporary:
            stage = Path(temporary) / "target"
            stage.mkdir()
            mapping = {}
            for index, original in enumerate(selected):
                # Preserve lockfile basename for parser selection, but isolate each in neutral directory.
                basename = (
                    "requirements.txt"
                    if Path(original).name.startswith("requirements")
                    else Path(original).name
                )
                neutral = (
                    f"f{index:06d}/{basename}"
                    if name == "osv-scanner"
                    else f"f{index:06d}{Path(original).suffix or '.txt'}"
                )
                source_root = inventory.snapshot_root or root
                source_relative = inventory.snapshot_paths[original] if inventory.snapshot_root else original
                _copy_regular_file(source_root, source_relative, stage / neutral, max_file_bytes)
                if name == "osv-scanner" and basename == "requirements.txt":
                    for line in (stage / neutral).read_text().splitlines():
                        value = line.split("#", 1)[0].strip()
                        if (
                            value
                            and not value.startswith("--hash=")
                            and not re.fullmatch(
                                r"[A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_,.-]+\])?==[A-Za-z0-9_.!+-]+(?:\s+.*)?",
                                value,
                            )
                        ):
                            raise ValueError(
                                "Requirements input must use fixed == versions; "
                                "includes/options are unsupported"
                            )
                mapping[neutral] = original
            (stage / ".gitleaksignore").write_bytes(b"")
            config = Path(str(files("hacker_code_konvert").joinpath("data/gitleaks.toml")))
            if name == "gitleaks":
                arguments = [
                    "dir",
                    "/target",
                    "--redact=100",
                    "--config",
                    "/rules/python-security.yml",
                    "-i",
                    "/target/.gitleaksignore",
                    "--report-format",
                    "json",
                    "--report-path",
                    "-",
                    "--exit-code",
                    "0",
                    "--no-banner",
                ]
            else:
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
                ]
                for neutral in mapping:
                    arguments.extend(["--lockfile", f"/target/{neutral}"])
            wrapped = build_bubblewrap_command(
                [str(Path(binary).resolve()), *arguments], staged_root=stage, rules_file=config
            )
            if database is not None and name == "osv-scanner":
                index = wrapped.index("--")
                wrapped[index:index] = ["--ro-bind", str(database.resolve()), "/database"]
            result = run_limited(
                wrapped, timeout_seconds=timeout_seconds, memory_bytes=memory_bytes, output_bytes=output_bytes
            )
            if result.timed_out or result.output_limited or result.returncode not in (0, 1):
                raise ValueError(
                    "Scanner failed, timed out or exceeded output limit: " + _error_excerpt(result.stderr)
                )
            payload = json.loads(result.stdout)
            matches: list[dict[str, Any]] = []
            if name == "gitleaks":
                if result.returncode != 0 or not isinstance(payload, list):
                    raise ValueError("Unexpected Gitleaks output")
                for item in payload:
                    matches.append(
                        {
                            "check_id": str(item["RuleID"]),
                            "path": item["File"],
                            "start": {"line": item["StartLine"]},
                            "extra": {
                                "message": "Potential credential detected; value redacted.",
                                "severity": "ERROR",
                            },
                        }
                    )
            else:
                if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
                    raise ValueError("Unexpected OSV output")
                for group in payload["results"]:
                    for package in group["packages"]:
                        for vuln in package.get("vulnerabilities", []):
                            severities[str(vuln["id"])] = osv_severity(vuln)
                            matches.append(
                                {
                                    "check_id": str(vuln["id"]),
                                    "path": group["source"]["path"],
                                    "extra": {
                                        "message": f"Dependency advisory {vuln['id']}",
                                        "severity": "WARNING",
                                    },
                                }
                            )
            findings = normalize_semgrep({"results": matches}, None)
            translate_paths(findings, mapping)
            for finding in findings:
                finding["category"] = "secret" if name == "gitleaks" else "dependency"
                finding["sources"][0]["name"] = name
                finding["sources"][0]["version"] = version
                if name == "osv-scanner":
                    finding["severity"], finding["risk"] = severities[finding["sources"][0]["rule_id"]]
            return ScannerResult(
                name=name,
                version=version,
                database=metadata,
                limitations=warnings,
                status="completed",
                findings=findings,
                sandbox=sandbox_metadata(),
                files_scanned=len(selected),
                command=[name, *arguments],
                input_hashes={key: hashlib.sha256((stage / key).read_bytes()).hexdigest() for key in mapping},
            )
    except (OSError, ValueError, KeyError, TypeError) as error:
        return ScannerResult(
            name=name,
            version=None,
            status="failed",
            errors=[f"Isolated {name} failed: {_error_excerpt(str(error).encode())}"],
        )
