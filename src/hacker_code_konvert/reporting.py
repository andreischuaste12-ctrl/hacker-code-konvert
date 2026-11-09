from __future__ import annotations

import json
import os
import re
import tempfile
from html import escape
from pathlib import Path
from typing import Any

from hacker_code_konvert.redaction import redact
from hacker_code_konvert.textsafety import strip_unsafe_characters


def _markdown_text(value: Any) -> str:
    text = re.sub(r"\s+", " ", strip_unsafe_characters(str(value))).strip()
    text = escape(text, quote=False)
    for character in "\\`*_{}[]()#+!|":
        text = text.replace(character, f"\\{character}")
    return text


def _markdown_code(value: Any) -> str:
    return re.sub(r"\s+", " ", strip_unsafe_characters(str(value))).strip().replace("`", "'")


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
        temporary.replace(path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def write_json(path: Path, value: Any) -> None:
    safe_value = redact(value)
    _atomic_write(path, json.dumps(safe_value, indent=2, sort_keys=True) + "\n")


def _coverage_lines(run: dict[str, Any]) -> list[str]:
    scanner = run["scanner"]
    inventory = run["inventory"]
    lines = [
        f"- Files inventoried: {inventory['files_seen']}",
        f"- Python files selected: {len(inventory['scan_files'])}",
    ]
    if scanner["name"] != "inventory":
        analyzed = scanner.get("files_scanned")
        shown = analyzed if analyzed is not None else "unknown"
        lines.append(f"- Python files analyzed by the scanner: {shown}")
    lines.extend(
        [
            f"- Manifests found: {len(inventory['manifests'])}",
            f"- Skipped entries: {len(inventory['skipped'])}",
        ]
    )
    return lines


def _no_findings_notice(run: dict[str, Any]) -> str:
    if run["scanner"]["name"] == "inventory":
        return (
            "No vulnerability scanner was run in this mode. This report contains an inventory only, "
            "and the absence of findings has no security meaning."
        )
    if not run["complete"]:
        return (
            "No findings were reported, but the scan did not complete or did not cover every selected "
            "file. The absence of findings is not meaningful for the uncovered code."
        )
    return (
        "No findings were identified by the checks that completed. "
        "Only the listed rule classes were checked. This does not prove that the project is secure."
    )


def render_markdown(run: dict[str, Any], findings: list[dict[str, Any]]) -> str:
    scanner = run["scanner"]
    lines = [
        "# Hacker Code Konvert Report",
        "",
        "## Run Metadata",
        "",
        f"- **Run ID:** `{_markdown_code(run['run_id'])}`",
        f"- **Started:** {_markdown_text(run['started_at'])}",
        f"- **Repository revision:** `{_markdown_code(run.get('revision') or 'unavailable')}`",
        f"- **Analysis profile:** `{_markdown_code(run['analysis_profile'])}`",
        f"- **Network:** `{_markdown_code(run['controls']['network'])}`",
        f"- **AI processing:** `{_markdown_code(run['controls']['ai_processing'])}`",
        (
            f"- **Scanner:** `{_markdown_code(scanner['name'])} "
            f"{_markdown_code(scanner.get('version') or 'unavailable')}`"
        ),
        f"- **Scanner status:** `{_markdown_code(scanner['status'])}`",
        f"- **Run complete:** `{_markdown_code(run['complete'])}`",
        (
            "- **Vulnerability scan performed:** "
            f"`{_markdown_code(run.get('vulnerability_scan_performed', False))}`"
        ),
        "",
        "## Coverage",
        "",
        *_coverage_lines(run),
        f"- Rules applied: {_markdown_text(run.get('rules_applied') or 'none')}",
        "",
        "## Results",
        "",
        f"Candidates: **{len(findings)}**",
        "",
    ]
    if not findings:
        lines.extend([_no_findings_notice(run), ""])
    for finding in findings:
        location = finding["location"]
        lines.extend(
            [
                f"### {_markdown_text(finding['id'])}: {_markdown_text(finding['title'])}",
                "",
                f"- **Status:** `{_markdown_code(finding['status'])}`",
                f"- **Severity:** `{_markdown_code(finding['severity'])}`",
                f"- **Confidence:** `{_markdown_code(finding['confidence'])}`",
                f"- **Confidence rationale:** {_markdown_text(finding['confidence_rationale'])}",
                (
                    f"- **Location:** `{_markdown_code(location.get('display_path', location['path']))}:"
                    f"{_markdown_code(location.get('start_line', 1))}`"
                ),
                f"- **Evidence:** {_markdown_text(finding['evidence']['summary'])}",
                f"- **Impact:** {_markdown_text(finding['impact'])}",
                f"- **Safe reproduction:** {_markdown_text(finding['reproduction']['reason'])}",
                f"- **Remediation:** {_markdown_text(finding['remediation']['summary'])}",
                "",
            ]
        )

    lines.extend(["## Limitations", ""])
    for limitation in run["limitations"]:
        lines.append(f"- {_markdown_text(limitation)}")
    if scanner.get("errors"):
        lines.extend(["", "## Scanner Errors and Coverage Gaps", ""])
        for error in scanner["errors"]:
            lines.append(f"- {_markdown_text(error)}")
    lines.append("")
    return "\n".join(lines)


def write_artifacts(output: Path, run: dict[str, Any], findings: list[dict[str, Any]]) -> None:
    """Write the report set. ``run.json`` is written last, so its presence marks a complete set."""
    created = not output.exists()
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    if created:
        output.chmod(0o700)
    write_json(output / "findings.json", {"schema_version": "1.0", "findings": findings})
    _atomic_write(output / "report.md", render_markdown(redact(run), redact(findings)))
    from hacker_code_konvert.sarif import render_sarif

    write_json(output / "results.sarif", render_sarif(run, findings))
    write_json(output / "run.json", run)
