"""Construction of normalized candidate findings shared by every scanner adapter."""

from __future__ import annotations

import hashlib
from typing import Any

from hacker_code_konvert.redaction import redact_text
from hacker_code_konvert.textsafety import strip_unsafe_characters

MAX_TEXT_CHARS = 600

# Category-specific guidance. Scanner output never supplies remediation text.
GUIDANCE: dict[str, dict[str, str]] = {
    "sast": {
        "impact": "Potential security impact requires human validation.",
        "condition": "Requires contextual source-to-sink review",
        "remediation": "Review the affected data flow and apply the framework-specific safe alternative.",
        "verification": "Repeat the local rule and relevant project tests after an approved fix.",
        "rationale": "The bundled rule matched, but exploitability and reachability are unresolved.",
    },
    "secret": {
        "impact": (
            "If the value is a live credential, anyone who can read the repository or its history "
            "may be able to use it."
        ),
        "condition": "Requires confirming that the value is a real, active credential",
        "remediation": (
            "Revoke and rotate the credential, remove it from the working tree and from Git history, "
            "and load it from a secret store or the environment at runtime."
        ),
        "verification": "Confirm the old credential is rejected and repeat the secret scan.",
        "rationale": "A credential pattern matched; whether the value is live has not been checked.",
    },
    "dependency": {
        "impact": (
            "The locked version is listed as affected by the advisory. Whether the vulnerable code "
            "is reachable in this project requires review."
        ),
        "condition": "Requires confirming that the affected functionality is used",
        "remediation": "Upgrade the dependency to a version that is not affected by the advisory.",
        "verification": (
            "Regenerate the lockfile and repeat the offline dependency scan with a current database."
        ),
        "rationale": "The locked version matched an advisory range; reachability is unresolved.",
    },
}


def clean_text(value: Any, limit: int = MAX_TEXT_CHARS) -> str:
    """Single-line, redacted, bounded text from an untrusted scanner or database field."""
    text = " ".join(redact_text(strip_unsafe_characters(str(value))).split())
    return text if len(text) <= limit else f"{text[: limit - 1]}…"


def fingerprint(rule_id: str, path_key: str, start_line: int, end_line: int, discriminator: str = "") -> str:
    source = f"{rule_id}\0{path_key}\0{start_line}\0{end_line}"
    if discriminator:
        source += f"\0{discriminator}"
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def discriminator(finding: dict[str, Any]) -> str:
    """Extra identity for findings that share a rule and location (several packages in one lockfile)."""
    package = finding["sources"][0].get("package")
    if not isinstance(package, dict):
        return ""
    return f"{package.get('ecosystem', '')}/{package.get('name', '')}@{package.get('version', '')}"


def gate_state() -> dict[str, str]:
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


def candidate(
    *,
    rule_id: str,
    path: str,
    start_line: int,
    end_line: int,
    title: str,
    severity: str,
    category: str,
    scanner: str,
    version: str | None,
    summary: str | None = None,
    remediation: str | None = None,
    source: dict[str, Any] | None = None,
    taxonomy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    guidance = GUIDANCE[category]
    origin: dict[str, Any] = {"type": "scanner", "name": scanner, "version": version, "rule_id": rule_id}
    origin.update(source or {})
    finding: dict[str, Any] = {
        "id": "",
        "fingerprint": "",
        "title": title,
        "status": "candidate",
        "analysis_profile": "repository",
        "severity": severity,
        "confidence": "medium",
        "confidence_rationale": guidance["rationale"],
        "category": category,
        "location": {"path": path, "start_line": start_line, "end_line": end_line},
        "threat_model": {
            "attacker": "unconfirmed",
            "required_access": "unconfirmed",
            "conditions": [guidance["condition"]],
        },
        "evidence": {"summary": summary or title, "source_to_sink": [], "redacted": True},
        "validation": gate_state(),
        "impact": guidance["impact"],
        "reproduction": {
            "performed": False,
            "reason": "The static MVP does not execute target code; human review is required.",
            "steps": [],
        },
        "remediation": {
            "summary": remediation or guidance["remediation"],
            "verification": guidance["verification"],
        },
        "sources": [origin],
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
    assign_identity(finding, path)
    return finding


def assign_identity(finding: dict[str, Any], path_key: str) -> None:
    location = finding["location"]
    digest = fingerprint(
        finding["sources"][0]["rule_id"],
        path_key,
        location["start_line"],
        location["end_line"],
        discriminator(finding),
    )
    finding["fingerprint"] = f"sha256:{digest}"
    finding["id"] = f"HCK-{digest[:12].upper()}"


def deduplicated(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique = {finding["fingerprint"]: finding for finding in findings}
    return [unique[key] for key in sorted(unique)]
