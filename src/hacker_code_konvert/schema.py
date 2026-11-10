from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Any

from hacker_code_konvert.textsafety import has_unsafe_characters

STATUSES = {"candidate", "validated", "false_positive", "accepted_risk"}
REVIEWED_DISMISSALS = {"false_positive", "accepted_risk"}
# Every status other than the scanner default records a human decision and must be signed.
REVIEWED_STATUSES = STATUSES - {"candidate"}
SEVERITIES = {"informational", "low", "medium", "high", "critical"}
CONFIDENCE = {"low", "medium", "high"}
PROFILES = {"repository", "differential", "dependency", "ecommerce", "active"}
GATE_RESULTS = {"pass", "fail", "unresolved", "pending", "not_applicable"}
FINGERPRINT_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")

REQUIRED_FIELDS = {
    "id",
    "fingerprint",
    "title",
    "status",
    "analysis_profile",
    "severity",
    "confidence",
    "confidence_rationale",
    "category",
    "location",
    "threat_model",
    "evidence",
    "validation",
    "impact",
    "reproduction",
    "remediation",
    "sources",
    "review",
    "disclosure",
}

REQUIRED_GATES = {
    "authorization_scope",
    "coherent_claim",
    "code_applicability",
    "attacker_control_reachability",
    "vulnerability_mechanism",
    "realistic_impact",
    "environmental_controls",
    "safe_evidence",
    "human_review",
}


class ValidationError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def validate_finding(finding: dict[str, Any]) -> None:
    _require(isinstance(finding, dict), "finding must be an object")
    missing = REQUIRED_FIELDS - finding.keys()
    _require(not missing, f"missing required fields: {', '.join(sorted(missing))}")
    for field in ("id", "title", "confidence_rationale", "category", "impact"):
        _require(isinstance(finding[field], str) and bool(finding[field].strip()), f"{field} is required")
    fingerprint = finding["fingerprint"]
    _require(
        isinstance(fingerprint, str) and FINGERPRINT_PATTERN.fullmatch(fingerprint) is not None,
        "invalid fingerprint",
    )
    _require(isinstance(finding["status"], str) and finding["status"] in STATUSES, "invalid status")
    _require(
        isinstance(finding["severity"], str) and finding["severity"] in SEVERITIES,
        "invalid severity",
    )
    _require(
        isinstance(finding["confidence"], str) and finding["confidence"] in CONFIDENCE,
        "invalid confidence",
    )
    _require(
        isinstance(finding["analysis_profile"], str) and finding["analysis_profile"] in PROFILES,
        "invalid analysis profile",
    )

    location = finding["location"]
    _require(isinstance(location, dict), "location must be an object")
    path = location.get("path")
    _require(isinstance(path, str) and bool(path), "location.path is required")
    _require(
        "\\" not in path and re.match(r"^[A-Za-z]:/", path) is None and not has_unsafe_characters(path),
        "invalid location.path",
    )
    pure_path = PurePosixPath(path)
    _require(not pure_path.is_absolute(), "location.path must be relative")
    _require(".." not in pure_path.parts, "location.path cannot escape the repository")
    _require(bool(pure_path.parts) and pure_path.as_posix() != ".", "location.path is required")
    for line_field in ("start_line", "end_line"):
        if line_field in location:
            line = location[line_field]
            _require(
                isinstance(line, int) and not isinstance(line, bool) and line > 0, f"invalid {line_field}"
            )
    if "start_line" in location and "end_line" in location:
        _require(location["end_line"] >= location["start_line"], "end_line cannot precede start_line")

    sources = finding["sources"]
    _require(isinstance(sources, list) and bool(sources), "at least one source is required")
    _require(all(isinstance(source, dict) for source in sources), "sources must contain objects")

    for field in ("threat_model", "evidence", "reproduction", "remediation", "review", "disclosure"):
        _require(isinstance(finding[field], dict), f"{field} must be an object")

    validation = finding["validation"]
    _require(isinstance(validation, dict), "validation must be an object")
    missing_gates = REQUIRED_GATES - validation.keys()
    _require(not missing_gates, f"missing validation gates: {', '.join(sorted(missing_gates))}")
    _require(
        all(isinstance(result, str) and result in GATE_RESULTS for result in validation.values()),
        "invalid verification gate result",
    )

    review = finding["review"]
    _require(isinstance(review, dict), "review must be an object")
    human_reviewed = review.get("human_reviewed") is True
    if finding["status"] == "validated":
        non_human_gates = {name: result for name, result in validation.items() if name != "human_review"}
        _require(
            all(result == "pass" for result in non_human_gates.values()),
            "validated findings require all technical gates to pass",
        )
        _require(validation["human_review"] == "pass", "validated findings require the human-review gate")
        _require(human_reviewed, "validated findings require recorded human review")
        _require(bool(review.get("reviewer")), "validated findings require a reviewer")
        _require(bool(review.get("reviewed_at")), "validated findings require a review date")

    # Dismissing a finding is a review decision with the same weight as confirming it: a result
    # marked false positive or accepted risk leaves the queue, so it needs an accountable reviewer.
    if finding["status"] in REVIEWED_DISMISSALS:
        label = finding["status"].replace("_", " ")
        _require(human_reviewed, f"{label} requires human review")
        _require(bool(review.get("reviewer")), f"{label} requires an authorized reviewer")
        _require(bool(review.get("reviewed_at")), f"{label} requires a review date")


def validate_findings(findings: list[dict[str, Any]]) -> None:
    seen: set[str] = set()
    for index, finding in enumerate(findings):
        try:
            validate_finding(finding)
        except ValidationError as error:
            raise ValidationError(f"finding {index}: {error}") from error
        fingerprint = finding["fingerprint"]
        _require(fingerprint not in seen, f"duplicate fingerprint: {fingerprint}")
        seen.add(fingerprint)
