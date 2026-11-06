from __future__ import annotations

from copy import deepcopy

import pytest

from hacker_code_konvert.schema import ValidationError, validate_findings


def candidate() -> dict:
    return {
        "id": "HCK-TEST",
        "fingerprint": "sha256:" + "a" * 64,
        "title": "Synthetic candidate",
        "status": "candidate",
        "analysis_profile": "repository",
        "severity": "medium",
        "confidence": "medium",
        "confidence_rationale": "Synthetic rule evidence exists; exploitability is unresolved.",
        "category": "sast",
        "location": {"path": "src/app.py", "start_line": 1, "end_line": 1},
        "threat_model": {},
        "evidence": {"summary": "Synthetic evidence", "redacted": True},
        "validation": {
            "authorization_scope": "pass",
            "coherent_claim": "pass",
            "code_applicability": "pass",
            "attacker_control_reachability": "unresolved",
            "vulnerability_mechanism": "unresolved",
            "realistic_impact": "unresolved",
            "environmental_controls": "unresolved",
            "safe_evidence": "pass",
            "human_review": "pending",
        },
        "impact": "Unconfirmed synthetic impact.",
        "reproduction": {"performed": False, "reason": "Synthetic unit test", "steps": []},
        "remediation": {},
        "sources": [{"type": "scanner", "name": "synthetic"}],
        "review": {"human_reviewed": False},
        "disclosure": {"status": "not_applicable"},
    }


def test_candidate_with_unresolved_gates_is_valid() -> None:
    validate_findings([candidate()])


def test_scanner_candidate_cannot_become_validated_without_review() -> None:
    finding = candidate()
    finding["status"] = "validated"
    with pytest.raises(ValidationError, match="technical gates"):
        validate_findings([finding])


def test_validated_requires_all_gates_and_human_review() -> None:
    finding = candidate()
    finding["status"] = "validated"
    finding["validation"] = {key: "pass" for key in finding["validation"]}
    finding["review"] = {
        "human_reviewed": True,
        "reviewer": "authorized-reviewer",
        "reviewed_at": "2026-11-06T00:00:00Z",
    }
    validate_findings([finding])


def test_validated_requires_reviewer_identity_and_date() -> None:
    finding = candidate()
    finding["status"] = "validated"
    finding["validation"] = {key: "pass" for key in finding["validation"]}
    finding["review"] = {"human_reviewed": True}
    with pytest.raises(ValidationError, match="reviewer"):
        validate_findings([finding])


def test_duplicate_fingerprints_fail() -> None:
    first = candidate()
    second = deepcopy(first)
    second["id"] = "HCK-TEST-2"
    with pytest.raises(ValidationError, match="duplicate fingerprint"):
        validate_findings([first, second])


def test_location_cannot_escape_root() -> None:
    finding = candidate()
    finding["location"]["path"] = "../outside.py"
    with pytest.raises(ValidationError, match="cannot escape"):
        validate_findings([finding])


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("status", [], "invalid status"),
        ("fingerprint", "not-a-fingerprint", "invalid fingerprint"),
        ("evidence", [], "evidence must be an object"),
    ],
)
def test_malformed_field_types_return_validation_errors(field: str, value: object, message: str) -> None:
    finding = candidate()
    finding[field] = value
    with pytest.raises(ValidationError, match=message):
        validate_findings([finding])


def test_non_object_finding_returns_validation_error() -> None:
    with pytest.raises(ValidationError, match="finding must be an object"):
        validate_findings(["not-an-object"])  # type: ignore[list-item]
