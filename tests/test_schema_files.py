"""The published JSON Schemas must agree with the executable validator and with real output."""

from __future__ import annotations

import copy
import json
from importlib.resources import files
from pathlib import Path

import pytest

from hacker_code_konvert.cli import main
from hacker_code_konvert.schema import REQUIRED_GATES, ValidationError, validate_finding

jsonschema = pytest.importorskip("jsonschema")


def _schema(name: str) -> dict:
    return json.loads(files("hacker_code_konvert").joinpath(f"data/{name}").read_text(encoding="utf-8"))


def _candidate() -> dict:
    return {
        "id": "HCK-TEST",
        "fingerprint": "sha256:" + "0" * 64,
        "title": "t",
        "status": "candidate",
        "analysis_profile": "repository",
        "severity": "low",
        "confidence": "low",
        "confidence_rationale": "r",
        "category": "sast",
        "location": {"path": "a.py", "start_line": 1, "end_line": 1},
        "threat_model": {},
        "evidence": {},
        "validation": {gate: "unresolved" for gate in REQUIRED_GATES},
        "impact": "i",
        "reproduction": {"performed": False, "reason": "r", "steps": []},
        "remediation": {},
        "sources": [{"type": "scanner"}],
        "review": {"human_reviewed": False, "reviewer": None, "reviewed_at": None},
        "disclosure": {"status": "not_applicable"},
    }


def _schema_accepts(finding: dict) -> bool:
    return not list(jsonschema.Draft202012Validator(_schema("finding.schema.json")).iter_errors(finding))


def _python_accepts(finding: dict) -> bool:
    try:
        validate_finding(finding)
    except ValidationError:
        return False
    return True


def test_schemas_are_valid_json_schema() -> None:
    jsonschema.Draft202012Validator.check_schema(_schema("finding.schema.json"))
    jsonschema.Draft202012Validator.check_schema(_schema("run.schema.json"))


def test_real_run_output_conforms_to_the_run_schema(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "a.py").write_text("x = 1\n", encoding="utf-8")
    output = tmp_path / "out"
    assert (
        main(["scan", str(repository), "--output", str(output), "--authorized", "--scanner", "inventory"])
        == 0
    )
    run = json.loads((output / "run.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(_schema("run.schema.json")).validate(run)


def _validated(**review) -> dict:
    finding = _candidate()
    finding["status"] = "validated"
    finding["validation"] = {gate: "pass" for gate in REQUIRED_GATES}
    finding["review"] = {
        "human_reviewed": True,
        "reviewer": "a reviewer",
        "reviewed_at": "2026-01-01",
        **review,
    }
    return finding


def _accepted_risk(**review) -> dict:
    finding = _candidate()
    finding["status"] = "accepted_risk"
    finding["review"] = {
        "human_reviewed": True,
        "reviewer": "an owner",
        "reviewed_at": "2026-01-01",
        **review,
    }
    return finding


def test_schema_and_validator_agree_on_review_invariants() -> None:
    unreviewed = _validated(human_reviewed=False)
    no_reviewer = _validated(reviewer="")
    one_gate_open = _validated()
    one_gate_open["validation"]["realistic_impact"] = "unresolved"
    cases = {
        "candidate": (_candidate(), True),
        "validated and reviewed": (_validated(), True),
        "validated without human review": (unreviewed, False),
        "validated without reviewer": (no_reviewer, False),
        "validated with an open gate": (one_gate_open, False),
        "accepted risk reviewed": (_accepted_risk(), True),
        "accepted risk unreviewed": (_accepted_risk(human_reviewed=False), False),
    }
    for name, (finding, expected) in cases.items():
        assert _schema_accepts(copy.deepcopy(finding)) is expected, f"schema: {name}"
        assert _python_accepts(copy.deepcopy(finding)) is expected, f"validator: {name}"
