from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from hacker_code_konvert.cli import main
from hacker_code_konvert.review import verify_review
from hacker_code_konvert.semgrep_adapter import normalize_semgrep


@pytest.fixture
def signed(tmp_path: Path, require_ssh_keygen):
    key = tmp_path / "key"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
    finding = normalize_semgrep(
        {"results": [{"path": "a.py", "extra": {"message": "Synthetic review"}}]}, "test"
    )[0]
    finding["status"] = "validated"
    finding["validation"] = {gate: "pass" for gate in finding["validation"]}
    finding["review"] = {"human_reviewed": True, "reviewer": "reviewer", "reviewed_at": "2026-11-09"}
    doc = tmp_path / "findings.json"
    doc.write_text(json.dumps({"findings": [finding]}))
    subprocess.run(
        ["ssh-keygen", "-Y", "sign", "-f", str(key), "-n", "hck-review", str(doc)],
        check=True,
        capture_output=True,
    )
    allowed = tmp_path / "allowed"
    allowed.write_text("reviewer " + key.with_suffix(".pub").read_text())
    return doc, Path(str(doc) + ".sig"), allowed


def test_valid_signature_and_disclosure_draft(signed, tmp_path: Path):
    doc, signature, allowed = signed
    options = [
        str(doc),
        "--signature",
        str(signature),
        "--allowed-signers",
        str(allowed),
        "--reviewer",
        "reviewer",
    ]
    assert main(["validate", *options]) == 0
    output = tmp_path / "draft.md"
    assert main(["report", "draft", *options, "--output", str(output)]) == 0
    assert "Draft only" in output.read_text()
    assert main(["report", "draft", *options, "--output", str(output)]) == 2


def test_tamper_and_untrusted_identity_fail(signed):
    doc, signature, allowed = signed
    with pytest.raises(ValueError):
        verify_review(doc, signature, allowed, "untrusted")
    doc.write_text(doc.read_text() + " ")
    with pytest.raises(ValueError):
        verify_review(doc, signature, allowed, "reviewer")
    with pytest.raises(ValueError):
        verify_review(doc, signature, allowed, "-option")


def test_cli_rejects_unsigned_validated_findings(signed):
    doc, _, _ = signed
    assert main(["validate", str(doc)]) == 2
