"""Regression tests for the audit of dccd0b2: a hostile repository must not be able to make a run
look complete while hiding content, and scanner adapters must measure what they claim."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from hacker_code_konvert import sandbox, seccomp
from hacker_code_konvert.cli import main
from hacker_code_konvert.database import fixed_versions
from hacker_code_konvert.external import CANARY_NAME, CANARY_RULE, _requirements_state, run_external
from hacker_code_konvert.findings import candidate, clean_text
from hacker_code_konvert.inventory import ScopeError, build_inventory
from hacker_code_konvert.models import Inventory, ScannerResult
from hacker_code_konvert.reporting import render_markdown
from hacker_code_konvert.sandbox import CommandResult
from hacker_code_konvert.schema import ValidationError, validate_findings
from hacker_code_konvert.semgrep_adapter import normalize_semgrep, run_semgrep

OPTIONS = dict(timeout_seconds=30, memory_bytes=1024**3, output_bytes=1_000_000, max_file_bytes=100_000)
LOCKFILE = json.dumps(
    {
        "name": "fixture",
        "lockfileVersion": 2,
        "packages": {"node_modules/hck-synthetic": {"version": "1.0.0"}},
    }
)


def _run_json(output: Path) -> dict:
    return json.loads((output / "run.json").read_text(encoding="utf-8"))


def _fake_binary(monkeypatch) -> None:
    monkeypatch.setattr("hacker_code_konvert.external.shutil.which", lambda _: "/bin/true")
    monkeypatch.setattr("hacker_code_konvert.external._probe_version", lambda *a: "test")


def _database(path: Path) -> Path:
    (path / "osv-scalibr/npm").mkdir(parents=True)
    vulnerability = {
        "id": "HCK-TEST-0001",
        "modified": "2026-01-01T00:00:00Z",
        "summary": "Synthetic advisory",
        "aliases": ["CVE-2099-0001"],
        "affected": [
            {
                "package": {"name": "hck-synthetic", "ecosystem": "npm"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}],
                "versions": ["1.0.0"],
            }
        ],
    }
    with zipfile.ZipFile(path / "osv-scalibr/npm/all.zip", "w") as archive:
        archive.writestr("HCK-TEST-0001.json", json.dumps(vulnerability))
    return path


def _osv_report(*sources: tuple[str, int]) -> bytes:
    """A report in which each (lockfile, vulnerable) source lists one package."""
    results = []
    for path, vulnerable in sources:
        package = {"package": {"name": "hck-synthetic", "version": "1.0.0", "ecosystem": "npm"}}
        if vulnerable:
            package["vulnerabilities"] = [
                {
                    "id": "HCK-TEST-0001",
                    "summary": "Synthetic advisory",
                    "aliases": ["CVE-2099-0001"],
                    "affected": [
                        {
                            "package": {"name": "hck-synthetic", "ecosystem": "npm"},
                            "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}],
                        }
                    ],
                }
            ]
        results.append({"source": {"path": f"/target/{path}", "type": "lockfile"}, "packages": [package]})
    return json.dumps({"results": results}).encode()


def _lockfiles(command: list[str]) -> list[str]:
    return [command[i + 1].removeprefix("/target/") for i, item in enumerate(command) if item == "--lockfile"]


# --------------------------------------------------------------------------------------------
# Selection and capture
# --------------------------------------------------------------------------------------------


def test_scan_of_a_directory_hidden_by_a_git_marker_is_incomplete(tmp_path: Path, monkeypatch) -> None:
    repository = tmp_path / "repository"
    (repository / "app").mkdir(parents=True)
    (repository / "app/vuln.py").write_text("eval(input())\n")
    (repository / "app/.git").write_text("")
    (repository / "ok.py").write_text("x = 1\n")
    monkeypatch.setattr(
        "hacker_code_konvert.cli.run_semgrep",
        lambda *a, **k: ScannerResult("semgrep", "test", "completed", files_scanned=1, files_submitted=1),
    )
    output = tmp_path / "report"
    assert main(["scan", str(repository), "--output", str(output), "--authorized"]) == 3
    run = _run_json(output)
    assert run["complete"] is False and run["scanner"]["status"] == "partial_coverage"
    assert run["inventory"]["skipped"] == [
        {"path": "app", "reason": "nested repository or submodule not traversed"}
    ]


def test_semgrep_with_nothing_to_analyze_is_not_a_complete_run(tmp_path: Path, monkeypatch) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "app.js").write_text("eval(location.hash)\n")
    (repository / "main.go").write_text("package main\n")
    monkeypatch.setattr("hacker_code_konvert.semgrep_adapter.semgrep_executable", lambda: "/bin/true")
    monkeypatch.setattr("hacker_code_konvert.semgrep_adapter.semgrep_version", lambda _: "test")
    output = tmp_path / "report"
    assert main(["scan", str(repository), "--output", str(output), "--authorized"]) == 3
    run = _run_json(output)
    assert run["complete"] is False
    assert "nothing was analyzed" in run["scanner"]["errors"][0]
    assert any("Go (1), JavaScript (1)" in limitation for limitation in run["limitations"])
    assert any("selected by suffix" in limitation for limitation in run["limitations"])


def test_capture_failure_removes_the_private_snapshot(tmp_path: Path, monkeypatch) -> None:
    created: list[str] = []
    original = __import__("tempfile").mkdtemp

    def tracking(*args, **kwargs):
        created.append(original(*args, **kwargs))
        return created[-1]

    monkeypatch.setattr("hacker_code_konvert.inventory.tempfile.mkdtemp", tracking)
    (tmp_path / "a.py").write_text("x = 1\n")
    with pytest.raises(ScopeError):
        build_inventory(tmp_path, max_files=0)
    assert created and not Path(created[0]).exists()


def test_git_attributes_are_reported_as_a_limitation(tmp_path: Path) -> None:
    (tmp_path / ".gitattributes").write_text("*.py filter=secret\n")
    assert any("filters are not executed" in item for item in build_inventory(tmp_path).limitations)


def test_staged_suffix_never_carries_hostile_characters(tmp_path: Path) -> None:
    from hacker_code_konvert.formats import neutral_suffix

    assert neutral_suffix("notes.TXT") == ".txt"
    assert neutral_suffix("archive.tar\n--flag") == ".dat"
    assert neutral_suffix("no-suffix") == ".dat"
    assert neutral_suffix("page.PHTML", "php") == ".php"


# --------------------------------------------------------------------------------------------
# Review integrity
# --------------------------------------------------------------------------------------------


def _finding(status: str, **review) -> dict:
    finding = normalize_semgrep({"results": [{"path": "a.py", "extra": {"message": "Synthetic"}}]}, "test")[0]
    finding["status"] = status
    finding["review"].update(review)
    return finding


def test_dismissing_a_finding_requires_recorded_review() -> None:
    with pytest.raises(ValidationError, match="false positive requires human review"):
        validate_findings([_finding("false_positive")])
    reviewed = dict(human_reviewed=True, reviewer="reviewer", reviewed_at="2026-11-10")
    validate_findings([_finding("false_positive", **reviewed)])
    with pytest.raises(ValidationError, match="accepted risk requires a review date"):
        validate_findings([_finding("accepted_risk", human_reviewed=True, reviewer="reviewer")])


def test_cli_rejects_an_unsigned_false_positive(tmp_path: Path, capsys) -> None:
    document = tmp_path / "findings.json"
    reviewed = dict(human_reviewed=True, reviewer="reviewer", reviewed_at="2026-11-10")
    document.write_text(json.dumps({"findings": [_finding("false_positive", **reviewed)]}))
    assert main(["validate", str(document)]) == 2
    assert "require a signature" in capsys.readouterr().err


def test_signed_false_positive_is_accepted_and_tampering_is_not(tmp_path: Path, require_ssh_keygen) -> None:
    key = tmp_path / "key"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
    document = tmp_path / "findings.json"
    reviewed = dict(human_reviewed=True, reviewer="reviewer", reviewed_at="2026-11-10")
    document.write_text(json.dumps({"findings": [_finding("false_positive", **reviewed)]}))
    subprocess.run(
        ["ssh-keygen", "-Y", "sign", "-f", str(key), "-n", "hck-review", str(document)],
        check=True,
        capture_output=True,
    )
    allowed = tmp_path / "allowed"
    allowed.write_text("reviewer " + key.with_suffix(".pub").read_text())
    options = [
        str(document),
        "--signature",
        f"{document}.sig",
        "--allowed-signers",
        str(allowed),
        "--reviewer",
        "reviewer",
    ]
    assert main(["validate", *options]) == 0
    # A draft needs a validated finding; a signed dismissal alone produces none.
    assert main(["report", "draft", *options, "--output", str(tmp_path / "draft.md")]) == 2
    document.write_text(document.read_text() + "\n")
    assert main(["validate", *options]) == 2
    assert main(["report", "draft", *options, "--output", str(tmp_path / "draft.md")]) == 2


def test_findings_document_size_is_bounded(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("hacker_code_konvert.cli.MAX_FINDINGS_FILE_BYTES", 8)
    document = tmp_path / "findings.json"
    document.write_text(json.dumps({"findings": []}))
    assert main(["validate", str(document)]) == 2


# --------------------------------------------------------------------------------------------
# Gitleaks adapter
# --------------------------------------------------------------------------------------------


def _gitleaks_item(path: str, rule: str = "github-pat", line: int = 3) -> dict:
    return {"RuleID": rule, "File": f"/target/{path}", "StartLine": line, "EndLine": line}


def test_gitleaks_command_ignores_inline_allow_comments(tmp_path: Path, monkeypatch) -> None:
    _fake_binary(monkeypatch)
    (tmp_path / "a.env").write_text('TOKEN="synthetic" # gitleaks:allow\n')
    seen: list[list[str]] = []

    def fake(command, **kwargs):
        seen.append(command)
        report = [_gitleaks_item("f000000.env"), _gitleaks_item(CANARY_NAME, CANARY_RULE, 1)]
        return CommandResult(0, json.dumps(report).encode(), b"", 1)

    monkeypatch.setattr("hacker_code_konvert.external.run_limited", fake)
    result = run_external("gitleaks", tmp_path, build_inventory(tmp_path), **OPTIONS)
    assert result.status == "completed", result.errors
    assert "--ignore-gitleaks-allow" in seen[0]
    assert "/rules/gitleaks.toml" in seen[0]
    # The canary proves the rules ran, and it never becomes a finding.
    assert result.coverage == {"canary_detected": True}
    assert [item["location"]["path"] for item in result.findings] == ["a.env"]
    assert result.findings[0]["category"] == "secret"
    assert "Revoke and rotate" in result.findings[0]["remediation"]["summary"]
    # Per-file coverage is not something Gitleaks reports, and the run says so.
    assert result.files_scanned is None and result.files_submitted == 1
    assert "does not report which files" in result.limitations[0]


def test_gitleaks_without_the_canary_fails_closed(tmp_path: Path, monkeypatch) -> None:
    _fake_binary(monkeypatch)
    (tmp_path / "a.env").write_text("x\n")
    for report in ([], [_gitleaks_item(CANARY_NAME, "some-other-rule", 1)]):
        monkeypatch.setattr(
            "hacker_code_konvert.external.run_limited",
            lambda *a, _r=report, **k: CommandResult(0, json.dumps(_r).encode(), b"", 1),
        )
        result = run_external("gitleaks", tmp_path, build_inventory(tmp_path), **OPTIONS)
        assert result.status == "failed" and "canary" in result.errors[0]
        assert not result.findings


def test_external_adapter_requires_a_snapshot_and_reports_sandbox_errors(tmp_path: Path, monkeypatch) -> None:
    _fake_binary(monkeypatch)
    assert run_external("gitleaks", tmp_path, Inventory(regular_files=["a"]), **OPTIONS).status == "failed"
    (tmp_path / "a.env").write_text("x\n")
    monkeypatch.setattr(
        "hacker_code_konvert.external.build_bubblewrap_command",
        lambda *a, **k: (_ for _ in ()).throw(sandbox.SandboxUnavailable("no namespaces")),
    )
    result = run_external("gitleaks", tmp_path, build_inventory(tmp_path), **OPTIONS)
    assert result.status == "failed" and "no namespaces" in result.errors[0]


def test_external_version_probe_failures_are_tolerated(monkeypatch) -> None:
    from hacker_code_konvert.external import _probe_version

    monkeypatch.setattr(
        "hacker_code_konvert.external.subprocess.run", lambda *a, **k: (_ for _ in ()).throw(OSError())
    )
    assert _probe_version("gitleaks", "/bin/true") is None
    monkeypatch.setattr(
        "hacker_code_konvert.external.subprocess.run",
        lambda *a, **k: subprocess.CompletedProcess([], 0, stdout=b"8.30.1\n"),
    )
    assert _probe_version("osv-scanner", "/bin/true") == "8.30.1"


# --------------------------------------------------------------------------------------------
# OSV adapter
# --------------------------------------------------------------------------------------------


def _osv_repository(root: Path, *names: str) -> Path:
    for name in names:
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(LOCKFILE)
    return root


def test_osv_findings_name_the_package_and_the_fix(tmp_path: Path, monkeypatch) -> None:
    _fake_binary(monkeypatch)
    root = _osv_repository(tmp_path / "repo", "package-lock.json")
    monkeypatch.setattr(
        "hacker_code_konvert.external.run_limited",
        lambda command, **k: CommandResult(1, _osv_report((_lockfiles(command)[0], 1)), b"", 1),
    )
    result = run_external(
        "osv-scanner", root, build_inventory(root), database=_database(tmp_path / "db"), **OPTIONS
    )
    assert result.status == "completed", result.errors
    finding = result.findings[0]
    assert finding["category"] == "dependency"
    assert finding["title"].startswith("HCK-TEST-0001: hck-synthetic 1.0.0 (npm)")
    assert "CVE-2099-0001" in finding["evidence"]["summary"]
    assert finding["remediation"]["summary"].startswith("Upgrade hck-synthetic to 1.0.1")
    assert finding["sources"][0]["package"] == {
        "name": "hck-synthetic",
        "version": "1.0.0",
        "ecosystem": "npm",
    }
    assert finding["location"]["path"] == "package-lock.json"
    assert result.files_scanned == 1 and result.files_submitted == 1
    assert result.coverage == {"packages_evaluated": 1}
    assert "--all-packages" in result.command


def test_one_unreadable_lockfile_does_not_discard_the_others(tmp_path: Path, monkeypatch) -> None:
    _fake_binary(monkeypatch)
    root = _osv_repository(tmp_path / "repo", "package-lock.json", "bad/package-lock.json")
    (root / "bad/package-lock.json").write_text("{not json")
    calls: list[list[str]] = []

    def fake(command, **kwargs):
        lockfiles = _lockfiles(command)
        calls.append(lockfiles)
        if len(lockfiles) > 1 or lockfiles[0].startswith("f000000/"):
            return CommandResult(127, b"", b"could not extract: invalid character", 1)
        return CommandResult(1, _osv_report((lockfiles[0], 1)), b"", 1)

    monkeypatch.setattr("hacker_code_konvert.external.run_limited", fake)
    result = run_external(
        "osv-scanner", root, build_inventory(root), database=_database(tmp_path / "db"), **OPTIONS
    )
    assert [len(call) for call in calls] == [2, 1, 1]
    assert result.status == "partial_coverage"
    assert len(result.findings) == 1
    assert "could not analyze 'bad/package-lock.json'" in result.errors[0]
    assert result.files_scanned == 1 and result.files_submitted == 2


def test_lockfile_without_extracted_packages_is_a_coverage_gap(tmp_path: Path, monkeypatch) -> None:
    _fake_binary(monkeypatch)
    root = _osv_repository(tmp_path / "repo", "package-lock.json", "empty/package-lock.json")
    monkeypatch.setattr(
        "hacker_code_konvert.external.run_limited",
        lambda command, **k: CommandResult(0, _osv_report(("f000001/package-lock.json", 0)), b"", 1),
    )
    result = run_external(
        "osv-scanner", root, build_inventory(root), database=_database(tmp_path / "db"), **OPTIONS
    )
    assert result.status == "partial_coverage"
    assert "extracted no package from 1 dependency file(s)" in result.errors[0]
    assert result.files_scanned == 1


@pytest.mark.parametrize(
    ("command", "status"),
    [
        (CommandResult(128, b"", b"No package sources found", 1), "failed"),
        (CommandResult(127, b"", b"extraction failed", 1), "failed"),
        (CommandResult(0, b"not json", b"", 1), "malformed_output"),
        (CommandResult(0, b'{"results": [{"source": {}}]}', b"", 1), "malformed_output"),
        (CommandResult(0, b"[]", b"", 1), "malformed_output"),
        (CommandResult(0, b"", b"", 1, timed_out=True), "timeout"),
        (CommandResult(0, b"", b"", 1, output_limited=True), "output_limited"),
    ],
)
def test_osv_process_outcomes(tmp_path: Path, monkeypatch, command, status) -> None:
    _fake_binary(monkeypatch)
    root = _osv_repository(tmp_path / "repo", "package-lock.json")
    monkeypatch.setattr("hacker_code_konvert.external.run_limited", lambda *a, **k: command)
    result = run_external(
        "osv-scanner", root, build_inventory(root), database=_database(tmp_path / "db"), **OPTIONS
    )
    assert result.status == status, result.errors
    assert not result.findings


def test_osv_timeout_during_per_file_isolation_is_a_timeout(tmp_path: Path, monkeypatch) -> None:
    _fake_binary(monkeypatch)
    root = _osv_repository(tmp_path / "repo", "package-lock.json", "other/package-lock.json")
    outcomes = iter([CommandResult(127, b"", b"failed", 1), CommandResult(0, b"", b"", 1, timed_out=True)])
    monkeypatch.setattr("hacker_code_konvert.external.run_limited", lambda *a, **k: next(outcomes))
    result = run_external(
        "osv-scanner", root, build_inventory(root), database=_database(tmp_path / "db"), **OPTIONS
    )
    assert result.status == "timeout"


def test_osv_exhausted_time_budget_does_not_start_the_scanner(tmp_path: Path, monkeypatch) -> None:
    _fake_binary(monkeypatch)
    root = _osv_repository(tmp_path / "repo", "package-lock.json")
    monkeypatch.setattr(
        "hacker_code_konvert.external.run_limited", lambda *a, **k: pytest.fail("scanner must not start")
    )
    options = {**OPTIONS, "timeout_seconds": 0}
    result = run_external(
        "osv-scanner", root, build_inventory(root), database=_database(tmp_path / "db"), **options
    )
    assert result.status == "timeout"


def test_oversized_lockfile_is_a_gap_and_the_rest_is_still_analyzed(tmp_path: Path, monkeypatch) -> None:
    _fake_binary(monkeypatch)
    root = _osv_repository(tmp_path / "repo", "package-lock.json")
    (root / "web").mkdir()
    (root / "web/package-lock.json").write_text(LOCKFILE + " " * 200_000)
    monkeypatch.setattr(
        "hacker_code_konvert.external.run_limited",
        lambda command, **k: CommandResult(1, _osv_report((_lockfiles(command)[0], 1)), b"", 1),
    )
    inventory = build_inventory(root, scanner="osv-scanner", max_file_bytes=100_000)
    result = run_external("osv-scanner", root, inventory, database=_database(tmp_path / "db"), **OPTIONS)
    assert inventory.incomplete
    assert result.status == "partial_coverage"
    assert "1 dependency file(s) were not captured" in result.errors[0]
    assert len(result.findings) == 1


def test_requirements_files_are_handled_one_by_one(tmp_path: Path, monkeypatch) -> None:
    _fake_binary(monkeypatch)
    root = _osv_repository(tmp_path / "repo", "package-lock.json")
    (root / "requirements.txt").write_text("requests>=2.0\n")
    (root / "requirements-empty.txt").write_text("# nothing yet\n\n")
    monkeypatch.setattr(
        "hacker_code_konvert.external.run_limited",
        lambda command, **k: CommandResult(1, _osv_report((_lockfiles(command)[0], 1)), b"", 1),
    )
    result = run_external(
        "osv-scanner", root, build_inventory(root), database=_database(tmp_path / "db"), **OPTIONS
    )
    assert result.status == "partial_coverage"
    assert len(result.findings) == 1
    assert "'requirements.txt' uses unpinned versions" in result.errors[0]
    assert any("'requirements-empty.txt' declares no dependency" in item for item in result.limitations)


@pytest.mark.parametrize(
    ("content", "state"),
    [
        ("django==4.2.1\n", "pinned"),
        ("django==4.2.1 ; python_version < '3.13'\n", "pinned"),
        ("django[argon2]==4.2.1 \\\n    --hash=sha256:abc\n", "pinned"),
        ("django==4.2.1  # pinned by the release process\n", "pinned"),
        ("# only a comment\n", "empty"),
        ("django>=4\n", "unpinned"),
        ("-r base.txt\n", "unpinned"),
        ("git+https://example.invalid/pkg.git\n", "unpinned"),
        ("--index-url https://example.invalid/simple\ndjango==4.2.1\n", "unpinned"),
    ],
)
def test_requirements_state(tmp_path: Path, content: str, state: str) -> None:
    path = tmp_path / "requirements.txt"
    path.write_text(content)
    assert _requirements_state(path) == state


def test_fixed_versions_match_only_the_named_package() -> None:
    vulnerability = {
        "affected": [
            {"package": {"name": "Other", "ecosystem": "npm"}, "ranges": [{"events": [{"fixed": "9.9.9"}]}]},
            {
                "package": {"name": "Hck-Synthetic", "ecosystem": "npm"},
                "ranges": [
                    {"events": [{"introduced": "0"}, {"fixed": "1.0.1"}]},
                    {"events": [{"fixed": "1.0.1"}]},
                ],
            },
            "malformed entry",
        ]
    }
    assert fixed_versions(vulnerability, "hck-synthetic", "npm") == ["1.0.1"]
    assert fixed_versions({}, "hck-synthetic", "npm") == []


def test_osv_finding_without_a_fix_says_so(tmp_path: Path, monkeypatch) -> None:
    _fake_binary(monkeypatch)
    root = _osv_repository(tmp_path / "repo", "package-lock.json")
    report = json.loads(_osv_report(("f000000/package-lock.json", 1)))
    report["results"][0]["packages"][0]["vulnerabilities"][0]["affected"] = []
    monkeypatch.setattr(
        "hacker_code_konvert.external.run_limited",
        lambda *a, **k: CommandResult(1, json.dumps(report).encode(), b"", 1),
    )
    result = run_external(
        "osv-scanner", root, build_inventory(root), database=_database(tmp_path / "db"), **OPTIONS
    )
    assert "records no fixed version" in result.findings[0]["remediation"]["summary"]


def test_two_packages_with_the_same_advisory_stay_distinct() -> None:
    def dependency(name: str) -> dict:
        return candidate(
            rule_id="HCK-TEST-0001",
            path="package-lock.json",
            start_line=1,
            end_line=1,
            title="t",
            severity="high",
            category="dependency",
            scanner="osv-scanner",
            version="test",
            source={"package": {"name": name, "version": "1.0.0", "ecosystem": "npm"}},
        )

    assert dependency("a")["fingerprint"] != dependency("b")["fingerprint"]
    assert dependency("a")["fingerprint"] == dependency("a")["fingerprint"]


def test_scanner_text_is_bounded_and_single_line() -> None:
    text = clean_text("line one\nline two ‮" + "x" * 2000)
    assert "\n" not in text and "‮" not in text and len(text) == 600


# --------------------------------------------------------------------------------------------
# CLI defaults and report
# --------------------------------------------------------------------------------------------


def test_lockfile_size_default_applies_only_to_dependency_scans(tmp_path: Path, monkeypatch) -> None:
    seen = {}
    monkeypatch.setattr(
        "hacker_code_konvert.external.run_external",
        lambda name, root, inventory, **k: seen.update(k) or ScannerResult(name, "t", "completed"),
    )
    (tmp_path / "repo").mkdir()
    main(
        [
            "scan",
            str(tmp_path / "repo"),
            "--output",
            str(tmp_path / "a"),
            "--authorized",
            "--scanner",
            "osv-scanner",
        ]
    )
    assert seen["max_file_bytes"] == 32 * 1024**2
    assert _run_json(tmp_path / "a")["limits"]["max_file_bytes"] == 32 * 1024**2
    main(
        [
            "scan",
            str(tmp_path / "repo"),
            "--output",
            str(tmp_path / "b"),
            "--authorized",
            "--scanner",
            "gitleaks",
        ]
    )
    assert seen["max_file_bytes"] == 1_000_000


def test_missing_isolation_controls_are_stated_as_limitations(tmp_path: Path, monkeypatch) -> None:
    isolation = {
        "process_limit": sandbox.PROCESS_LIMIT_ABSENT,
        "seccomp_unresolved_syscalls": ["mount_setattr"],
    }
    monkeypatch.setattr(
        "hacker_code_konvert.cli.run_semgrep",
        lambda *a, **k: ScannerResult("semgrep", "test", "completed", sandbox=isolation),
    )
    (tmp_path / "repo").mkdir()
    output = tmp_path / "report"
    main(["scan", str(tmp_path / "repo"), "--output", str(output), "--authorized"])
    limitations = " ".join(_run_json(output)["limitations"])
    assert "No process-count limit was enforced" in limitations
    assert "cannot express every denied system call: mount_setattr" in limitations


def test_report_states_what_each_scanner_measured() -> None:
    run = {
        "run_id": "r",
        "started_at": "2026-11-10T00:00:00+00:00",
        "analysis_profile": "repository",
        "controls": {"network": "disabled", "ai_processing": "disabled"},
        "complete": True,
        "vulnerability_scan_performed": True,
        "rules_applied": {"ids": [], "count": 0, "sha256": None, "kind": "offline advisory database"},
        "inventory": {"files_seen": 4, "scan_files": [], "manifests": ["a"], "skipped": []},
        "limitations": [],
        "scanner": {
            "name": "osv-scanner",
            "status": "completed",
            "files_scanned": 2,
            "files_submitted": 3,
            "coverage": {"packages_evaluated": 41},
        },
    }
    report = render_markdown(run, [])
    assert "Files submitted to the scanner: 3" in report
    assert "Files the scanner reported as analyzed: 2" in report
    assert "Dependency packages evaluated: 41" in report
    assert "Rules applied: offline advisory database" in report
    run["scanner"].update(name="gitleaks", files_scanned=None, files_submitted=None, coverage={})
    report = render_markdown(run, [])
    assert "Files submitted to the scanner: unknown" in report
    assert "analyzed: not reported by this scanner" in report
    assert "Python files" not in report


# --------------------------------------------------------------------------------------------
# Sandbox construction
# --------------------------------------------------------------------------------------------


def test_process_limit_is_applied_only_where_the_kernel_scopes_it_to_the_sandbox(monkeypatch) -> None:
    monkeypatch.delenv("HCK_CGROUP_PARENT", raising=False)
    monkeypatch.setattr(sandbox.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(sandbox.platform, "release", lambda: "6.8.0-generic")
    monkeypatch.setattr(sandbox.os, "access", lambda path, mode: path == "/bin/prlimit")
    assert sandbox.process_limit_prefix(64) == ["/bin/prlimit", "--nproc=64:64", "--"]
    assert "RLIMIT_NPROC 64" in sandbox.process_limit_description(64)

    monkeypatch.setattr(sandbox.os, "access", lambda path, mode: False)
    assert sandbox.process_limit_prefix() == []
    monkeypatch.setattr(sandbox.os, "access", lambda path, mode: True)
    monkeypatch.setattr(sandbox.platform, "release", lambda: "5.13.0")
    assert sandbox.process_limit_prefix() == []
    monkeypatch.setattr(sandbox.platform, "release", lambda: "unparsable")
    assert sandbox.process_limit_prefix() == []
    monkeypatch.setattr(sandbox.platform, "release", lambda: "6.8.0")
    monkeypatch.setattr(sandbox.os, "geteuid", lambda: 0)
    assert sandbox.process_limit_prefix() == []
    assert sandbox.process_limit_description() == sandbox.PROCESS_LIMIT_ABSENT
    monkeypatch.setenv("HCK_CGROUP_PARENT", "/sys/fs/cgroup/delegated")
    assert sandbox.process_limit_description() == "delegated cgroup pids.max"


def test_process_limit_wraps_the_scanner_inside_the_sandbox(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(sandbox, "bubblewrap_path", lambda: "/usr/bin/bwrap")
    monkeypatch.setattr(
        sandbox, "process_limit_prefix", lambda limit: ["/usr/bin/prlimit", f"--nproc={limit}", "--"]
    )
    command = sandbox.build_bubblewrap_command(
        ["/usr/bin/true", "argument"], staged_root=tmp_path, rules_file=None, max_processes=7
    )
    assert command[command.index("--") + 1 :] == [
        "/usr/bin/prlimit",
        "--nproc=7",
        "--",
        "/usr/bin/true",
        "argument",
    ]


def test_sandbox_metadata_describes_the_filesystem_and_socket_policy(monkeypatch) -> None:
    monkeypatch.setattr(sandbox, "bubblewrap_version", lambda: "bubblewrap test")
    metadata = sandbox.sandbox_metadata(scratch_bytes=4096)
    assert "read-only root and /dev" in metadata["filesystem"] and "4096 bytes" in metadata["filesystem"]
    assert "every socket family except AF_UNIX" in metadata["seccomp"]
    assert metadata["seccomp_unresolved_syscalls"] == seccomp.unresolved_syscalls()


def test_unresolved_seccomp_names_are_reported_not_hidden(monkeypatch) -> None:
    class Library:
        @staticmethod
        def seccomp_syscall_resolve_name(name: bytes) -> int:
            return seccomp.UNKNOWN_SYSCALL if name == b"mount_setattr" else 1

    seccomp.unresolved_syscalls.cache_clear()
    monkeypatch.setattr(seccomp, "_library", lambda: Library())
    assert seccomp.unresolved_syscalls() == ["mount_setattr"]
    seccomp.unresolved_syscalls.cache_clear()
    monkeypatch.setattr(seccomp, "_library", lambda: (_ for _ in ()).throw(OSError("missing")))
    assert seccomp.unresolved_syscalls() == []
    seccomp.unresolved_syscalls.cache_clear()


def test_missing_libseccomp_fails_closed(monkeypatch) -> None:
    monkeypatch.setattr(seccomp.ctypes.util, "find_library", lambda _: None)
    with pytest.raises(OSError, match="libseccomp is required"):
        seccomp.filter_file()


# --------------------------------------------------------------------------------------------
# Real sandbox and scanners (mandatory in CI)
# --------------------------------------------------------------------------------------------

SANDBOX_PROBE = r"""
import ctypes, json, os, shutil
result = {"sizes": {path: shutil.disk_usage(path).total for path in ("/tmp", "/home", "/dev/shm")}}
result["writable"] = []
for path in ("/probe", "/dev/probe", "/rules/probe", "/target/probe", "/usr/probe"):
    try:
        open(path, "w").close()
        result["writable"].append(path)
    except OSError:
        pass
libc = ctypes.CDLL(None, use_errno=True)
sockets = {}
domains = {"inet": 2, "inet_high_bits": 0x100000002, "netlink": 16, "alg": 38, "unix": 1}
for label, domain in domains.items():
    arguments = (ctypes.c_long(41), ctypes.c_ulong(domain), ctypes.c_long(1), ctypes.c_long(0))
    sockets[label] = libc.syscall(*arguments) >= 0
result["sockets"] = sockets
result["accounts_visible"] = os.path.exists("/etc/passwd") or os.path.exists("/etc/group")
result["opt_visible"] = os.path.exists("/opt")
try:
    with open("/tmp/fill", "wb") as stream:
        for _ in range(64):
            stream.write(b"\0" * 1024 * 1024)
    result["scratch_overflow"] = True
except OSError:
    result["scratch_overflow"] = False
print(json.dumps(result))
"""


def _run_probe(tmp_path: Path, unavailable, script: str, **options) -> sandbox.CommandResult:
    staged = tmp_path / "target"
    staged.mkdir()
    (staged / "probe.py").write_text(script)
    rules = tmp_path / "rules.yml"
    rules.write_text("rules: []\n")
    try:
        wrapped = sandbox.build_bubblewrap_command(
            [str(Path(sys.executable).resolve()), "/target/probe.py"],
            staged_root=staged,
            rules_file=rules,
            **options,
        )
    except sandbox.SandboxUnavailable:
        unavailable("the test interpreter lives in an unsupported location")
    return sandbox.run_limited(
        wrapped, timeout_seconds=30, memory_bytes=2 * 1024**3, output_bytes=200 * 1024**2
    )


@pytest.mark.integration
@pytest.mark.skipif(os.uname().machine != "x86_64", reason="the probe uses the x86-64 socket syscall number")
def test_sandbox_bounds_writable_memory_and_allows_only_unix_sockets(
    tmp_path: Path, require_sandbox, unavailable
) -> None:
    result = _run_probe(tmp_path, unavailable, SANDBOX_PROBE, scratch_bytes=32 * 1024**2)
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    observed = json.loads(result.stdout)
    assert observed["sizes"] == {
        "/tmp": 32 * 1024**2,
        "/home": sandbox.HOME_BYTES,
        "/dev/shm": sandbox.SHARED_MEMORY_BYTES,
    }
    assert observed["writable"] == []
    assert observed["scratch_overflow"] is False
    assert observed["sockets"] == {
        "inet": False,
        "inet_high_bits": False,
        "netlink": False,
        "alg": False,
        "unix": True,
    }
    assert not observed["accounts_visible"] and not observed["opt_visible"]


FORK_PROBE = r"""
import os, sys, time
children = 0
try:
    for _ in range(200):
        if os.fork() == 0:
            time.sleep(5)
            os._exit(0)
        children += 1
except OSError:
    pass
print(children)
sys.stdout.flush()
os.killpg(0, 9)
"""


@pytest.mark.integration
def test_process_limit_stops_a_fork_storm_inside_the_sandbox(
    tmp_path: Path, require_sandbox, unavailable
) -> None:
    if not sandbox.process_limit_prefix():
        pytest.skip("no namespaced process limit for this user or kernel; the run records that")
    result = _run_probe(tmp_path, unavailable, FORK_PROBE, max_processes=32)
    assert 0 < int(result.stdout.split()[0]) < 32


def _require_binary(name: str, unavailable) -> None:
    if not shutil.which(name):
        unavailable(f"{name} is required")


@pytest.mark.integration
def test_gitleaks_allow_comment_cannot_suppress_a_credential(
    tmp_path: Path, require_sandbox, unavailable
) -> None:
    _require_binary("gitleaks", unavailable)
    import hashlib

    token = "ghp_" + hashlib.sha256(b"HCK-PUBLIC-SYNTHETIC-NOT-A-CREDENTIAL").hexdigest()[:36]
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "a.env").write_text(f'GITHUB_TOKEN="{token}" # gitleaks:allow\n')
    output = tmp_path / "report"
    assert (
        main(["scan", str(repository), "--output", str(output), "--authorized", "--scanner", "gitleaks"]) == 0
    )
    findings = json.loads((output / "findings.json").read_text())["findings"]
    assert [(item["location"]["path"], item["category"]) for item in findings] == [("a.env", "secret")]
    serialized = "".join(path.read_text() for path in output.iterdir())
    assert token not in serialized and "hck_canary_" not in serialized
    assert _run_json(output)["scanner"]["coverage"] == {"canary_detected": True}


@pytest.mark.integration
def test_osv_reports_partial_coverage_and_keeps_valid_results(
    tmp_path: Path, require_sandbox, unavailable
) -> None:
    _require_binary("osv-scanner", unavailable)
    repository = _osv_repository(tmp_path / "repository", "package-lock.json")
    (repository / "broken").mkdir()
    (repository / "broken/package-lock.json").write_text("{not json")
    (repository / "requirements.txt").write_text("requests>=2\n")
    output = tmp_path / "report"
    code = main(
        [
            "scan",
            str(repository),
            "--output",
            str(output),
            "--authorized",
            "--scanner",
            "osv-scanner",
            "--offline-database",
            str(_database(tmp_path / "database")),
        ]
    )
    run = _run_json(output)
    assert code == 3 and run["scanner"]["status"] == "partial_coverage", run["scanner"]["errors"]
    findings = json.loads((output / "findings.json").read_text())["findings"]
    assert len(findings) == 1
    assert findings[0]["sources"][0]["package"]["name"] == "hck-synthetic"
    assert findings[0]["sources"][0]["fixed_versions"] == ["1.0.1"]
    errors = " ".join(run["scanner"]["errors"])
    assert "'broken/package-lock.json'" in errors and "'requirements.txt'" in errors
    assert run["scanner"]["files_scanned"] == 1 and run["scanner"]["files_submitted"] == 2


@pytest.mark.integration
def test_disguised_source_files_are_analyzed(tmp_path: Path, require_semgrep, require_sandbox) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "pointer.php").write_text(
        "version https://git-lfs.github.com/spec/v1\n<?php echo $_GET['name'];\n"
    )
    (repository / "view.phtml").write_text("<?php echo $_GET['name'];\n")
    (repository / "job").write_text("#!/usr/bin/env python3\neval(input())\n")
    inventory = build_inventory(repository, scanner="semgrep")
    result = run_semgrep(
        repository,
        inventory,
        timeout_seconds=90,
        memory_bytes=4096 * 1024 * 1024,
        output_bytes=5_000_000,
        max_file_bytes=1_000_000,
    )
    assert result.status == "completed", result.errors
    assert result.files_scanned == result.files_submitted == 3
    assert {(item["sources"][0]["rule_id"], item["location"]["path"]) for item in result.findings} == {
        ("hck.php.unescaped-output", "pointer.php"),
        ("hck.php.unescaped-output", "view.phtml"),
        ("hck.python.dangerous-eval", "job"),
    }


@pytest.mark.integration
@pytest.mark.parametrize("corpus", ["python", "php", "mixed"])
def test_corpus_measurement(tmp_path: Path, corpus: str, require_semgrep, require_sandbox) -> None:
    root = Path(__file__).parent / "fixtures" / corpus
    output = tmp_path / "report"
    assert main(["scan", str(root), "--output", str(output), "--authorized"]) == 0
    measured = subprocess.run(
        [
            sys.executable,
            "scripts/evaluate_fixture_quality.py",
            "--findings",
            str(output / "findings.json"),
            "--expected",
            str(root / "expected.json"),
            "--output",
            str(tmp_path / "quality.json"),
        ],
        capture_output=True,
        check=False,
        timeout=30,
    )
    assert measured.returncode == 0, measured.stdout.decode()
    metrics = json.loads((tmp_path / "quality.json").read_text())
    assert metrics["false_positives"] == 0 and metrics["false_negatives"] == 0
    if corpus == "mixed":
        assert metrics["known_gaps"] == 1 and metrics["known_gaps_now_detected"] == 0
