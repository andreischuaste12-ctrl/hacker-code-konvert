from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from importlib.resources import files
from pathlib import Path

import pytest

from hacker_code_konvert.inventory import ScopeError, build_inventory, stage_scan_files
from hacker_code_konvert.semgrep_adapter import (
    _error_excerpt,
    _safe_relative_path,
    coverage_problems,
    normalize_semgrep,
    recorded_command,
    run_semgrep,
    scanner_arguments,
    semgrep_version,
)

EXPECTED_FIXTURE_FINDINGS = {
    ("hck.python.dangerous-eval", "vulnerable.py"),
    ("hck.python.dangerous-eval", "tests/hidden_in_tests.py"),
}


def test_malformed_or_escaping_paths_are_not_preserved() -> None:
    payload = {
        "results": [
            {
                "check_id": "synthetic.rule",
                "path": "../../outside.py",
                "start": {"line": 1},
                "end": {"line": 1},
                "extra": {"message": "Synthetic result", "severity": "WARNING", "metadata": {}},
            }
        ]
    }
    findings = normalize_semgrep(payload, "test")
    assert findings[0]["location"]["path"] == "unknown"


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {},
        {"results": ["not-an-object"]},
        {"results": [{"extra": []}]},
    ],
)
def test_malformed_semgrep_output_is_rejected(payload: object) -> None:
    with pytest.raises(TypeError):
        normalize_semgrep(payload, "test")  # type: ignore[arg-type]


def test_sandbox_target_prefix_is_removed() -> None:
    payload = {
        "results": [
            {
                "check_id": "synthetic.rule",
                "path": "/target/package/module.py",
                "start": {"line": 1},
                "end": {"line": 1},
                "extra": {"message": "Synthetic result", "severity": "INFO", "metadata": {}},
            }
        ]
    }
    findings = normalize_semgrep(payload, "test")
    assert findings[0]["location"]["path"] == "package/module.py"


@pytest.mark.integration
def test_bundled_semgrep_rules_ignore_target_suppressions(require_semgrep) -> None:
    executable = shutil.which("semgrep")
    assert executable
    fixture = Path(__file__).parent / "fixtures/python"
    inventory = build_inventory(fixture)
    rules = Path(str(files("hacker_code_konvert").joinpath("data/python-security.yml")))
    with tempfile.TemporaryDirectory() as temporary:
        staged = Path(temporary) / "target"
        home = Path(temporary) / "home"
        home.mkdir()
        stage_scan_files(fixture, inventory, staged, max_file_bytes=1_000_000)
        result = subprocess.run(
            [
                executable,
                "--config",
                str(rules),
                "--json",
                "--metrics=off",
                "--disable-version-check",
                "--no-git-ignore",
                "--disable-nosem",
                ".",
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=60,
            cwd=staged,
            env={**os.environ, "HOME": str(home), "SEMGREP_SEND_METRICS": "off"},
        )
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    findings = normalize_semgrep(json.loads(result.stdout), "test")
    observed = {(item["sources"][0]["rule_id"], item["location"]["path"]) for item in findings}
    assert observed == EXPECTED_FIXTURE_FINDINGS


@pytest.mark.integration
def test_semgrep_runs_inside_networkless_sandbox(require_semgrep, require_sandbox) -> None:
    fixture = Path(__file__).parent / "fixtures/python"
    inventory = build_inventory(fixture)
    result = run_semgrep(
        fixture,
        inventory,
        timeout_seconds=60,
        memory_bytes=4096 * 1024 * 1024,  # documented minimum; semgrep-core needs the virtual address space
        output_bytes=5_000_000,
        max_file_bytes=1_000_000,
    )
    assert result.status == "completed", result.errors
    observed = {(item["sources"][0]["rule_id"], item["location"]["path"]) for item in result.findings}
    assert observed == EXPECTED_FIXTURE_FINDINGS
    assert result.files_scanned == len(inventory.scan_files)
    assert result.sandbox["capabilities"] == "dropped"


def test_recorded_command_matches_what_is_executed() -> None:
    arguments = scanner_arguments(123_456)
    recorded = recorded_command(arguments)

    assert recorded[0] == "semgrep"
    assert "--offline" not in recorded  # this flag was recorded before although it was never passed
    assert recorded[1:] == [
        {"/rules/python-security.yml": "<bundled-python-rules>", "/target": "<staged-target>"}.get(item, item)
        for item in arguments
    ]
    for required in ("--disable-nosem", "--no-git-ignore", "--metrics=off", "--disable-version-check"):
        assert required in recorded
    assert recorded[recorded.index("--max-target-bytes") + 1] == "123456"


def test_version_probe_disables_the_version_check(monkeypatch) -> None:
    captured: dict[str, object] = {}

    class Completed:
        returncode = 0
        stdout = b"1.184.0\n"

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["env"] = kwargs["env"]
        captured["cwd"] = kwargs["cwd"]
        return Completed()

    monkeypatch.setattr("hacker_code_konvert.semgrep_adapter.subprocess.run", fake_run)

    assert semgrep_version("/usr/bin/semgrep") == "1.184.0"
    assert "--disable-version-check" in captured["command"]
    assert captured["env"]["SEMGREP_ENABLE_VERSION_CHECK"] == "0"
    assert captured["env"]["SEMGREP_SEND_METRICS"] == "off"
    assert captured["cwd"] != os.getcwd()  # never the (possibly untrusted) current directory


def test_coverage_is_complete_when_every_selected_file_was_analyzed() -> None:
    payload = {"paths": {"scanned": ["/target/a.py", "/target/pkg/b.py"], "skipped": None}, "errors": []}
    assert coverage_problems(payload, ["a.py", "pkg/b.py"]) == []


def test_files_silently_dropped_by_the_scanner_make_coverage_incomplete() -> None:
    payload = {"paths": {"scanned": ["/target/app/main.py"]}, "errors": []}
    problems = coverage_problems(payload, ["app/main.py", "tests/exploit.py", "test/exploit2.py"])
    assert len(problems) == 1
    assert "did not analyze 2 of 3" in problems[0]
    assert "tests/exploit.py" in problems[0]


def test_scanner_errors_and_skips_are_not_ignored() -> None:
    payload = {
        "paths": {"scanned": ["a.py"], "skipped": [{"path": "big.py", "reason": "exceeded_size_limit"}]},
        "errors": [
            {
                "type": ["PartialParsing", [{"path": "a.py"}]],
                "path": "a.py",
                "message": "code: password = 'x'",
            },
        ],
    }
    problems = coverage_problems(payload, ["a.py"])
    joined = " ".join(problems)
    assert "skipped file" in joined and "exceeded_size_limit" in joined
    assert "PartialParsing" in joined and "a.py" in joined
    assert "password" not in joined  # error text can quote source code and is never copied


def test_missing_paths_report_means_coverage_cannot_be_verified() -> None:
    assert "could not be verified" in coverage_problems({"results": []}, ["a.py"])[0]
    assert "could not be verified" in coverage_problems({"paths": "x"}, ["a.py"])[0]


def test_hostile_paths_in_scanner_output_are_neutralized() -> None:
    payload = {
        "paths": {"scanned": []},
        "errors": [{"type": "Error\x1b[2J", "path": "evil\u202egnp.py"}],
    }
    joined = " ".join(coverage_problems(payload, ["x.py"]))
    assert "\x1b" not in joined and "\u202e" not in joined


def test_bidirectional_and_control_characters_in_paths_become_unknown() -> None:
    for hostile in ("evil\u202egnp.py", "a\x1b[31m.py", "a\u009b2J.py", "a\u2028b.py", "C:/windows.py"):
        assert _safe_relative_path(hostile) == "unknown"


def test_scanner_stderr_excerpt_is_redacted_and_single_line() -> None:
    stderr = (
        b"Traceback ...\n"
        b'{"password": "hunter2-synthetic"} github_pat_11AAAAAAA0synthetic1234567890abcdefghij\n'
        b"line with \x1b[2J escape\n"
    )
    excerpt = _error_excerpt(stderr)
    assert "hunter2-synthetic" not in excerpt
    assert "github_pat_" not in excerpt
    assert "\x1b" not in excerpt and "\n" not in excerpt


def test_stderr_excerpt_is_bounded_even_for_huge_output() -> None:
    assert len(_error_excerpt(b"x" * 5_000_000)) <= 1000


def _patch_available_scanner(monkeypatch) -> None:
    monkeypatch.setattr("hacker_code_konvert.semgrep_adapter.semgrep_executable", lambda: "/bin/true")
    monkeypatch.setattr("hacker_code_konvert.semgrep_adapter.semgrep_version", lambda executable: "test")


def test_staging_failure_is_reported_as_failed_not_raised(tmp_path: Path, monkeypatch) -> None:
    _patch_available_scanner(monkeypatch)
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "app.py").write_text("x = 1\n", encoding="utf-8")

    def refuse(*args, **kwargs):
        raise PermissionError(13, "Permission denied", str(repository / "app.py"))

    monkeypatch.setattr("hacker_code_konvert.semgrep_adapter.stage_scan_files", refuse)
    result = run_semgrep(
        repository,
        build_inventory(repository),
        timeout_seconds=5,
        memory_bytes=1024**3,
        output_bytes=10_000,
        max_file_bytes=1_000_000,
    )
    assert result.status == "failed"
    assert "Staging the selected files failed" in result.errors[0]


def test_cli_turns_a_staging_failure_into_an_incomplete_run(tmp_path: Path, monkeypatch) -> None:
    from hacker_code_konvert.cli import main

    _patch_available_scanner(monkeypatch)
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "app.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setattr(
        "hacker_code_konvert.semgrep_adapter.stage_scan_files",
        lambda *a, **k: (_ for _ in ()).throw(ScopeError("file changed type during staging: app.py")),
    )
    output = tmp_path / "report"

    assert main(["scan", str(repository), "--output", str(output), "--authorized"]) == 3
    run = json.loads((output / "run.json").read_text(encoding="utf-8"))
    assert run["complete"] is False and run["scanner"]["status"] == "failed"
    assert run["controls"]["scanner_input"] == "not_applicable"  # no sandbox actually ran


def _write_repository(root: Path, files_: dict[str, str]) -> Path:
    root.mkdir()
    for name, content in files_.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return root


def _run_isolated(repository: Path):
    return run_semgrep(
        repository,
        build_inventory(repository),
        timeout_seconds=90,
        memory_bytes=4096 * 1024 * 1024,
        output_bytes=5_000_000,
        max_file_bytes=1_000_000,
    )


@pytest.mark.integration
def test_vulnerable_code_in_test_directories_is_not_silently_skipped(
    tmp_path: Path, require_semgrep, require_sandbox
) -> None:
    sink = "def f(x):\n    return eval(x)\n"
    repository = _write_repository(
        tmp_path / "repository",
        {
            "app/main.py": sink,
            "tests/exploit.py": sink,
            "test/exploit2.py": sink,
            "src/tests/exploit3.py": sink,
        },
    )

    result = _run_isolated(repository)

    assert result.status == "completed", result.errors
    assert {item["location"]["path"] for item in result.findings} == {
        "app/main.py",
        "tests/exploit.py",
        "test/exploit2.py",
        "src/tests/exploit3.py",
    }
    assert result.files_scanned == 4


@pytest.mark.integration
def test_scanner_parse_errors_make_the_run_incomplete(
    tmp_path: Path, require_semgrep, require_sandbox
) -> None:
    repository = _write_repository(
        tmp_path / "repository",
        {
            "ok.py": "def f(x):\n    return eval(x)\n",
            "broken.py": "x = 1\x00\ndef g(y):\n    return eval(y)\n",
        },
    )

    result = _run_isolated(repository)

    assert result.status == "partial_coverage"
    assert any("PartialParsing" in item and "broken.py" in item for item in result.errors)
    assert {item["location"]["path"] for item in result.findings} >= {"ok.py"}
