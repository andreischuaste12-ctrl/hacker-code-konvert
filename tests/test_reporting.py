from __future__ import annotations

from hacker_code_konvert.reporting import _markdown_code, _markdown_text


def test_untrusted_markdown_is_escaped_and_single_line() -> None:
    value = "candidate\n## injected [link](https://example.invalid) `<tag>`"
    rendered = _markdown_text(value)

    assert "\n" not in rendered
    assert "\\#\\# injected" in rendered
    assert "\\[link\\]\\(" in rendered
    assert "&lt;tag&gt;" in rendered


def test_untrusted_code_span_cannot_close_delimiter() -> None:
    assert _markdown_code("file`\n## injected") == "file' ## injected"


def test_terminal_and_bidirectional_controls_are_stripped_from_reports() -> None:
    hostile = "name \x1b[2J\u009b31m evil\u202egnp.py \u2028 end"
    for rendered in (_markdown_text(hostile), _markdown_code(hostile)):
        for forbidden in ("\x1b", "\u009b", "\u202e", "\u2028"):
            assert forbidden not in rendered


def _run(**overrides):
    run = {
        "run_id": "r",
        "started_at": "t",
        "revision": None,
        "analysis_profile": "repository",
        "controls": {"network": "disabled", "ai_processing": "disabled"},
        "scanner": {
            "name": "semgrep",
            "version": "1",
            "status": "completed",
            "errors": [],
            "files_scanned": 3,
        },
        "inventory": {"files_seen": 3, "scan_files": ["a.py"], "manifests": [], "skipped": []},
        "limitations": [],
        "complete": True,
        "vulnerability_scan_performed": True,
    }
    run.update(overrides)
    return run


def test_clean_notice_is_only_used_for_complete_scans() -> None:
    from hacker_code_konvert.reporting import render_markdown

    assert "No findings were identified" in render_markdown(_run(), [])
    incomplete = render_markdown(_run(complete=False), [])
    assert "No findings were identified" not in incomplete
    assert "not meaningful" in incomplete
    inventory_run = _run(vulnerability_scan_performed=False)
    inventory_run["scanner"]["name"] = "inventory"
    inventory_only = render_markdown(inventory_run, [])
    assert "No vulnerability scanner was run" in inventory_only


def test_coverage_gaps_are_listed_in_the_report() -> None:
    from hacker_code_konvert.reporting import render_markdown

    run = _run(complete=False)
    run["scanner"]["status"] = "partial_coverage"
    run["scanner"]["errors"] = ["Semgrep did not analyze 2 of 3 selected file(s): tests/x.py."]
    report = render_markdown(run, [])
    assert "Coverage Gaps" in report and "tests/x.py" in report
    assert "Files the scanner reported as analyzed: 3" in report
