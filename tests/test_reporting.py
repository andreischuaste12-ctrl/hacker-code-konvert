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
