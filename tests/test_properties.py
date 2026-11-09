from __future__ import annotations

import re

from hypothesis import given, settings
from hypothesis import strategies as st

from hacker_code_konvert.redaction import redact_text
from hacker_code_konvert.reporting import _markdown_text
from hacker_code_konvert.semgrep_adapter import _safe_relative_path
from hacker_code_konvert.textsafety import has_unsafe_characters


@given(st.text(max_size=40000))
@settings(max_examples=150, deadline=500)
def test_redaction_is_bounded_and_idempotent(value: str) -> None:
    redacted = redact_text(value)
    assert redact_text(redacted) == redacted


@given(st.text())
def test_paths_are_relative(value: str) -> None:
    path = _safe_relative_path(value)
    assert not path.startswith("/")
    assert ".." not in path.split("/")
    assert not re.match(r"^[A-Za-z]:", path)


@given(st.text())
def test_markdown_contains_no_unsafe_characters(value: str) -> None:
    assert not has_unsafe_characters(_markdown_text(value))
