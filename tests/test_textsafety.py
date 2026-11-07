from __future__ import annotations

from hacker_code_konvert.textsafety import has_unsafe_characters, strip_unsafe_characters


def test_detects_control_bidirectional_and_separator_characters() -> None:
    for value in ("\x1b[0m", "\x7f", "\u009b", "\u202e", "\u200b", "\ufeff", "\u2028", "\u2029"):
        assert has_unsafe_characters(f"a{value}b"), repr(value)


def test_ordinary_text_including_unicode_letters_is_safe() -> None:
    for value in ("src/módulo/arquivo.py", "日本語/ファイル.py", "plain.py", "with space.py"):
        assert not has_unsafe_characters(value)
        assert strip_unsafe_characters(value) == value


def test_strip_keeps_newlines_and_tabs_for_callers_that_collapse_whitespace() -> None:
    assert strip_unsafe_characters("a\n\tb\x1b[2J\u202e") == "a\n\tb[2J"
