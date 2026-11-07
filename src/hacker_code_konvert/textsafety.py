from __future__ import annotations

import unicodedata

# Control (Cc), format/bidirectional (Cf), surrogate (Cs), private-use (Co), and
# line/paragraph separator (Zl, Zp) characters can spoof file names or drive a terminal.
_UNSAFE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Zl", "Zp"})
_KEPT_WHITESPACE = frozenset({"\n", "\t"})


def has_unsafe_characters(value: str) -> bool:
    """Return True when the text contains control, bidirectional, or separator characters."""
    return any(unicodedata.category(character) in _UNSAFE_CATEGORIES for character in value)


def strip_unsafe_characters(value: str) -> str:
    """Remove characters that can spoof displayed text or inject terminal control sequences.

    Newlines and tabs are preserved so callers can still collapse whitespace themselves.
    """
    return "".join(
        character
        for character in value
        if character in _KEPT_WHITESPACE or unicodedata.category(character) not in _UNSAFE_CATEGORIES
    )
