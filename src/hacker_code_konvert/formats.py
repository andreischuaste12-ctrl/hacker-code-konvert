"""Input selection shared by capture and the scanner adapters.

Selection decides what a scanner is shown, so it is part of the coverage contract: a file that is
not selected is not analyzed. Source files are recognized by suffix, by an interpreter line, or by a
PHP opening tag at the start of the file. They are always staged under the canonical suffix of their
language, so the scanner cannot disagree with the selection.
"""

from __future__ import annotations

import re
from pathlib import Path

LOCKFILES = {
    "package-lock.json",
    "yarn.lock",
    "poetry.lock",
    "Cargo.lock",
    "go.sum",
    "go.mod",
    "composer.lock",
    "Gemfile.lock",
    "pnpm-lock.yaml",
    "Pipfile.lock",
    "pom.xml",
    "gradle.lockfile",
}

PYTHON = "python"
PHP = "php"
# Language name shown in the inventory and canonical staged suffix for each supported language.
SOURCE_LANGUAGES = {PYTHON: ("Python", ".py"), PHP: ("PHP", ".php")}
SOURCE_SUFFIXES = {
    ".py": PYTHON,
    ".pyw": PYTHON,
    ".php": PHP,
    ".phtml": PHP,
    ".pht": PHP,
    ".phps": PHP,
    ".php3": PHP,
    ".php4": PHP,
    ".php5": PHP,
    ".php7": PHP,
    ".php8": PHP,
    ".inc": PHP,
}
# Bytes inspected at the start of a file whose suffix is not a supported source suffix.
SOURCE_SNIFF_BYTES = 512

_PYTHON_INTERPRETER = re.compile(rb"\A#![^\r\n]{0,200}\bpython[0-9.]*\b")
_PHP_INTERPRETER = re.compile(rb"\A#![^\r\n]{0,200}\bphp[0-9.]*\b")
_PHP_OPEN_TAG = re.compile(rb"\A\s*<\?(?:php\b|=)", re.IGNORECASE)

# A Git LFS pointer is a tiny text file with a fixed grammar. Requiring the complete grammar means a
# file that merely starts with the version line (for example a PHP script, whose text before the
# opening tag is plain output) is analyzed as ordinary content instead of being skipped.
LFS_POINTER_MAX_BYTES = 1024
_LFS_POINTER = re.compile(
    rb"\Aversion https://git-lfs\.github\.com/spec/v1\n"
    rb"(?:ext-[0-9]-[A-Za-z0-9._-]{1,64} sha256:[0-9a-f]{64}\n){0,10}"
    rb"oid sha256:[0-9a-f]{64}\n"
    rb"size [0-9]{1,20}\n?\Z"
)


_PLAIN_SUFFIX = re.compile(r"\.[a-z0-9_+-]{1,16}")


def dependency_file(name: str) -> bool:
    name = Path(name).name
    return name in LOCKFILES or (name.startswith("requirements") and name.endswith(".txt"))


def source_language(name: str, head: bytes = b"") -> str | None:
    """Return the supported language of a file, from its suffix or from its first bytes."""
    language = SOURCE_SUFFIXES.get(Path(name).suffix.lower())
    if language:
        return language
    head = head[:SOURCE_SNIFF_BYTES].removeprefix(b"\xef\xbb\xbf")
    if _PYTHON_INTERPRETER.match(head):
        return PYTHON
    if _PHP_INTERPRETER.match(head) or _PHP_OPEN_TAG.match(head):
        return PHP
    return None


def is_lfs_pointer(data: bytes) -> bool:
    """True only for content that is, in full, a Git LFS pointer."""
    return len(data) <= LFS_POINTER_MAX_BYTES and _LFS_POINTER.fullmatch(data) is not None


def neutral_suffix(name: str, language: str | None = None) -> str:
    """Suffix for a staged copy: canonical for supported languages, otherwise a plain known-safe one."""
    if language:
        return SOURCE_LANGUAGES[language][1]
    suffix = Path(name).suffix.lower()
    return suffix if _PLAIN_SUFFIX.fullmatch(suffix) else ".dat"
