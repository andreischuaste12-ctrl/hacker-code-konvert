from __future__ import annotations

import os
import shutil

import pytest

from hacker_code_konvert.sandbox import bubblewrap_supported


def _unavailable(reason: str) -> None:
    """Skip locally, but fail where the integration environment is mandatory (CI).

    A silently skipped integration test would let the sandbox and scanner paths go unverified.
    """
    if os.environ.get("HCK_REQUIRE_INTEGRATION") == "1":
        pytest.fail(f"integration prerequisite missing: {reason}", pytrace=False)
    pytest.skip(reason)


@pytest.fixture
def require_semgrep() -> None:
    if not shutil.which("semgrep"):
        _unavailable("Semgrep is required")


@pytest.fixture
def require_sandbox() -> None:
    if not bubblewrap_supported():
        _unavailable("usable bubblewrap namespaces are required")


@pytest.fixture
def unavailable():
    """Report a missing integration prerequisite discovered inside a test."""
    return _unavailable
