from __future__ import annotations

import sys

from hacker_code_konvert.sandbox import run_limited


def test_timeout_is_recorded() -> None:
    result = run_limited(
        [sys.executable, "-c", "import time; time.sleep(5)"],
        timeout_seconds=1,
        memory_bytes=256 * 1024 * 1024,
        output_bytes=1024,
    )
    assert result.timed_out is True


def test_output_limit_is_recorded() -> None:
    result = run_limited(
        [sys.executable, "-c", "print('x' * 100000)"],
        timeout_seconds=5,
        memory_bytes=256 * 1024 * 1024,
        output_bytes=1024,
    )
    assert result.output_limited is True
