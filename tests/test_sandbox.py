from __future__ import annotations

import sys
from pathlib import Path

from hacker_code_konvert.sandbox import build_bubblewrap_command, run_limited


def test_bubblewrap_command_has_networkless_read_only_boundary(tmp_path: Path, monkeypatch) -> None:
    staged = tmp_path / "target"
    staged.mkdir()
    rules = tmp_path / "rules.yml"
    rules.write_text("rules: []\n", encoding="utf-8")
    monkeypatch.setattr("hacker_code_konvert.sandbox.bubblewrap_path", lambda: "/usr/bin/bwrap")

    command = build_bubblewrap_command(["/usr/bin/true"], staged_root=staged, rules_file=rules)

    assert "--unshare-all" in command
    assert command[command.index("--tmpfs") + 1] == "/tmp"
    assert command[command.index("/home") - 1] == "--tmpfs"
    assert ["--ro-bind", str(staged), "/target"] == command[command.index(str(staged)) - 1 :][:3]


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
