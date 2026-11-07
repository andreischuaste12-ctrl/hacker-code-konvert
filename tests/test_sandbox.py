from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from hacker_code_konvert.sandbox import (
    SandboxUnavailable,
    _require_narrow_mount,
    build_bubblewrap_command,
    run_limited,
    runtime_mounts,
)


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


def _fake_virtualenv(base: Path, *, interpreter_home: str = "/usr/bin") -> Path:
    environment = base / "tools" / "venv"
    (environment / "bin").mkdir(parents=True)
    (environment / "pyvenv.cfg").write_text(f"home = {interpreter_home}\n", encoding="utf-8")
    executable = environment / "bin" / "semgrep"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    executable.chmod(0o755)
    return executable


def test_command_drops_all_capabilities(tmp_path: Path, monkeypatch) -> None:
    staged = tmp_path / "target"
    staged.mkdir()
    rules = tmp_path / "rules.yml"
    rules.write_text("rules: []\n", encoding="utf-8")
    monkeypatch.setattr("hacker_code_konvert.sandbox.bubblewrap_path", lambda: "/usr/bin/bwrap")

    command = build_bubblewrap_command(["/usr/bin/true"], staged_root=staged, rules_file=rules)

    index = command.index("--cap-drop")
    assert command[index + 1] == "ALL"
    assert "--unshare-all" in command


def test_system_installation_needs_no_extra_mount() -> None:
    assert runtime_mounts(Path("/usr/bin/semgrep")) == []
    assert runtime_mounts(Path("/opt/hostedtoolcache/Python/3.12.0/x64/bin/semgrep")) == []


def test_virtualenv_installation_mounts_only_the_environment(tmp_path: Path) -> None:
    executable = _fake_virtualenv(tmp_path)
    assert runtime_mounts(executable.resolve()) == [executable.resolve().parent.parent]


def test_interpreter_outside_system_directories_is_mounted_narrowly(tmp_path: Path) -> None:
    home_bin = tmp_path / "pyenv" / "versions" / "3.12" / "bin"
    home_bin.mkdir(parents=True)
    executable = _fake_virtualenv(tmp_path, interpreter_home=str(home_bin))
    mounts = runtime_mounts(executable.resolve())
    assert mounts == [executable.resolve().parent.parent, home_bin.parent]


def test_unsupported_layout_fails_closed_instead_of_exposing_a_home_directory(tmp_path: Path) -> None:
    # Previously the grandparent directory was mounted, which exposed all of <home> for ~/bin/semgrep.
    home = tmp_path / "home" / "alice"
    (home / "bin").mkdir(parents=True)
    (home / ".ssh").mkdir()
    executable = home / "bin" / "semgrep"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    with pytest.raises(SandboxUnavailable):
        runtime_mounts(executable.resolve())


def test_broad_mounts_are_refused() -> None:
    for broad in (Path("/"), Path("/home"), Path("/srv")):
        with pytest.raises(SandboxUnavailable):
            _require_narrow_mount(broad)


@pytest.mark.integration
def test_sandbox_has_no_network_no_capabilities_and_read_only_target(
    tmp_path: Path, require_sandbox, unavailable
) -> None:
    staged = tmp_path / "target"
    staged.mkdir()
    rules = tmp_path / "rules.yml"
    rules.write_text("rules: []\n", encoding="utf-8")
    probe = (
        "import json, socket\n"
        "result = {}\n"
        "try:\n"
        "    socket.create_connection(('192.0.2.1', 9), timeout=2)\n"
        "    result['network'] = 'connected'\n"
        "except OSError:\n"
        "    result['network'] = 'blocked'\n"
        "try:\n"
        "    open('/target/probe', 'w').write('x')\n"
        "    result['target_write'] = 'allowed'\n"
        "except OSError:\n"
        "    result['target_write'] = 'denied'\n"
        "lines = open('/proc/self/status').read().splitlines()\n"
        "status = dict(line.split(':\\t') for line in lines if ':\\t' in line)\n"
        "result['cap_effective'] = status['CapEff'].strip()\n"
        "print(json.dumps(result))\n"
    )
    try:
        wrapped = build_bubblewrap_command(
            [str(Path(sys.executable).resolve()), "-c", probe], staged_root=staged, rules_file=rules
        )
    except SandboxUnavailable:
        unavailable("the test interpreter lives in an unsupported location")
    result = run_limited(wrapped, timeout_seconds=30, memory_bytes=2 * 1024**3, output_bytes=100_000)
    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    observed = json.loads(result.stdout)
    assert observed["network"] == "blocked"
    assert observed["target_write"] == "denied"
    assert int(observed["cap_effective"], 16) == 0
