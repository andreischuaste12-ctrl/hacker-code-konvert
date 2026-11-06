from __future__ import annotations

import os
import resource
import shutil
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass
class CommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    duration_ms: int
    timed_out: bool = False
    output_limited: bool = False


class SandboxUnavailable(RuntimeError):
    pass


def bubblewrap_path() -> str:
    executable = shutil.which("bwrap")
    if not executable:
        raise SandboxUnavailable("bubblewrap is required for scanner isolation")
    return executable


def bubblewrap_supported() -> bool:
    try:
        executable = bubblewrap_path()
        result = subprocess.run(
            [
                executable,
                "--ro-bind",
                "/usr",
                "/usr",
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--unshare-net",
                "--",
                "/usr/bin/true",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=5,
            env={"PATH": "/usr/bin:/bin"},
        )
    except (OSError, subprocess.TimeoutExpired, SandboxUnavailable):
        return False
    return result.returncode == 0


def build_bubblewrap_command(
    command: list[str],
    *,
    staged_root: Path,
    rules_file: Path,
) -> list[str]:
    bwrap = bubblewrap_path()
    wrapped = [
        bwrap,
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--dir",
        "/home",
        "--dir",
        "/rules",
        "--ro-bind",
        str(staged_root),
        "/target",
        "--ro-bind",
        str(rules_file),
        "/rules/python-security.yml",
        "--chdir",
        "/target",
    ]

    for system_path in ("/usr", "/bin", "/lib", "/lib64", "/opt"):
        path = Path(system_path)
        if path.exists():
            wrapped.extend(["--ro-bind", system_path, system_path])

    executable = Path(command[0]).resolve(strict=True)
    if not any(executable.is_relative_to(Path(base)) for base in ("/usr", "/bin", "/opt")):
        prefix = executable.parent.parent
        wrapped.extend(["--ro-bind", str(prefix), str(prefix)])

    wrapped.extend(["--", *command])
    return wrapped


def _set_limits(memory_bytes: int, cpu_seconds: int, output_bytes: int) -> None:
    resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 1))
    resource.setrlimit(resource.RLIMIT_FSIZE, (output_bytes, output_bytes))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    os.umask(0o077)


def run_limited(
    command: list[str],
    *,
    timeout_seconds: int,
    memory_bytes: int,
    output_bytes: int,
) -> CommandResult:
    environment = {
        "HOME": "/home",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "SEMGREP_SEND_METRICS": "off",
    }
    started = time.monotonic()
    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=stdout_file,
            stderr=stderr_file,
            env=environment,
            close_fds=True,
            start_new_session=True,
            preexec_fn=lambda: _set_limits(memory_bytes, timeout_seconds, output_bytes),
        )
        timed_out = False
        try:
            returncode = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGKILL)
            returncode = process.wait()

        duration_ms = int((time.monotonic() - started) * 1000)
        stdout_size = stdout_file.tell()
        stderr_size = stderr_file.tell()
        output_limited = stdout_size >= output_bytes or stderr_size >= output_bytes
        stdout_file.seek(0)
        stderr_file.seek(0)
        stdout = stdout_file.read(output_bytes)
        stderr = stderr_file.read(output_bytes)

    return CommandResult(
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        duration_ms=duration_ms,
        timed_out=timed_out,
        output_limited=output_limited,
    )
