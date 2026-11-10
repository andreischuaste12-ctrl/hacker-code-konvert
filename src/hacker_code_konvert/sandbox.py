from __future__ import annotations

import os
import platform
import re
import resource
import shutil
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Directories mounted read-only so the scanner runtime can load libraries and configuration.
SYSTEM_MOUNTS = ("/usr", "/bin", "/lib", "/lib64")
# Locations from which a scanner executable needs no additional mount.
SYSTEM_EXECUTABLE_BASES = ("/usr", "/bin")
# Host configuration files the dynamic loader and runtimes read. Account databases are not exposed.
ETC_FILES = ("ld.so.cache", "localtime", "ssl/certs/ca-certificates.crt")
# Every writable location inside the sandbox is a size-capped tmpfs. The sandbox root and /dev are
# remounted read-only, so these caps bound all memory the scanner can consume through files.
DEFAULT_SCRATCH_BYTES = 256 * 1024**2
HOME_BYTES = 16 * 1024**2
SHARED_MEMORY_BYTES = 64 * 1024**2
DEFAULT_MAX_PROCESSES = 256
PRLIMIT_CANDIDATES = ("/usr/bin/prlimit", "/bin/prlimit")
# RLIMIT_NPROC is accounted per user namespace from Linux 5.14 on; before that it counts every
# process of the host user and cannot be used as a per-sandbox limit.
NAMESPACED_NPROC_KERNEL = (5, 14)


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


def bubblewrap_version() -> str | None:
    try:
        result = subprocess.run(
            [bubblewrap_path(), "--version"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=5,
            cwd="/",
            env={"PATH": "/usr/bin:/bin"},
        )
    except (OSError, subprocess.TimeoutExpired, SandboxUnavailable):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.decode("utf-8", errors="replace").strip() or None


def bubblewrap_supported() -> bool:
    """Check that bubblewrap can start the same kind of namespaces the scanner run needs."""
    try:
        executable = bubblewrap_path()
        true_binary = shutil.which("true")
        if not true_binary:
            return False
        command = [
            executable,
            "--unshare-all",
            "--unshare-user",
            "--disable-userns",
            "--cap-drop",
            "ALL",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
        ]
        for system_path in ("/usr", "/bin", "/lib", "/lib64"):
            if Path(system_path).exists():
                command.extend(["--ro-bind", system_path, system_path])
        command.extend(["--", str(Path(true_binary).resolve())])
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=5,
            cwd="/",
            env={"PATH": "/usr/bin:/bin"},
        )
    except (OSError, subprocess.TimeoutExpired, SandboxUnavailable):
        return False
    return result.returncode == 0


def _is_under(path: Path, bases: tuple[str, ...]) -> bool:
    return any(path.is_relative_to(Path(base)) for base in bases)


def _venv_home(config: Path) -> Path | None:
    try:
        for line in config.read_text(encoding="utf-8", errors="replace").splitlines():
            key, separator, value = line.partition("=")
            if separator and key.strip() == "home":
                return Path(value.strip())
    except OSError:
        return None
    return None


def _require_narrow_mount(path: Path) -> Path:
    # Never expose the filesystem root or a top-level directory such as /home or /srv.
    if len(path.parts) < 3:
        raise SandboxUnavailable(f"refusing to mount broad directory for the scanner runtime: {path}")
    return path


def runtime_mounts(executable: Path) -> list[Path]:
    """Return the extra read-only mounts the scanner runtime needs.

    Supported layouts are system locations (/usr, /bin), Python virtual environments, a Python
    installation prefix, and a product directory under /opt (only that directory is mounted, never
    the whole of /opt). Any other layout would require exposing an unrelated directory (for example
    a home directory), so it fails closed instead.
    """
    if _is_under(executable, SYSTEM_EXECUTABLE_BASES):
        return []
    environment_root = executable.parent.parent
    config = environment_root / "pyvenv.cfg"
    if executable.parent.name == "bin" and config.is_file():
        mounts = [_require_narrow_mount(environment_root)]
        interpreter_home = _venv_home(config)
        if interpreter_home is not None and not _is_under(interpreter_home, SYSTEM_EXECUTABLE_BASES):
            mounts.append(_require_narrow_mount(interpreter_home.parent))
        return mounts
    if executable.parent.name == "bin" and any((environment_root / "lib").glob("python*/os.py")):
        return [_require_narrow_mount(environment_root)]
    if executable.is_relative_to("/opt") and len(executable.parts) >= 4:
        return [Path(*executable.parts[:3])]
    raise SandboxUnavailable(
        "the scanner must be installed under /usr, in its own directory under /opt, or inside a "
        f"Python virtual environment; refusing to expose the directory around {executable}"
    )


def _kernel_version() -> tuple[int, int]:
    match = re.match(r"(\d+)\.(\d+)", platform.release())
    return (int(match.group(1)), int(match.group(2))) if match else (0, 0)


def process_limit_prefix(max_processes: int = DEFAULT_MAX_PROCESSES) -> list[str]:
    """Command prefix that caps the number of processes and threads inside the sandbox.

    The limit is applied by ``prlimit`` after Bubblewrap has created the user namespace, where
    RLIMIT_NPROC counts only the sandbox. It is unavailable to the superuser (the kernel exempts
    it), on kernels older than 5.14, and where ``prlimit`` is not installed; the caller records
    that in the run instead of pretending a limit exists.
    """
    if os.geteuid() == 0 or _kernel_version() < NAMESPACED_NPROC_KERNEL:
        return []
    for candidate in PRLIMIT_CANDIDATES:
        if os.access(candidate, os.X_OK):
            return [candidate, f"--nproc={max_processes}:{max_processes}", "--"]
    return []


def build_bubblewrap_command(
    command: list[str],
    *,
    staged_root: Path,
    rules_file: Path | None,
    scratch_bytes: int = DEFAULT_SCRATCH_BYTES,
    max_processes: int = DEFAULT_MAX_PROCESSES,
    read_only_binds: tuple[tuple[Path, str], ...] = (),
) -> list[str]:
    bwrap = bubblewrap_path()
    wrapped = [
        bwrap,
        "--unshare-all",
        "--unshare-user",
        "--disable-userns",
        "--cap-drop",
        "ALL",
        "--die-with-parent",
        "--new-session",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--size",
        str(SHARED_MEMORY_BYTES),
        "--tmpfs",
        "/dev/shm",
        "--size",
        str(scratch_bytes),
        "--tmpfs",
        "/tmp",
        "--size",
        str(HOME_BYTES),
        "--tmpfs",
        "/home",
        "--ro-bind",
        str(staged_root),
        "/target",
        "--chdir",
        "/target",
    ]
    if rules_file is not None:
        wrapped.extend(["--dir", "/rules", "--ro-bind", str(rules_file), f"/rules/{rules_file.name}"])

    for system_path in SYSTEM_MOUNTS:
        path = Path(system_path)
        if path.exists():
            wrapped.extend(["--ro-bind", system_path, system_path])

    for name in ETC_FILES:
        source = Path("/etc") / name
        if source.exists():
            wrapped.extend(["--ro-bind", str(source.resolve()), f"/etc/{name}"])

    executable = Path(command[0]).resolve(strict=True)
    for mount in runtime_mounts(executable):
        wrapped.extend(["--ro-bind", str(mount), str(mount)])
    for source, destination in read_only_binds:
        wrapped.extend(["--ro-bind", str(source), destination])

    # Bubblewrap builds the sandbox on tmpfs mounts that are otherwise writable and limited only by
    # host memory. Make the root and /dev read-only after everything above is in place.
    wrapped.extend(["--remount-ro", "/dev", "--remount-ro", "/"])
    wrapped.extend(["--", *process_limit_prefix(max_processes), *command])
    return wrapped


PROCESS_LIMIT_ABSENT = (
    "not enforced (running as root, kernel older than 5.14, or prlimit unavailable); "
    "use a delegated cgroup"
)


def process_limit_description(max_processes: int = DEFAULT_MAX_PROCESSES) -> str:
    controls = []
    if os.environ.get("HCK_CGROUP_PARENT"):
        controls.append("delegated cgroup pids.max")
    if process_limit_prefix(max_processes):
        controls.append(f"RLIMIT_NPROC {max_processes} inside the sandbox user namespace")
    return "; ".join(controls) or PROCESS_LIMIT_ABSENT


def sandbox_metadata(
    *, scratch_bytes: int = DEFAULT_SCRATCH_BYTES, max_processes: int = DEFAULT_MAX_PROCESSES
) -> dict[str, Any]:
    """Describe the isolation controls that build_bubblewrap_command applies."""
    from hacker_code_konvert.seccomp import unresolved_syscalls

    return {
        "tool": "bubblewrap",
        "version": bubblewrap_version(),
        "namespaces": "user, mount, pid, ipc, uts, cgroup, network",
        "network": "disabled",
        "capabilities": "dropped",
        "target": "read-only",
        "filesystem": (
            "read-only root and /dev; writable tmpfs only at /tmp "
            f"({scratch_bytes} bytes), /home ({HOME_BYTES} bytes) and /dev/shm ({SHARED_MEMORY_BYTES} bytes)"
        ),
        "seccomp": (
            "libseccomp filter; every socket family except AF_UNIX and dangerous kernel "
            "interfaces denied"
        ),
        "seccomp_unresolved_syscalls": unresolved_syscalls(),
        "process_limit": process_limit_description(max_processes),
    }


def _set_limits(memory_bytes: int, cpu_seconds: int, output_bytes: int) -> None:  # pragma: no cover
    resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 1))
    resource.setrlimit(resource.RLIMIT_FSIZE, (output_bytes, output_bytes))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
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
        "SEMGREP_ENABLE_VERSION_CHECK": "0",
        "GOMEMLIMIT": "512MiB",
        "GOMAXPROCS": "1",
    }
    started = time.monotonic()
    from contextlib import ExitStack

    from hacker_code_konvert.cgroups import delegated_tasks
    from hacker_code_konvert.seccomp import filter_file

    with ExitStack() as resources:
        cgroup_procs = resources.enter_context(delegated_tasks())

        def child_limits() -> None:  # pragma: no cover
            if cgroup_procs is not None:
                cgroup_procs.write_text(str(os.getpid()))
            _set_limits(memory_bytes, timeout_seconds, output_bytes)

        inherited: tuple[int, ...] = ()
        if Path(command[0]).name == "bwrap":
            bpf = resources.enter_context(filter_file())
            index = command.index("--")
            command = command[:index] + ["--seccomp", str(bpf.fileno())] + command[index:]
            inherited = (bpf.fileno(),)
        stdout_file = resources.enter_context(tempfile.TemporaryFile())
        stderr_file = resources.enter_context(tempfile.TemporaryFile())
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=stdout_file,
            stderr=stderr_file,
            env=environment,
            cwd="/",
            close_fds=True,
            pass_fds=inherited,
            start_new_session=True,
            preexec_fn=child_limits,
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
