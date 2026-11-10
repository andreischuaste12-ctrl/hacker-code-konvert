"""Generate a host-architecture BPF filter using the system libseccomp."""

from __future__ import annotations

import ctypes
import ctypes.util
import errno
import functools
import tempfile
from typing import BinaryIO

DENIED_SYSCALLS = (
    "unshare",
    "setns",
    "fsopen",
    "fsconfig",
    "fsmount",
    "fspick",
    "move_mount",
    "open_tree",
    "mount_setattr",
    "pivot_root",
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
    "open_by_handle_at",
    "kexec_load",
    "kexec_file_load",
    "init_module",
    "finit_module",
    "delete_module",
    "ptrace",
    "process_vm_readv",
    "process_vm_writev",
    "mount",
    "umount2",
    "bpf",
    "userfaultfd",
    "keyctl",
    "add_key",
    "request_key",
    "perf_event_open",
)
SCMP_ACT_ALLOW = 0x7FFF0000
SCMP_ACT_ERRNO = 0x00050000
SCMP_CMP_NE = 1
SCMP_CMP_MASKED_EQ = 7
CLONE_NEWUSER = 0x10000000
AF_UNIX = 1
# libseccomp returns -1 for a name it does not know; other negative values are pseudo-numbers
# for calls that exist on another architecture and are safe to pass to seccomp_rule_add.
UNKNOWN_SYSCALL = -1


def _library() -> ctypes.CDLL:
    library = ctypes.util.find_library("seccomp")
    if library is None:
        raise OSError("libseccomp is required for scanner isolation")
    lib = ctypes.CDLL(library, use_errno=True)
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    return lib


@functools.cache
def unresolved_syscalls() -> list[str]:
    """Denied names the installed libseccomp cannot express; reported so the gap is never silent."""
    try:
        lib = _library()
    except OSError:
        return []
    return [
        name
        for name in DENIED_SYSCALLS
        if lib.seccomp_syscall_resolve_name(name.encode()) == UNKNOWN_SYSCALL
    ]


def filter_file() -> BinaryIO:
    lib = _library()
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_release.argtypes = [ctypes.c_void_p]
    lib.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    lib.seccomp_export_bpf.argtypes = [ctypes.c_void_p, ctypes.c_int]
    context = lib.seccomp_init(SCMP_ACT_ALLOW)  # libseccomp checks the architecture itself.
    if not context:
        raise OSError("seccomp_init failed")
    output = tempfile.TemporaryFile()
    try:
        for syscall in DENIED_SYSCALLS:
            number = lib.seccomp_syscall_resolve_name(syscall.encode())
            if number == UNKNOWN_SYSCALL:
                continue  # Listed by unresolved_syscalls() and recorded in the run.
            if number >= 0 and lib.seccomp_rule_add(context, SCMP_ACT_ERRNO | errno.EPERM, number, 0) != 0:
                raise OSError(f"Could not deny syscall {syscall}")

        class Argument(ctypes.Structure):
            _fields_ = [
                ("arg", ctypes.c_uint),
                ("op", ctypes.c_int),
                ("datum_a", ctypes.c_uint64),
                ("datum_b", ctypes.c_uint64),
            ]

        lib.seccomp_rule_add_array.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_int,
            ctypes.c_uint,
            ctypes.POINTER(Argument),
        ]
        clone = lib.seccomp_syscall_resolve_name(b"clone")
        comparison = Argument(0, SCMP_CMP_MASKED_EQ, CLONE_NEWUSER, CLONE_NEWUSER)
        if (
            lib.seccomp_rule_add_array(
                context, SCMP_ACT_ERRNO | errno.EPERM, clone, 1, ctypes.byref(comparison)
            )
            != 0
        ):
            raise OSError("Could not restrict clone namespaces")
        clone3 = lib.seccomp_syscall_resolve_name(b"clone3")
        if clone3 >= 0 and lib.seccomp_rule_add(context, SCMP_ACT_ERRNO | errno.ENOSYS, clone3, 0) != 0:
            raise OSError("Could not disable clone3")
        # Allow only AF_UNIX (needed for runtime self-pipes). The comparison covers the whole
        # 64-bit register: the kernel reads the domain as a 32-bit int, so an equality denylist is
        # bypassed by setting the upper bits, while "anything other than exactly 1" is not.
        for syscall in ("socket", "socketpair"):
            number = lib.seccomp_syscall_resolve_name(syscall.encode())
            comparison = Argument(0, SCMP_CMP_NE, AF_UNIX, 0)
            if (
                lib.seccomp_rule_add_array(
                    context, SCMP_ACT_ERRNO | errno.EPERM, number, 1, ctypes.byref(comparison)
                )
                != 0
            ):
                raise OSError("Could not deny network socket domains")
        if lib.seccomp_export_bpf(context, output.fileno()) != 0:
            raise OSError("seccomp BPF export failed")
        output.seek(0)
        return output
    except BaseException:
        output.close()
        raise
    finally:
        lib.seccomp_release(context)
