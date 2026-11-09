"""Generate a host-architecture BPF filter using the system libseccomp."""

from __future__ import annotations

import ctypes
import ctypes.util
import errno
import tempfile
from typing import BinaryIO


def filter_file() -> BinaryIO:
    library = ctypes.util.find_library("seccomp")
    if library is None:
        raise OSError("libseccomp is required for scanner isolation")
    lib = ctypes.CDLL(library, use_errno=True)
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_release.argtypes = [ctypes.c_void_p]
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    lib.seccomp_export_bpf.argtypes = [ctypes.c_void_p, ctypes.c_int]
    context = lib.seccomp_init(0x7FFF0000)  # SCMP_ACT_ALLOW; libseccomp checks architecture.
    if not context:
        raise OSError("seccomp_init failed")
    output = tempfile.TemporaryFile()
    try:
        for syscall in (
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
            "mount",
            "umount2",
            "bpf",
            "userfaultfd",
            "keyctl",
            "add_key",
            "request_key",
            "perf_event_open",
        ):
            number = lib.seccomp_syscall_resolve_name(syscall.encode())
            if number >= 0 and lib.seccomp_rule_add(context, 0x50000 | errno.EPERM, number, 0) != 0:
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
        comparison = Argument(0, 7, 0x10000000, 0x10000000)  # MASKED_EQ CLONE_NEWUSER
        if (
            lib.seccomp_rule_add_array(context, 0x50000 | errno.EPERM, clone, 1, ctypes.byref(comparison))
            != 0
        ):
            raise OSError("Could not restrict clone namespaces")
        clone3 = lib.seccomp_syscall_resolve_name(b"clone3")
        if clone3 >= 0 and lib.seccomp_rule_add(context, 0x50000 | errno.ENOSYS, clone3, 0) != 0:
            raise OSError("Could not disable clone3")
        # Deny network domains while retaining AF_UNIX for Python asyncio self-pipes.
        for syscall in ("socket", "socketpair"):
            number = lib.seccomp_syscall_resolve_name(syscall.encode())
            for domain in (2, 10, 15, 16, 17, 40):  # INET, INET6, NETLINK, PACKET
                comparison = Argument(0, 4, domain, 0)  # SCMP_CMP_EQ
                if (
                    lib.seccomp_rule_add_array(
                        context, 0x50000 | errno.EPERM, number, 1, ctypes.byref(comparison)
                    )
                    != 0
                ):
                    raise OSError("Could not deny network socket domain")
        if lib.seccomp_export_bpf(context, output.fileno()) != 0:
            raise OSError("seccomp BPF export failed")
        output.seek(0)
        return output
    except BaseException:
        output.close()
        raise
    finally:
        lib.seccomp_release(context)
