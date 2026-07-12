#!/usr/bin/env python3
"""Kernel-acceptance helper for Linx.Seccomp's S1 integration tests.

Reads a cBPF filter blob from the file path given as argv[1], packs
it into struct sock_fprog, sets PR_SET_NO_NEW_PRIVS, and calls
seccomp(SECCOMP_SET_MODE_FILTER, 0, &fprog) — the same syscall the
Linx agent will issue from c_src/linx_process.c in S2.

An optional second argument, ``x32``, invokes an x32-numbered getpid
after installation. Success means the filter killed the child with
SIGSYS before syscall dispatch; an x32-disabled kernel returning ENOSYS
is a failure because it proves the guard did not fire.

Exit codes (consumed by the Elixir test in test/linx/seccomp_test.exs):

    0      — kernel accepted the filter (either the helper exited
             cleanly, or its child was killed by SIGSYS during
             teardown because the filter blocked exit_group — both
             prove the kernel honoured the filter format).

    >0     — kernel rejected the filter; the value is the POSIX
             errno (22 = EINVAL is the usual "malformed BPF" code).

Forks so the parent can report the verdict regardless of what the
filter does to the child's exit syscall.

Not part of the Linx library — only used by the test harness.
"""

import ctypes
import os
import sys


PR_SET_NO_NEW_PRIVS = 38
SECCOMP_SET_MODE_FILTER = 1

# Arch-specific SYS_seccomp number — Linx's syscall table covers the
# same arches the helper supports.
_SYS_SECCOMP = {"x86_64": 317, "aarch64": 277}


def main():
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "x32"):
        print("usage: seccomp_check.py <bpf-file> [x32]", file=sys.stderr)
        sys.exit(255)

    mode = sys.argv[2] if len(sys.argv) == 3 else "install"

    arch = os.uname().machine
    if arch not in _SYS_SECCOMP:
        print(f"unsupported arch: {arch}", file=sys.stderr)
        sys.exit(255)

    if mode == "x32" and arch != "x86_64":
        print("x32 probe requires x86_64", file=sys.stderr)
        sys.exit(77)

    sys_seccomp = _SYS_SECCOMP[arch]

    with open(sys.argv[1], "rb") as f:
        bpf = f.read()

    n_insns = len(bpf) // 8
    if n_insns * 8 != len(bpf):
        print(f"bpf blob is not a multiple of 8 bytes: {len(bpf)}", file=sys.stderr)
        sys.exit(255)

    libc = ctypes.CDLL("libc.so.6", use_errno=True)

    class sock_fprog(ctypes.Structure):
        _fields_ = [
            ("len", ctypes.c_ushort),
            ("filter", ctypes.c_void_p),
        ]

    buf = ctypes.create_string_buffer(bpf, len(bpf))
    fprog = sock_fprog(n_insns, ctypes.cast(buf, ctypes.c_void_p).value)

    pid = os.fork()
    if pid == 0:
        # Child: NNP + install. Exit cleanly on success or with errno
        # on failure. os._exit avoids running atexit handlers (some of
        # which might issue blocked syscalls).
        libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
        r = libc.syscall(sys_seccomp, SECCOMP_SET_MODE_FILTER, 0, ctypes.byref(fprog))
        if r == 0:
            if mode == "x32":
                # __X32_SYSCALL_BIT | __NR_getpid. The compiler's unsigned
                # JGE guard must return SECCOMP_RET_KILL_PROCESS first.
                libc.syscall(0x40000000 | 39)
                os._exit(125)
            else:
                os._exit(0)
        else:
            os._exit(ctypes.get_errno())
    else:
        # Parent: wait for child, translate the wait status to an exit
        # code the test harness can read.
        _, status = os.waitpid(pid, 0)
        if os.WIFEXITED(status):
            sys.exit(os.WEXITSTATUS(status))
        elif os.WIFSIGNALED(status) and mode == "x32":
            sys.exit(0 if os.WTERMSIG(status) == 31 else 126)
        elif os.WIFSIGNALED(status):
            # Killed by signal — filter installed successfully but the
            # teardown syscall (likely exit_group) was blocked.
            # That's still "kernel accepted the filter."
            sys.exit(0)
        else:
            sys.exit(255)


if __name__ == "__main__":
    main()
