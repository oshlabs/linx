# Linx.Seccomp references

The kernel docs and man pages this subsystem encodes. Cite specific
sections in the source when interpretation is non-obvious.

## Man pages

- **`seccomp(2)`** — the canonical reference for the
  `seccomp(SECCOMP_SET_MODE_FILTER, flags, &fprog)` syscall. The
  flags (`SECCOMP_FILTER_FLAG_TSYNC`, `SECCOMP_FILTER_FLAG_LOG`,
  `SECCOMP_FILTER_FLAG_SPEC_ALLOW`, etc.), the return-value
  conventions, the error semantics.
- **`seccomp_load(3)`, `seccomp_init(3)`, etc.** — libseccomp's
  surface. Linx does **not** use libseccomp; we cite these for
  conceptual reference (their model shaped a lot of seccomp
  usage in the wild) but we ship a pure-Elixir cBPF generator.
- **`prctl(2)`** — specifically:
  - `PR_GET_SECCOMP`, `PR_SET_SECCOMP` — older interface for
    seccomp (still works; `seccomp(2)` is the preferred modern
    interface because it supports flags).
  - `PR_SET_NO_NEW_PRIVS`, `PR_GET_NO_NEW_PRIVS` — the bit that
    seccomp installs depend on if unprivileged.
- **`bpf(2)`** — adjacent. cBPF is the older "classic BPF" format
  seccomp accepts; eBPF (what `bpf(2)` itself manipulates) is
  different. Seccomp filters can also be eBPF programs since
  Linux 6.9 (very recent; Linx targets cBPF for now).
- **`proc(5)`** — the `Seccomp:` line in `/proc/<pid>/status`
  documents the mode (0=disabled, 1=strict, 2=filter).

## Kernel documentation

- **`Documentation/userspace-api/seccomp_filter.rst`** — the
  canonical kernel doc. Especially:
  - "Filter programming" — the `seccomp_data` structure layout
    that cBPF reads from (architecture, syscall_nr, args).
  - "Filter return actions" — full semantics of every
    `SECCOMP_RET_*` action.
- **`include/uapi/linux/seccomp.h`** — UAPI header with
  `SECCOMP_RET_*` constants, the `SECCOMP_FILTER_FLAG_*` bits,
  the `seccomp_data` and `seccomp_notif_*` struct definitions.
- **`include/uapi/linux/filter.h`** — the cBPF instruction
  format (`struct sock_filter`, `struct sock_fprog`, the BPF
  opcode constants).
- **`include/uapi/linux/bpf_common.h`** — the BPF opcode
  bit-encoding (`BPF_LD`, `BPF_W`, `BPF_ABS`, `BPF_JMP`,
  `BPF_JEQ`, `BPF_RET`, `BPF_K`, `BPF_A`, …).
- **`include/uapi/linux/audit.h`** — the `AUDIT_ARCH_*`
  constants used in seccomp filters (e.g.
  `AUDIT_ARCH_X86_64 = 0xC000003E`,
  `AUDIT_ARCH_AARCH64 = 0xC00000B7`).

## Syscall number sources

These are the canonical references for the `Linx.Seccomp.Syscalls`
hand-curated table. See `Linx.Seccomp` "Extending the
syscall table" for the procedure.

- **x86_64:** `arch/x86/entry/syscalls/syscall_64.tbl` in the
  kernel source. Also exposed as
  `/usr/include/asm/unistd_64.h` on most distros.
- **aarch64:** `include/uapi/asm-generic/unistd.h` in the kernel
  source. aarch64 uses the generic syscall table.

The web-readable upstream:
- https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_64.tbl
- https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/unistd.h

## Adjacent userspace tooling (background, not implementation)

- **`libseccomp`** — the canonical userspace seccomp library. We
  don't link against it (pure Elixir + the underlying syscall
  are sufficient for our needs), but its API model (`seccomp_init`,
  `seccomp_rule_add`, `seccomp_load`) shaped much of the seccomp
  ecosystem.
- **`scmp_sys_resolver(1)`** — libseccomp utility for resolving
  syscall name ↔ number. Useful for cross-checking the Linx
  syscall table.
- **`seccomp-tools`** — third-party tool for disassembling
  seccomp filters from binaries. Useful for cross-checking the
  Linx compiler's output.
- **`bpfc(8)`** — part of iproute2. Compiles cBPF assembly to
  binary. Useful for hand-verifying golden-byte tests.

## Reference filters in the wild

- **Docker default seccomp profile** —
  https://github.com/moby/moby/blob/master/profiles/seccomp/default.json
  (the JSON form). Denies ~50 dangerous syscalls; allows
  everything else. The shape Silo's JSON adapter will target.
- **runc's default seccomp profile** — same model as Docker's;
  the underlying mechanism.
- **Chrome's renderer-process sandbox** —
  `sandbox/linux/seccomp-bpf-helpers/` in the Chromium tree.
  ~30-syscall allow-list per renderer.
- **systemd's `SystemCallFilter=`** — service unit option that
  compiles to a seccomp filter. Different DSL but same kernel
  primitive.

## In-repo cross-references

- `Linx.Process` — the checkpoint protocol that `Linx.Seccomp`
  hooks into, adding one new agent command to that protocol.
- `Linx.Capabilities` — the commit pattern `Linx.Seccomp`
  mirrors exactly (per-thread syscalls applied by the child
  agent at the checkpoint).
- `lib/linx/capabilities.ex` — pattern for the public verb +
  state-machine guards.
- `lib/linx/capabilities/error.ex` — pattern for
  `Linx.Seccomp.Error`'s shape and Exception impl.
- `c_src/linx_process.c` — `child_read_command()` and
  `await_proceed()` are where the new branches land.

## Out of scope — pointers for future work

- **eBPF-based seccomp filters** — Linux 6.9+. More expressive
  than cBPF (loops, maps, helper functions). A future
  `Linx.Seccomp.EBpf` might layer on top.
- **`SECCOMP_RET_USER_NOTIF`** — kernel-to-userspace decision
  delegation. Documented in `seccomp_unotify(2)`. A future
  sibling module.
- **`PTRACE_SECCOMP_GET_FILTER`** — extracting an installed
  filter from a running process via ptrace. See `ptrace(2)`.
  Niche; requires `CAP_SYS_PTRACE`.
- **systemd's exec-filter DSL** — if Linx ever wants a
  systemd-compat filter representation, the DSL is documented
  in `systemd.exec(5)` under `SystemCallFilter=`.
