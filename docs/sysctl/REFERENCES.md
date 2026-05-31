# Linx.Sysctl references

The kernel docs and man pages this subsystem encodes. Cite specific
sections in the source when interpretation is non-obvious.

## Man pages

- **`sysctl(8)`** — the userspace tool whose surface this subsystem
  mirrors. The `-a` / `-w` / `-p` semantics, dot-form key naming,
  and the `--system` workflow that walks `/etc/sysctl.d/*.conf` are
  all here. Linx exposes the `-r` / `-w` equivalents (read/write);
  the `--system` conf-file applier is deferred to a consumer.
- **`proc(5)`** — the canonical reference for `/proc/sys/`, the
  layout of subtrees (`net/`, `kernel/`, `vm/`, `fs/`, …), and the
  per-namespace routing rules. The "Files and directories" section
  under `/proc/sys/` is the source of truth.
- **`namespaces(7)`** — overview of which namespaces own which
  parts of the sysctl tree (network for `net.*`, UTS for
  `kernel.hostname`, IPC for `kernel.shm*` / `kernel.msg*` /
  `kernel.sem` / `fs.mqueue.*`).
- **`network_namespaces(7)`** — specifically the per-netns
  `/proc/sys/net/` semantics that make `net.ipv4.ip_forward`
  meaningful inside a container.
- **`uts_namespaces(7)`**, **`ipc_namespaces(7)`** — analogous
  references for the UTS / IPC subtrees.
- **`setns(2)`** — the syscall the S3 NIF wraps for cross-namespace
  reads and writes. Particularly the "Description" of valid
  namespace types and the "Notes" on what passing `0` for the
  second argument means (autodetect from the file's type).

## Kernel documentation

- **`Documentation/admin-guide/sysctl/`** — the kernel's own per-
  subtree docs:
  - `kernel.rst` — `kernel.*` knobs (hostname, printk, panic,
    randomize_va_space, …)
  - `net.rst` — top-level `net.*` knobs; per-protocol specifics
    live alongside the protocol's docs
  - `vm.rst` — `vm.*` knobs (swappiness, overcommit, dirty_ratio,
    …)
  - `fs.rst` — `fs.*` knobs (file-max, inotify limits, mqueue, …)
  - `user.rst` — per-userns `user.max_*_namespaces` nesting limits
  - `abi.rst` — `abi.*`
- **`Documentation/networking/ip-sysctl.rst`** — the exhaustive
  reference for every `net.ipv4.*` and `net.ipv6.*` knob.
- **`Documentation/networking/...sysctl.rst`** — analogous per-
  subsystem files (`tcp.rst`, `nf_conntrack-sysctl.rst`, …).

## Adjacent userspace tooling (for context, not implementation)

- **`procps-ng`** (`sysctl(8)`) — the canonical userspace tool.
  Worth skimming the source for edge cases in key normalization
  (the `/` vs `.` separator interchangeability, quoting of values
  containing whitespace).
- **`systemd-sysctl(8)`** — systemd's variant of the conf-file
  applier; same `sysctl.d` semantics with some extensions.
  Relevant as a reference design for an eventual consumer-side
  conf-file layer (not in Linx).
- **`nerves_system_*` defconfigs** — for the Nerves use case, the
  set of `CONFIG_*` kernel options that determines which sysctls
  exist on a given device. `Linx.Sysctl.list/0` (S2) is the way to
  discover what's actually present at runtime.

## In-repo cross-references

- `Linx.Mount` — the `:in :: :self | {:pid, n} | {:path, p}`
  option shape and the setns-on-a-throwaway-pthread pattern.
  `Linx.Sysctl`'s S3 NIF is structurally identical.
- `lib/linx/mount.ex` and `c_src/linx_mount.c` — the precedent the
  S3 implementation will mirror end-to-end.
- `Linx.User` — the pure-Elixir-procfs precedent for S0–S2
  (no NIF, no Port).
- `lib/linx/cgroup.ex` — another pure-procfs subsystem, useful as
  a reference for `%Linx.Cgroup.Error{}`-style structured errors
  that `Linx.Sysctl.Error` will mirror in S1.
