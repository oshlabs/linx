# Linx.Sysctl references

The kernel docs and man pages this subsystem encodes. Cite specific
sections in the source when interpretation is non-obvious.

## Man pages

- **[`sysctl(8)`](https://man7.org/linux/man-pages/man8/sysctl.8.html)** — the userspace tool whose surface this subsystem
  mirrors. The `-a` / `-w` / `-p` semantics, dot-form key naming,
  and the `--system` workflow that walks `/etc/sysctl.d/*.conf` are
  all here. Linx exposes the `-r` / `-w` equivalents (read/write);
  the `--system` conf-file applier is deferred to a consumer.
- **[`proc(5)`](https://man7.org/linux/man-pages/man5/proc.5.html)** — the canonical reference for `/proc/sys/`, the
  layout of subtrees (`net/`, `kernel/`, `vm/`, `fs/`, …), and the
  per-namespace routing rules. The "Files and directories" section
  under `/proc/sys/` is the source of truth.
- **[`namespaces(7)`](https://man7.org/linux/man-pages/man7/namespaces.7.html)** — overview of which namespaces own which
  parts of the sysctl tree (network for `net.*`, UTS for
  `kernel.hostname`, IPC for `kernel.shm*` / `kernel.msg*` /
  `kernel.sem` / `fs.mqueue.*`).
- **[`network_namespaces(7)`](https://man7.org/linux/man-pages/man7/network_namespaces.7.html)** — specifically the per-netns
  `/proc/sys/net/` semantics that make `net.ipv4.ip_forward`
  meaningful inside a container.
- **[`uts_namespaces(7)`](https://man7.org/linux/man-pages/man7/uts_namespaces.7.html)**, **[`ipc_namespaces(7)`](https://man7.org/linux/man-pages/man7/ipc_namespaces.7.html)** — analogous
  references for the UTS / IPC subtrees.
- **[`setns(2)`](https://man7.org/linux/man-pages/man2/setns.2.html)** — the syscall the cross-namespace NIF wraps for
  reads and writes. Particularly the "Description" of valid
  namespace types and the "Notes" on what passing `0` for the
  second argument means (autodetect from the file's type).

## Kernel documentation

- **[`Documentation/admin-guide/sysctl/`](https://docs.kernel.org/admin-guide/sysctl/index.html)** — the kernel's own per-
  subtree docs:
  - [`kernel.rst`](https://docs.kernel.org/admin-guide/sysctl/kernel.html) — `kernel.*` knobs (hostname, printk, panic,
    randomize_va_space, …)
  - [`net.rst`](https://docs.kernel.org/admin-guide/sysctl/net.html) — top-level `net.*` knobs; per-protocol specifics
    live alongside the protocol's docs
  - [`vm.rst`](https://docs.kernel.org/admin-guide/sysctl/vm.html) — `vm.*` knobs (swappiness, overcommit, dirty_ratio,
    …)
  - [`fs.rst`](https://docs.kernel.org/admin-guide/sysctl/fs.html) — `fs.*` knobs (file-max, inotify limits, mqueue, …)
  - [`user.rst`](https://docs.kernel.org/admin-guide/sysctl/user.html) — per-userns `user.max_*_namespaces` nesting limits
  - [`abi.rst`](https://docs.kernel.org/admin-guide/sysctl/abi.html) — `abi.*`
- **[`Documentation/networking/ip-sysctl.rst`](https://docs.kernel.org/networking/ip-sysctl.html)** — the exhaustive
  reference for every `net.ipv4.*` and `net.ipv6.*` knob.
- **`Documentation/networking/...sysctl.rst`** — analogous per-
  subsystem files (`tcp.rst`, `nf_conntrack-sysctl.rst`, …).

## Adjacent userspace tooling (for context, not implementation)

- **`procps-ng`** ([`sysctl(8)`](https://man7.org/linux/man-pages/man8/sysctl.8.html)) — the canonical userspace tool.
  Worth skimming the source for edge cases in key normalization
  (the `/` vs `.` separator interchangeability, quoting of values
  containing whitespace).
- **[`systemd-sysctl(8)`](https://man7.org/linux/man-pages/man8/systemd-sysctl.8.html)** — systemd's variant of the conf-file
  applier; same `sysctl.d` semantics with some extensions.
  Relevant as a reference design for an eventual consumer-side
  conf-file layer (not in Linx).
- **`nerves_system_*` defconfigs** — for the Nerves use case, the
  set of `CONFIG_*` kernel options that determines which sysctls
  exist on a given device. `Linx.Sysctl.list/0` is the way to
  discover what's actually present at runtime.

## In-repo cross-references

- `Linx.Mount` — the `:in :: :self | {:pid, n} | {:path, p}`
  option shape and the setns-on-a-throwaway-pthread pattern.
  `Linx.Sysctl`'s cross-namespace NIF is structurally identical.
- `lib/linx/mount.ex` and `c_src/linx_mount.c` — the precedent the
  cross-namespace implementation mirrors end-to-end.
- `Linx.User` — the pure-Elixir-procfs precedent
  (no NIF, no Port).
- `lib/linx/cgroup.ex` — another pure-procfs subsystem, useful as
  a reference for `%Linx.Cgroup.Error{}`-style structured errors
  that `Linx.Sysctl.Error` mirrors.
