# Changelog

All notable changes to Linx are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-05-31

Declarative configuration via reconciliation: describe the desired kernel state
and converge the kernel onto it — idempotent and self-healing across drift,
crashes, and reboots. Built on the `pull` / `diff` / `push(mode: :reconcile)` /
`subscribe` template `Linx.Netfilter` set in 0.1.0, extended to rtnl, sysctl,
and cgroup limits, with a thin opt-in control loop on top. All additive — no
breaking changes.

### Added

- **`Linx.Netlink.Rtnl` reconciliation** — per-resource `Linx.Netlink.Rtnl.Diff`
  (two-way `RTPROT`-tag ownership for routes, three-way `last_applied` ownership
  for everything else), `NLM_F_REPLACE` in-place updates with settable route
  table / protocol / metric, single-shot `Linx.Netlink.Rtnl.Reconcile` for
  addresses and routes, and `Linx.Netlink.Rtnl.Monitor` — a multicast
  change-notification GenServer (the `ip monitor` equivalent; `ENOBUFS` →
  `:resync_needed`).
- **`Linx.Sysctl.Reconcile`** and **`Linx.Cgroup.Reconcile`** — single-shot
  declarative reconciliation (three-way `last_applied` ownership, best-effort
  apply) for sysctl knobs and cgroup limit knobs.
- **`Linx.Reconcile`** — a thin, opt-in, single-subsystem control loop (periodic
  timer resync plus low-latency Monitor wakeups) driven through the
  **`Linx.Reconcile.Source`** plug-in contract, with adapters for sysctl, rtnl,
  and cgroup limits. No `Application` boot side effect, no singleton — you add it
  to your own supervision tree.
- **`Linx.Process` supervision ergonomics** — `child_spec/1`, restart-friendly
  exit semantics (`linger`, `auto_proceed`), and reliable OS-process reaping in
  `terminate` so a supervised restart never leaks the old child.
- Docs: `docs/reconcile/PLAN.md` (design) and `docs/reconcile/EXAMPLES.md`
  (overview), plus reconcile sections in each subsystem's `EXAMPLES.md`.

### Fixed

- `Linx.NFT` tokenizer: a digit-led first IPv6 hextet ending in `d`
  followed by `:` (e.g. `830d:…`) was misread as the time literal
  "830 days" — `d` is the only time unit that is also a hex digit. Such
  hextets now scan as IPv6 addresses. Found by a round-trip property test.

## [0.1.0] - 2026-05-31

First release. Ten Linux-kernel-interface subsystems, exposed as idiomatic
Elixir, that all compose through the `Linx.Process` checkpoint.

### Added

- **`Linx.Process`** — `clone(2)` with namespace flags, `setns(2)`, signals,
  `waitpid(2)`, and stdio plumbing (inherit / `/dev/null` / AF_UNIX / PTY),
  driven by an external C agent (a Port) with a checkpoint protocol.
- **`Linx.Tty`** — `/dev/tty`, `termios(3)` raw/save/restore, window-size
  ioctls, and `attach/2` (`:controlling` and `:group_leader` modes) for
  byte-pumping a `:pty` workload to the caller's terminal.
- **`Linx.Cgroup`** — cgroup v2 resource control via direct `/sys/fs/cgroup`
  I/O: typed memory/pids/cpu setters, freeze/thaw, `%Stats{}` counters.
- **`Linx.Mount`** — `mount(2)`, `umount2(2)`, `pivot_root(2)`, bind/remount/
  move, a `/proc/<pid>/mountinfo` parser, and a cross-namespace `:in` option.
- **`Linx.User`** — user-namespace uid/gid/setgroups mapping.
- **`Linx.Capabilities`** — the five per-thread capability sets as MapSets of
  `:cap_*` atoms; procfs read side, checkpoint-window write verbs.
- **`Linx.Seccomp`** — pure-Elixir cBPF syscall filters (`allow_list`/
  `deny_list`/`Builder`/`from_rules`), installed at the checkpoint.
- **`Linx.Sysctl`** — `/proc/sys/` knobs with dot-form keys, per-namespace
  routing, and the same `:in` option as `Linx.Mount`.
- **`Linx.Netlink`** — an `AF_NETLINK` client with rtnetlink (links,
  addresses, routes, neighbours, rules, stats) and nfnetlink families.
- **`Linx.Netfilter`** — nf_tables over `NETLINK_NETFILTER`: the `~NFT`
  sigil and pipeline DSL, `push`/`pull`/`diff`, socket-owned tables, a live
  `subscribe/1` monitor, NFLOG `log_listen/2`, and a `mix format` plugin.
- **Value types** — `Linx.IP` (+ `Subnet`) and `Linx.MAC`, each with a
  compile-time sigil that `Inspect` round-trips.

[Unreleased]: https://github.com/oshlabs/linx/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/oshlabs/linx/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/oshlabs/linx/releases/tag/v0.1.0
