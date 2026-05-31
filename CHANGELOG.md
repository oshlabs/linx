# Changelog

All notable changes to Linx are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/oshlabs/linx/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/oshlabs/linx/releases/tag/v0.1.0
