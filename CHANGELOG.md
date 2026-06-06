# Changelog

All notable changes to Linx are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-06-06

### Changed

- **Raised the minimum toolchain to Elixir 1.18 / OTP 28** (was Elixir 1.15 / OTP 26).
  `Linx.Tty`'s group-leader attach drives `prim_tty` internals (the OTP-28 `output_mode` accessor)
  that don't exist on older OTP, so that path never functioned there. CI now tests the 1.18/28
  floor and 1.19/28 current pairings.

## [0.1.1] - 2026-06-04

### Fixed

- Point the README's subsystem links at HexDocs so they resolve on the hex.pm package page
  (relative `docs/*.md` links 404 there).

## [0.1.0] - 2026-06-04

First public release — Linux kernel interfaces for Elixir, exposed as idiomatic, library-first
primitives (not a runtime):

- **Netlink** — rtnetlink sockets: links, addresses, routes, rules, neighbours, and monitoring.
- **Process** — process and namespace lifecycle with a checkpoint/proceed model.
- **Tty** — terminal/PTY control, including group-leader attach over the OTP `prim_tty` driver.
- **Cgroup** — cgroup v2 resource limits and stats.
- **Mount** — filesystem mounts.
- **User** — user-namespace identity (uid/gid) mappings.
- **Capabilities** — per-process capability sets.
- **Seccomp** — per-thread seccomp filters.
- **Sysctl** — kernel-tunable parameters.
- **Netfilter** — modern firewalling via nf_tables.
- **Reconcile** — declarative reconciliation across the above subsystems.

[0.2.0]: https://github.com/oshlabs/linx/releases/tag/v0.2.0
[0.1.1]: https://github.com/oshlabs/linx/releases/tag/v0.1.1
[0.1.0]: https://github.com/oshlabs/linx/releases/tag/v0.1.0
