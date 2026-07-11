# Changelog

All notable changes to Linx are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Two efforts land here: full remediation of the deep code assessment
(`docs/code-assessment.md`) — 4 critical, 15 major, 18 minor, and 9 build/test
findings, all fixed with test coverage — and the first six passes of the `~NFT`
parity roadmap (`NFT-PLAN.md`), kernel-verified throughout.

### Added — `~NFT` parity (toward full nftables syntax)

- **Verification harnesses.** A differential test runs real `nft --check -f`
  (unprivileged, via `unshare -r -n`) over every fixture *and* over
  `Linx.NFT.format/1` output — whatever Linx emits is guaranteed loadable by
  nft. A kernel-acceptance test pushes the new encodings through a live
  netlink socket and reads them back. An aspirational real-world corpus
  ratchets coverage: 9/9 fixtures fully supported.
- **Protocol-context dependency generation** (nft evaluate.c's `proto_ctx`):
  transport matches auto-materialise a `meta l4proto` guard, and ip/ip6 header
  matches in `inet` chains a `meta nfproto` guard — fixing a real correctness
  bug where `tcp dport 22` compiled to a bare offset load that also matched
  UDP packets. Contradictory hand-written guards are located errors.
- **Concatenations end-to-end**: set declarations (`type ipv4_addr .
  inet_service`), elements, and rule-side selectors; `flags interval`
  concatenated sets use the kernel ≥ 5.6 pipapo encoding
  (`NFT_SET_CONCAT` + per-field bounds), so `10.0.0.0/24 . 80-443`-style
  elements work.
- **Dynamic-set statements** (`add @set { key timeout 5m }` with nested
  `limit`/`counter`) — the fail2ban building block.
- **Bitwise/flag matching**: `tcp flags syn` (implicit bit test), masked
  compares (`tcp flags & (fin|syn|rst|ack) == syn`, `ct mark & 0xff == 0x4`),
  and symbolic tcp-flag names.
- **Named counter, quota, and limit objects** (NEWOBJ + objref), the inline
  `quota` statement, and `limit rate` statements.
- **Verdict maps** (named and inline anonymous), `define`/`$var` substitution
  with did-you-mean, `dnat` to `addr:port`, `iif`/`oif` by name, ip6
  `nexthdr`/`hoplimit`, kind-keyed icmp/icmpv6 type names, and log flags
  (a plain `log` no longer silently becomes nflog group 5000).
- **`include` resolution** in `parse/2`/`parse_file/2` with nft-compatible
  semantics: relative to the including file, then `:include_paths`; glob
  support; nesting capped at 16 plus cycle detection; located errors inside
  included files. The `~NFT` sigil rejects `include` (inline source has no
  base directory).
- **Multi-error reporting**: the parser recovers at statement boundaries
  instead of stopping at the first error (capped at 10, nft's
  `parser_max_errors`); `ParseError` gains an `others` field, single-error
  output is byte-identical to before.
- **scanner.l-faithful lexing**: octal literals, nft-exact quoted strings,
  dotted/slashed bare strings (`example.com`), compound timestrings
  (`1h30m10s`).

### Fixed — `~NFT` wire correctness

- **`NFTA_SET_TIMEOUT` is milliseconds** — `timeout 1h` used to install a
  3.6-second element timeout.
- **`meta nfproto`/`l4proto` wire keys** were emitted as 12/13
  (`NFT_META_NFTRACE`/`RTCLASSID` in the kernel enum) instead of 15/16.
- `udp dport` no longer renders as `tcp dport` (and icmpv6 as icmp) in
  formatted output; formatter output re-parses to the identical ruleset.
- `ct_state` was missing from the Set/Map key-type whitelists (anonymous
  `ct state vmap` died at push time); plain (non-interval) concatenated sets
  no longer emit `NFTA_SET_DESC_CONCAT`, which the kernel rejects without the
  `NFT_SET_CONCAT` flag.

### Security

- **Seccomp: x32-ABI guard.** x86_64 filters now trap syscalls entered via the
  x32 ABI (`__X32_SYSCALL_BIT`) or with negative `nr`, mirroring libseccomp.
  Previously every deny-list (and any allow-list with a permissive default)
  was bypassable on `CONFIG_X86_X32` kernels. Filters grow by 2 instructions.
- **Namespace entry: pid-reuse TOCTOU closed.** `linx_process` opens all
  `/proc/<pid>/ns/*` fds through a pinned dirfd before the first `setns`;
  `linx_sysctl` re-verifies ns identity after its open loop. A target dying
  mid-entry can no longer splice together namespaces of two processes.
- **NUL-byte injection rejected** in every path/string crossing the NIF and
  Port boundaries. **Mount target creation** no longer follows symlinks
  (`O_EXCL|O_NOFOLLOW`). **Kernel-controlled rule userdata** no longer interns
  unbounded atoms. Native builds get `-fstack-protector-strong`,
  `_FORTIFY_SOURCE=2`, and full RELRO; the `linx_process` Port binary — the
  one artifact that runs `clone`/`setns`/`execve` as root — is additionally
  built PIE (`-fPIE -pie`) so it gets ASLR regardless of the host compiler's
  default.

### Fixed

- **`Linx.Process` sessions trap exits**: supervisor `:shutdown` and crashing
  linked callers now reap the OS workload instead of orphaning (and then
  duplicating) it.
- **Netlink receive path**: explicit 64 KiB reads with `MSG_TRUNC` detection
  (datagrams over 8 KiB were silently truncated); `NLMSG_DONE`'s
  `dump_done_errno` and `NLM_F_DUMP_INTR` are now checked, so failed or
  torn dumps return errors instead of silently incomplete snapshots.
- **Netfilter set-element layer rewritten type-directed**: textual IPs parse
  to address bytes (were sent as raw ASCII), ranges/CIDRs encode as proper
  interval start/end pairs (crashed the encoder), marks and the host-order
  meta/ct fields (`mark`, `iif`, `oif`, `length`, `skuid`, `skgid`, `ct mark`)
  compare in host byte order (never matched on little-endian), `:ifname` keys
  are NUL-padded to their declared width, `Verdict.queue/1` keeps its queue
  number, and reconcile patches carry declared key/data types instead of
  guessing from value shape. Interval elements round-trip through `pull`.
- **PTY robustness**: input is buffered in the agent and flushed on `POLLOUT`
  (a >4 KiB paste dropped its tail), large `pty_write/2` calls are chunked
  below the agent's 32 KiB frame ceiling (used to SIGKILL the workload),
  writes before `:running` are refused (used to kill the parked child),
  `Tty.attach/2` requires a running session, the `:controlling` pump traps
  exits so the terminal is always restored, and owners get exactly one
  terminal event.
- **Every error stage the C agent emits is now decodable** (`:safe` atom
  whitelist was missing `:chdir` and most transport errors — they surfaced
  as `:agent_died`); a test greps the C source to keep the whitelist honest.
- Session verbs (`proceed`, `abort`, `signal`, `pty_write`, `pty_set_winsize`)
  return `{:error, :no_process}` on dead sessions instead of exiting the
  caller; `signal/2` bounds signum to `1..64`.
- `Linx.IP.parse/1` is strict (rejects classful shorthand like `"10.0.0"`);
  netlink decoders tolerate short/empty attributes instead of crashing;
  attribute encoding rejects payloads past the 16-bit `nla_len` limit;
  netlink sequence numbers wrap correctly at 32 bits.
- `finit_module` added to the x86_64 seccomp syscall table; `~NFT` accepts
  `priority filter + 10`; reconcile reads the generation counter before the
  snapshot (CAS race).

### Changed

- **`{:connect_unix, path}` stdio directives now connect in the agent,
  host-side, at spawn/enter time** — before the `clone(2)` (or, in enter
  mode, before any `setns(2)`); the workload inherits the already-connected
  fd and only `dup2`s it. Previously the *child* connected after `:proceed`,
  which resolved `path` in the child's (possibly pivoted) mount namespace
  and surfaced bad paths only after the whole checkpoint bring-up.
  Consequences: `path` is always a host path; the listener's `accept`
  completes at spawn time (before `:ready`); a failed connect is a new
  pre-clone error stage `:connect_unix` emitted before `:ready`; and child
  seccomp filters no longer need `socket`/`connect` for stdio plumbing.
- **Tables built with `Table.new/3` / `Ruleset.add_table/3` now default to
  `flags: [:owner]`** — a pushed table auto-reaps when the creating socket
  closes, aligning the primary authoring path with the documented "sockets
  own their tables" guarantee (kernel ≥ 5.13). Pass `flags: [:persist]` or
  `flags: []` to opt out.
- `Linx.Sysctl` accepts `sysctl(8)`-style slash-form keys
  (`"net/ipv4/conf/eth0.100/forwarding"`) so dotted interface names are
  addressable; `list/0..2` emit round-trippable keys for such entries.
- Shared-socket concurrency limits are now documented honestly: one
  `%Socket{}`, one driving process at a time.
- Native builds honor `CFLAGS`, rebuild on toolchain/flag/OTP changes
  (content-fingerprint staleness instead of mtime), and compile to a temp
  path with an atomic rename.

### CI

- New privileged job runs the full `:integration` suite as root; an aarch64
  leg exercises the arm64 syscall tables on real hardware; the seccomp
  kernel-acceptance tests (no root needed) run in the default suite.
- Dialyzer (via `dialyxir`) runs in CI with a cached PLT, enforcing the
  project's `@spec`-on-every-public-function policy.

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
