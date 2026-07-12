# Changelog

All notable changes to Linx are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Three efforts land here: full remediation of the deep code assessment
(`docs/code-assessment.md`) — 4 critical, 15 major, 18 minor, and 9 build/test
findings, all fixed with test coverage; a major expansion of the netfilter
encoder and pipeline DSL, kernel-verified throughout; and the **removal of the
`~NFT` text frontend** (breaking).

### Removed — **breaking**

- **The `~NFT` sigil and the `Linx.NFT` namespace** (tokenizer, parser,
  compiler, formatter, `mix format` plugin, `.nft` file support) are gone.
  `~NFT` was a reimplementation of nft's own frontend: an approximation that
  invited the expectation of *exact* nft syntax and semantics, which only nft
  itself can honor — and it had no consumers. The **pipeline DSL**
  (`Ruleset` / `Table` / `Chain` / `Rule` / `Expr`) is the authoring surface;
  everything `~NFT` could express compiles to it, and every encoder
  capability it exercised remains kernel-verified via
  `test/linx/netfilter/kernel_acceptance_test.exs`. To display a ruleset as
  nft text, shell out to `nft list ruleset`. The frontend lives in git
  history should it ever be wanted again.

### Added — netfilter encoder & pipeline DSL

All kernel-verified through a live-netlink acceptance test (push, then read
back and compare):

- **Concatenated set keys end-to-end**: declarations
  (`key_type: {:concat, [:ipv4_addr, :inet_service]}`), elements, and
  rule-side selectors (consecutive reg32 loads); `:interval`-flagged
  concatenated sets use the kernel ≥ 5.6 pipapo encoding
  (`NFT_SET_CONCAT` + per-field bounds), so `10.0.0.0/24 . 80-443`-style
  elements work.
- **Dynamic-set update expressions** (`Expr.dynset/2`, `nft_dynset`) with
  nested per-element stateful expressions (`limit`/`counter`) — the
  fail2ban building block.
- **Named counter, quota, and limit objects** (NEWOBJ encoding +
  `Expr.objref/2`), and the inline `Expr.quota/1` / `Expr.limit/1`
  statements.
- **Verdict maps**: named (`Linx.Netfilter.Vmap`) and inline anonymous via
  `Expr.vmap_literal/3` (mirroring `set_literal/3`), including
  ct_state-keyed maps.
- `Expr.payload/2` field aliases for `tcp_flags`, `ip6_nexthdr`,
  `ip6_hoplimit`, icmpv6 type/code; `dnat`/`snat` to `addr:port`.

### Fixed — netfilter wire correctness

- **`meta nfproto`/`l4proto` wire keys** were emitted as 12/13
  (`NFT_META_NFTRACE`/`RTCLASSID` in the kernel enum) instead of 15/16.
- `ct_state` was missing from the Set/Map key-type whitelists (anonymous
  ct-state vmaps died at push time); plain (non-interval) concatenated sets
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
- `finit_module` added to the x86_64 seccomp syscall table; reconcile reads
  the generation counter before the snapshot (CAS race).

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

### Review pass (2026-07-11)

A follow-up whole-library review landed a second round of fixes:

- **Shared errno table.** `Linx.Errno` replaces the ten per-subsystem
  errno↔code maps (which had drifted apart); every `%Linx.*.Error{}`
  resolves through it, and `lib/linx.ex` documents the cross-subsystem
  error model. Type-level corrections: `Linx.Mount.Error` gains the five
  stages the code actually produces, `Linx.Sysctl.Error` drops a phantom
  `:chdir`, `Linx.Netfilter.Error.operation` shrinks to the three atoms
  actually constructed (`:push | :pull | :create_table` — **breaking** if
  you matched the old aspirational list), `Linx.User.setup_maps/2`
  documents its `{:bad_setup, _}` shape.
- **Seccomp cross-arch table fix.** `setsid`/`sendfile` were missing from
  the x86_64 map and `setrlimit`/`renameat` from aarch64 — a portable
  allow-list naming one silently failed to allow it on the other arch. An
  invariant test pins every remaining asymmetry as genuinely single-arch.
- **Netfilter: objects and flowtables survive `pull`** (`GETOBJ` /
  `GETFLOWTABLE` dumps) **and flowtables push** (`NEWFLOWTABLE` encoding,
  netdev-ingress hook, device list, `:hw_offload`/`:counter` flags) —
  previously `to_batch` silently discarded `add_flowtable` data.
  `validate_for_reconcile` rejects objects/flowtables (and anonymous
  set/vmap literals) in desired rulesets rather than silently never
  creating them.
- **Netfilter decoder symmetry**: `log`/`quota`/`objref` expressions and
  pipapo `KEY_END`/concat-type-id decoding — pulled rulesets containing
  them now compare equal instead of churning `:replace_rule` every
  reconcile pass. The encoder's silent empty-data fallback now **raises**
  for unknown expressions; rule comments are bounded at 253 bytes; named
  chain priorities are validated per family at build time; textual IPs are
  refused where a set key type must be inferred.
- **Silently-swallowed netlink failures surface**: socket bind errors
  (previously a deaf Monitor with no error anywhere), NFLOG config NACKs
  (previously `log_listen` succeeded and never delivered), and lost
  replies (`Request.talk` gains a per-datagram timeout, default 5s —
  **behavior change** from blocking forever).
- **Native hardening follow-through**: `linx_mount.c` re-verifies
  namespace identity after opening `/proc/<pid>/ns/{mnt,pid}` (the
  pid-reuse narrowing its siblings already had); `linx_sysctl.c` returns
  `EFBIG` instead of silently truncating reads at 64 KiB;
  `netlink_socket.c` rejects embedded NUL in netns paths; `linx_tty.c`
  restores termios on its alloc-failure path; `Linx.Tty.attach/2`'s
  setup window can no longer strand the terminal raw if the port open
  raises; `Linx.Process` checks the agent binary is executable, not just
  present.
- **Reconcile convergence fix**: a desired string value with a trailing
  newline now converges instead of being rewritten (and reported applied)
  every pass; `Linx.Cgroup.create/1` verifies an `EEXIST` target is a
  directory; `Linx.Mount` gains `:nosymfollow` (MS_NOSYMFOLLOW, ≥ 5.10)
  and unescapes mountinfo `super_options`.
- **Lifecycle race fixes**: `Linx.Process` teardown tolerates the external
  agent closing between the decision to reap and `Port.command/2`, preserving
  the intended session exit instead of crashing in `terminate/2`. Netfilter
  Monitor and NFLOG startup close their socket when configuration fails.
- **NFLOG readiness is now sequence-safe**: every configuration request waits
  for its matching kernel ACK through `Linx.Netlink.Request`; a lost ACK is an
  error instead of a listener that starts successfully but never delivers.

### Changed — orphan policy on unclean VM death (behavior change)

- **`Linx.Process` workloads no longer outlive an uncleanly-dying VM by
  default.** When the BEAM channel closes without the graceful reap
  (Ctrl-C abort, `kill -9 beam.smp` — any path where `terminate/2` never
  runs), the agent now SIGTERMs the workload, waits a grace period, then
  SIGKILLs it (the escalation matters: a PID-namespace init with no
  SIGTERM handler swallows the SIGTERM). Previously the workload was
  left to finish naturally — a leak in every scenario, since Linx has no
  orphan re-adoption. The new `:orphan_policy` option on `spawn/1` /
  `enter/2` controls this: `{:kill, grace_ms}` (default `{:kill, 5000}`)
  or `:linger` for the old let-it-finish semantics. Graceful teardowns
  (`GenServer.stop`, supervisor `:shutdown`, crashing linked callers)
  are unaffected — they reap immediately via `terminate/2` as before.

### CI

- New privileged job runs the full `:integration` suite as root; an aarch64
  leg exercises the arm64 syscall tables on real hardware; the seccomp
  kernel-acceptance tests (no root needed) run in the default suite.
- Dialyzer (via `dialyxir`) runs in CI with a cached PLT, enforcing the
  project's `@spec`-on-every-public-function policy.
- Documentation warnings and Hex package construction are checked in CI.
- The standalone `linx_process` Port and all four NIFs run focused suites
  under ASan and UBSan in CI; `LINX_SANITIZE` provides the same fingerprinted
  native build mode locally. NIF execution preloads libasan into the BEAM;
  leak detection stays scoped to the isolated Port process.
- Property tests cover full-field, multi-message Netlink framing round trips
  and malformed `nlmsg_len` rejection.
- Generated kernel-shaped mountinfo entries cover field preservation, octal
  escaping, propagation tags, and unknown optional fields.
- A test-only cBPF evaluator checks generated Seccomp rule sets semantically
  across both architectures, including architecture mismatch and x32 guards.
- Exact full-message nf_tables fixtures pin table, base-chain, counter-object,
  and flowtable framing beyond the existing set-element byte assertions.

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
