# Linx code assessment — remediation summary & remaining work

A multi-agent deep review of the whole codebase (C sources, Process/Tty, Netlink,
Netfilter/NFT, the file-I/O subsystems, and build/test/packaging) produced a
checklist of 46 findings: 4 critical, 15 major, 18 minor, 9 build/test. This
document records **what was fixed** (all 46) and **what still needs doing**
(follow-through, deferred features, and test/validation gaps that the
remediation surfaced but did not close).

> **Status: remediation complete and landed (2026-07-02, committed as
> `ceaeb2a`).** Every finding below is fixed and covered by a test. Verified
> green by the full unprivileged suite (1075 tests) *and* the full privileged
> suite (`./sudotest.sh` — 1233 tests, 0 failures) on Linux 6.x, and since
> then by GitHub CI on every push to `main` — including the privileged root
> job and the aarch64 leg this pass introduced.
>
> The full per-finding analysis (Where / Defect / Failure / Fix, with line
> numbers accurate post-0.2.0) lives in this file's git history. It is condensed
> here now that the work is landed; the code, tests, and `CHANGELOG.md`'s
> `[Unreleased]` section carry the authoritative detail.

---

## What was fixed

### Security (highest severity)

- **C2 — Seccomp x32-ABI guard.** x86_64 filters now trap syscalls entered via
  the x32 ABI (`__X32_SYSCALL_BIT`, `0x40000000`) or with a negative `nr`,
  mirroring libseccomp. Every deny-list (and any permissive-default allow-list)
  was bypassable on `CONFIG_X86_X32` kernels. Filters grow by 2 instructions;
  byte-level golden tests pin the trap; aarch64 is unchanged.
- **M3 — Namespace-entry PID-reuse TOCTOU.** `linx_process.c` opens every
  `/proc/<pid>/ns/*` fd through a single pinned `/proc/<pid>` dirfd *before* the
  first `setns`, so a target death + pid recycle can no longer splice together
  two processes' namespaces. `linx_sysctl.c` re-verifies ns identity after its
  open loop.
- **m1 — Atom-table exhaustion via kernel-controlled rule userdata.**
  `String.to_existing_atom` with a binary fallback; a co-tenant can no longer
  grow the permanent atom table by writing userdata TLVs.
- **m15 — NUL-byte injection.** `binary_to_cstr`/`decode_string` in all three C
  units reject embedded `\0`, so `"validated\0smuggled"` can't defeat
  Elixir-side path validation by truncating at the NUL.
- **m17 — Mount target symlink redirect.** `ensure_target_file` uses
  `lstat` + `O_CREAT|O_EXCL|O_NOFOLLOW`; a container-writable tree can no longer
  redirect root's file creation (and thus a bind-mount target) via a symlink at
  the final component.
- **Build hardening (I4).** All native builds gain `-fstack-protector-strong`,
  `-D_FORTIFY_SOURCE=2` (release only), and full RELRO (`-z relro -z now`);
  verified present in the emitted binaries.

### Process & Tty lifecycle

- **C1 — `trap_exit` in sessions.** `init/1` traps exits, so a supervisor
  `:shutdown` and a crashing linked `spawn/1` caller both run `terminate/2` and
  reap the OS workload instead of orphaning (and then duplicating) it. The
  `child_spec/1` `shutdown` timeout is now meaningful.
- **M7 — PTY backpressure & oversized writes.** The agent buffers PTY input and
  flushes on `POLLOUT` (a >4 KB paste dropped its tail on `EAGAIN`); overflow of
  a 1 MiB cap emits `{:linx_process, :pty_in_dropped, n}` rather than silently
  losing bytes. `pty_write/2` chunks below the agent's 32 KiB frame ceiling
  (an oversized frame used to desync the wire and SIGKILL the workload).
- **M8 — `:controlling` attach traps exits.** Mirrors the group-leader pump, so
  a linked `linger: false` session's exit signal unwinds through the terminal
  restore instead of leaving the tty raw and `prim_tty`'s reader disabled
  node-wide.
- **M9 / M10 — attach & `pty_write` stage guards.** `pty_write/2` before
  `:running` returns `{:error, :not_running}` (used to kill the parked child);
  `Tty.attach/2` requires the `:running` stage; both pumps have a defensive
  `{:linx_process, :aborted}` clause.
- **M11 — `:safe`-decode atom whitelist.** `@error_stages` now covers every
  stage the C agent emits (`:chdir`, `:command_too_big`, the transport errors,
  …); a test greps the C sources so the whitelist can't drift again. Previously
  most documented transport errors surfaced as a misleading `:agent_died`.
- **m11 — Dead-session verbs.** `proceed`/`abort`/`signal`/`pty_write`/
  `pty_set_winsize` catch the `:noproc` exit and return `{:error, :no_process}`.
- **m12 — `signal/2`** guards signum to `1..64` (the agent silently dropped
  >64 while the verb reported `:ok`).
- **m13 — Checkpoint command buffer.** `await_proceed`/`child_read_command` read
  into 32 KiB (matching the documented ceiling) and `emit_error(:command_too_big)`
  on `EMSGSIZE` instead of dying as `:agent_died`.
- **m16 — Empty `pty_in`** (`malloc(0)`) is handled as a valid no-op.
- **m18 — Exactly one terminal event.** A result-set guard drops the second
  terminal-shaped frame on the `command_too_big` path.

### Netlink receive / decode

- **C3 — Datagram truncation.** Both synchronous engines read 64 KiB via
  `Socket.recv_datagram/2` and surface `{:error, :truncated}` on `MSG_TRUNC`;
  datagrams over OTP's 8 KiB default read length were silently cut.
- **M4 — `NLMSG_DONE` errno.** A negative `dump_done_errno` returns
  `{:error, %Error{}}` instead of `{:ok, partial_list}`.
- **M5 — `NLM_F_DUMP_INTR`.** A torn dump returns `{:error, :dump_interrupted}`
  instead of an inconsistent snapshot presented as success.
- **M6 — Shared-socket concurrency claim.** The false "cannot collide" docstring
  is replaced with an honest statement of the one-driver-per-socket limitation.
  *(Documentation only — see Remaining work.)*
- **m2 — Seq wrap.** `next_seq/1` masks to 32 bits and skips 0, so a reply still
  matches its request after 2³² calls.
- **m4 — Tolerant decode.** `codec.ex` `unscalar/2` / `decode_header` and
  `IP.decode/1` fall back to `nil` on short/empty attributes instead of crashing
  the caller (e.g. a monitor GenServer).
- **m5 — `nla_len` bound.** `Attr.encode/1` raises past the 16-bit limit instead
  of emitting a wrapped length the kernel misparses.

### Netfilter encoder / NFT compiler (element layer)

- **C4 — Textual IPs.** `encode_key_value` is type-directed: a `"1.2.3.4"`
  string parses to 4 address bytes (was sent as 7 ASCII bytes → kernel EINVAL).
- **M1 — Interval elements.** Ranges/CIDRs encode as `NFT_SET_ELEM_INTERVAL_END`
  start/end pairs (the encoding nft/libnftnl use for plain interval sets, kernel-
  agnostic — chosen over `NFTA_SET_ELEM_KEY_END`, which needs ≥ 5.6). They used
  to raise an uncaught `ArgumentError` at push. The decoder pairs the markers
  back into `{:range, lo, hi}` on pull.
- **M2 — Host-order fields.** `meta mark`/`iif`/`oif`/`length`/`skuid`/`skgid`
  and `ct mark` encode host byte order (never matched on little-endian);
  `meta protocol` stays network order. Ranges over these raise a clear compile
  error rather than mis-encode (see Remaining work).
- **M12 — Reconcile type inference.** Element ops thread the parent set's
  declared `{key_type, data_type, interval?}` instead of guessing from value
  magnitude (a low port like `22` was mis-encoded as a 1-byte `:inet_proto`
  key).
- **m6 — `finit_module: 313`** added to the x86_64 syscall table.
- **m7 — `Verdict.queue(n)`** encodes the queue number in the code's high 16
  bits (`NF_QUEUE_NR`) and round-trips on decode; a bare queue silently went
  to 0.
- **m8 — `+` priority offset** tokenizes (`priority filter + 10`).
- **m9 — `:eval`/`:dynamic`** documented as aliases (both `0x20`; round-trips
  normalise to `:dynamic`).
- **m10 — Reconcile CAS race.** The generation counter is read *before* the
  snapshot so a commit in the window forces a retry instead of a stale-data CAS
  success.
- **Also landed alongside the cluster:** `:ifname` keys NUL-pad to their 16-byte
  declared width; `Set.Element.check/2` accepts the `{:range, lo, hi}` shape;
  new `test/linx/netfilter/encoder_test.exs` asserts exact wire bytes (the
  value-equality-only blindspot the review called out).

### Netfilter behaviour & sysctl

- **M13 — Owner-flag default.** `Table.new/3` (and thus `Ruleset.add_table/3`)
  default to `flags: [:owner]`, so a pushed table auto-reaps when its socket
  closes — aligning the primary authoring path with the documented guarantee.
  **User-visible behaviour change**; opt out with `flags: [:persist]` or `[]`.
- **M14 — Dotted interface names.** `Linx.Sysctl` accepts `sysctl(8)`-style
  slash-form keys (`"net/ipv4/conf/eth0.100/forwarding"`, dots literal); `list/*`
  emit round-trippable keys for such entries.
- **m3 — Strict IP parsing.** `Linx.IP.parse/1` uses `parse_strict_address`, so
  classful shorthand (`"10.0.0"` → `10.0.0.0`) errors instead of installing a
  valid-but-wrong address.
- **m14 — `list_in_ns`** no longer wraps a mid-loop ENOMEM as the malformed
  `{:ok, {:error, …}}`.

### Build / test / CI

- **I1 — Fingerprint-based staleness.** The five custom compilers share
  `Mix.Linx.CC`: staleness keys off a content+flags+OTP fingerprint (not mtime,
  which missed `CC`/`CFLAGS`/`LINX_DEBUG`/OTP changes and epoch-mtime Hex
  tarballs), and each build compiles to a temp path then atomically renames.
- **I2 — Seccomp kernel-acceptance in CI.** The rootless
  `PR_SET_NO_NEW_PRIVS` + `seccomp(2)` tests (need only `python3`) run in the
  default suite — the only guard against a fail-open miscompile.
- **I3 — `CFLAGS` honored** (appended after built-in flags). **I4 —** hardening
  flags (above).
- **I5 — Deflaked tty pump tests.** Wall-clock sleeps replaced with readiness
  signals (a watcher that ends the pump on the observed echo / geometry poll).
- **I6 — CI matrix widened** with an aarch64 leg (`ubuntu-24.04-arm`) so the
  arm64 syscall tables run on real hardware.
- **M15 / privileged CI.** A new job runs the full `:integration` suite as root;
  `sudotest.sh`/`sudorun.sh` (I7) compile as the invoking user and chown build
  artifacts back so root never leaves ownership that breaks later non-root
  compiles.
- **I8 —** stale `docs/release/…` comment dropped. **I9 —** `PLAN.md` refreshed
  to post-0.2.0 framing.

---

## Remaining work

Nothing below is a regression or a known-broken path — the remediation is
self-consistent and green. These are follow-throughs, deliberately-deferred
features, and coverage/validation gaps. Roughly ordered by priority.

### Process

1. ~~Commit the change set.~~ **Done** — landed as `ceaeb2a` (2026-07-02).
2. ~~Actually run the new CI jobs.~~ **Done** — the privileged root job and
   the aarch64 leg run green on every push to `main` since `1aff5b6`.
3. **Decide the release vehicle for M13.** The owner-flag default is a
   behaviour change for existing users. Confirm it should ship as-is (it aligns
   code with the long-documented guarantee) and that a minor-version bump +
   the CHANGELOG note are the right disclosure.

### Netlink dump robustness (follow-through)

4. **Retry, or teach reconcilers, on `:dump_interrupted` / DONE-errno.** The
   engine now *surfaces* these (M4/M5), and every dump caller
   (`Route.list`, `Address.list`, `Link.list`, `Rule.list`, `Neighbour.list`,
   `Stats`, netfilter `pull`) propagates them cleanly under a `{:error, term}`
   spec — nothing is broken. But no caller yet does the *ideal* thing: a
   bounded auto re-dump on `NLM_F_DUMP_INTR` (libnl's `NLE_DUMP_INTR` retry),
   and `Rtnl.Reconcile` should treat both errors as "skip this cycle" rather
   than diffing against an error. Today a transient churn error propagates to
   the caller as a one-shot failure.

### Shared-socket concurrency (M6 was doc-only)

5. **Build a socket-owning connection process** if concurrent access to one
   `%Socket{}` is ever needed. The current fix only *documents* the
   one-driver-at-a-time limitation; the real fix (a GenServer that owns the fd
   and demuxes replies to waiters by seq) is unbuilt. Not required as long as
   callers open one socket per concurrent user, which the docs now mandate.

### `~NFT` feature gaps (deferred; also in `PLAN.md`)

6. **Ranges over host-byte-order fields** (`meta mark 10-20`, `ct mark`
   ranges). M2 makes these raise a clear compile error rather than mis-encode.
   Real support needs a byteorder-conversion expression before the set lookup
   (intervals are compared in memcmp order, which isn't numeric order for a
   native-endian key on little-endian hosts).
7. ~~Concatenated set types and pipapo-backed concatenated ranges.~~
   **Done** — landed kernel-verified in the NFT-parity passes
   (`e60ad2d`, `9711855`, 2026-07-02); see `NFT-PLAN.md`.

### Native hardening & fuzzing (deferred; also in `PLAN.md`)

8. **`openat2(RESOLVE_BENEATH)` for mount target *parent* directories.** m17
   protected the final path component (`O_EXCL|O_NOFOLLOW`); a symlinked
   *parent* dir in a live, adversarial container is still a theoretical
   redirect. Worth doing if `linx_mount` is ever used against untrusted running
   containers (today's typical call precedes the workload).
9. **ASan / UBSan over the C.** Build the four NIFs and the `linx_process` port
   with `-fsanitize=address,undefined` and run the suite under them (the port
   as a standalone exe; the NIFs via `LD_PRELOAD` of libasan). First automated
   backstop for the `c_src` edge-case guards this pass added.

### Test-coverage gaps

10. **x32 kernel-acceptance test.** C2 has byte-level golden tests but nothing
    yet invokes an actual x32 syscall against a real kernel to prove the trap
    *fires*. The `test/support/seccomp_check.py` helper could be extended to
    call e.g. `getpid` via the x32 entry under a deny-list and assert the kill.
11. **PTY backpressure / overflow paths (M7).** The `POLLOUT` flush and the
    `pty_in_dropped` overflow are exercised indirectly (a 64 KiB flood test),
    but there's no test that deterministically fills the tty input queue and
    asserts the buffer→flush handoff, nor one that trips the 1 MiB cap and
    asserts the `pty_in_dropped` event. Both are timing/pressure-dependent.
12. **Privileged, adversarial paths without coverage.** m17's symlink refusal
    and M3's TOCTOU narrowing are only covered for the happy path by the
    `enter`/mount integration tests — the *attack* (a racing pid recycle, a
    planted symlink) isn't reproduced. Hard to make deterministic; document as
    a known coverage limit if not built.
13. **Property tests for the highest-risk pure code** (from `PLAN.md`): a small
    in-test cBPF evaluator proving a compiled `Linx.Seccomp` filter blocks what
    it should (complements the kernel-acceptance tests with exhaustive input
    coverage); round-trip properties for the `/proc/<pid>/mountinfo` parser and
    the full netlink `Message` codec.
14. **Extend wire-byte assertions beyond the set-element layer.** The new
    `encoder_test.exs` pins exact bytes for set elements (the specific
    blindspot C4/M1/M2/M12 lived in); the rest of the netfilter encoder is
    still covered only by value-equality round-trips.

### Minor / opportunistic

15. **Sysctl ns identity: `pidfd` over re-verify.** `linx_sysctl.c`'s
    post-open stat re-verification (M3) *narrows* the pid-reuse window rather
    than eliminating it the way the `linx_process.c` pinned-dirfd approach does.
    A `pidfd_open` + `pidfd`-relative resolution would be strictly stronger; the
    paths are opaque binaries there (possibly bind-mounted netns files), which
    is why the cheaper re-verify was used.

---

## Verified as correct (no action)

Recorded so a future reviewer doesn't re-investigate — these were checked during
the review and found sound:

- fd hygiene between clone/exec (`child_fn` closes parent ends; internal
  pipes/PTY are `O_CLOEXEC` or explicitly closed; `apply_stdio` closes on every
  error branch).
- Dirty-scheduler usage: all blocking NIFs flagged `ERL_NIF_DIRTY_JOB_IO_BOUND`,
  non-blocking ones not.
- The netlink netns throwaway-thread `setns` pattern (socket created after
  `setns`, `SOCK_CLOEXEC`, thread joined within the NIF, the `unshare(CLONE_FS)`
  subtlety) — correct and consistent.
- cBPF opcode/offset/jump/endianness emission (opcodes, `nr=0`/`arch=4` offsets,
  little-endian instruction packing, `jt = target-pos-1`, default-RET reuse, the
  `e2big` guard). The *only* seccomp defect was the missing x32 guard (C2, now
  fixed).
- Capabilities bit table (0–40 vs `capability.h`), `/proc/<pid>/status`
  tag-keyed parsing.
- User: `setgroups=deny` written before `gid_map` (correct kernel ordering),
  write-once respected.
- Mount: mountinfo parser (`\040` escapes, `-` optional-field terminator,
  unknown-tag skip), `MS_*`/`MNT_*` tables, 8-arg `mount` NIF,
  `unshare(CLONE_FS)`-before-`setns(CLONE_NEWNS)` ordering.
- Cgroup: idempotent `create` (EEXIST→ok), robust `parse_keyed`/`read_int`,
  per-controller partial reporting. (`read/2`/`write/3` accept an arbitrary file
  arg — documented raw escape hatch, not a defect.)
- Reconcile (sysctl+cgroup): three-way `last_applied`, best-effort apply,
  token-wise value comparison (`cpu.max`'s `"max <period>"`, tab/space tuples).
- Netlink wire *encoding*: struct layouts, attribute IDs, NLA 4-byte
  alignment/padding, extended-ack parsing incl. the `NLM_F_CAPPED` echoed-header
  skip, the nfnetlink big-endian `res_id`/`NFTA_*` asymmetry. CRUD flag usage
  (`CREATE|EXCL` add, `CREATE|REPLACE` replace, `RTPROT_UNSPEC` route delete).
  (The *decode/receive* side is where C3/M4/M5/m2/m4/m5 lived.)
- Netfilter value-type validators (Ruleset/Table/Chain/Rule/Verdict) and batch
  framing (`NFNL_MSG_BATCH_BEGIN/END`, attribute nesting, big-endian NLA
  helpers); `format → parse` round-trip is self-coherent. (The *element* layer
  is where C4/M1/M2/M12/m7 lived.)
- `linx_tty`: `restore_and_close` tolerating EBADF (intentional, documented),
  winsize bounds-checked, termios blob size-checked before memcpy.
- Packaging: the `linx-*.tar` in the tree are `.gitignore`d local `mix hex.build`
  leftovers, not repo defects. `files:` list correct; docs extras exist;
  CHANGELOG matched git history; no stray `@tag :skip`; integration tests clean
  up after themselves.
