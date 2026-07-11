# Linx code assessment — remediation summary

A multi-agent deep review of the whole codebase (C sources, Process/Tty, Netlink,
Netfilter/NFT, the file-I/O subsystems, and build/test/packaging) produced a
checklist of 46 findings: 4 critical, 15 major, 18 minor, 9 build/test.

> **Status: remediation complete and landed (2026-07-02, committed as
> `ceaeb2a`).** Every finding is fixed and covered by a test. Verified
> green by the full unprivileged suite (1075 tests) *and* the full privileged
> suite (`./sudotest.sh` — 1233 tests, 0 failures) on Linux 6.x, and since
> then by GitHub CI on every push to `main` — including the privileged root
> job and the aarch64 leg this pass introduced.

---

## What was fixed

All 46 findings — spanning seccomp (an x32-ABI bypass), process/tty lifecycle,
the netlink receive path, the netfilter set-element encoder, sysctl, and the
native build/test/CI pipeline — were fixed with test coverage and landed as
`ceaeb2a` (2026-07-02). The full per-finding analysis (Where / Defect /
Failure / Fix) lives in this file's git history, and the user-visible fixes
are itemised in `CHANGELOG.md`'s `[Unreleased]` section; the code and tests
carry the authoritative detail.

## Remaining work

Tracked in `PLAN.md` — the follow-throughs, deferred features, and
coverage/validation gaps the remediation surfaced but did not close live there.

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
