# Linx — plan

Forward-looking work, post-0.2.0. This file captures what's intentionally
deferred. (The detailed per-topic release plans were working scaffolding; they
live in git history under `docs/release/` if needed. The full-codebase
assessment and its remediation checklist live in `docs/code-assessment.md`.)

This is a maintainer doc — it is not shipped in the hex package and does not
render on hexdocs.

## Release

- **Decide the release vehicle for the owner-flag default (M13).**
  `Table.new/3` / `Ruleset.add_table/3` defaulting to `flags: [:owner]` is a
  behaviour change for existing users. Confirm it should ship as-is (it aligns
  code with the long-documented "sockets own their tables" guarantee) and that
  a minor-version bump + the CHANGELOG note are the right disclosure.

## Verification

Largely closed by the code-assessment remediation pass: CI now runs a
privileged job (full `:integration` suite as root on `ubuntu-24.04`), an
aarch64 leg, and the seccomp kernel-acceptance tests in the default
unprivileged suite. Still open:

- **ASan / UBSan over the native code.** Build the four NIFs and the
  `linx_process` port with `-fsanitize=address,undefined` and run the suite
  under them — the port first (a standalone executable), the NIFs via
  `LD_PRELOAD` of libasan. First backstop for the `c_src` edge-case guards.

- **Property tests for the highest-risk pure code.** A small in-test cBPF
  evaluator that proves a compiled `Linx.Seccomp` filter actually blocks what
  it should (complements the kernel-acceptance tests with exhaustive
  input coverage); plus round-trip properties for the `/proc/<pid>/mountinfo`
  parser and the full netlink `Message` codec.

- **x32 kernel-acceptance test.** The seccomp x32-ABI guard has byte-level
  golden tests, but nothing yet invokes an actual x32 syscall against a real
  kernel to prove the trap *fires*. `test/support/seccomp_check.py` could be
  extended to call e.g. `getpid` via the x32 entry under a deny-list and
  assert the kill.

- **Deterministic PTY backpressure / overflow tests.** The agent's `POLLOUT`
  flush and the 1 MiB `pty_in_dropped` cap are exercised only indirectly (a
  64 KiB flood test); there is no test that deterministically fills the tty
  input queue and asserts the buffer→flush handoff, nor one that trips the
  cap and asserts the `pty_in_dropped` event. Both are
  timing/pressure-dependent.

- **Privileged, adversarial-path coverage.** The mount-target symlink refusal
  and the namespace-entry pid-reuse (TOCTOU) narrowing are covered only for
  the happy path by the `enter`/mount integration tests — the *attack* (a
  racing pid recycle, a planted symlink) isn't reproduced. Hard to make
  deterministic; document as a known coverage limit if not built.

- **Extend wire-byte assertions beyond the set-element layer.**
  `test/linx/netfilter/encoder_test.exs` pins exact bytes for set elements
  (where the assessment's element-layer defects lived); the rest of the
  netfilter encoder is still covered only by value-equality round-trips.

## Deferred features

(The `~NFT` text frontend and its parity roadmap were removed on the
`remove-nft` branch — an unconsumed approximation of nft's own frontend that
set expectations of exact parity it couldn't honor. The pipeline DSL is the
authoring surface; the frontend lives in git history if ever wanted again.)

- **Extract the shared flat-KV reconcile engine (cgroup + sysctl).**
  `Linx.Cgroup.Reconcile` and `Linx.Sysctl.Reconcile` are ~85%
  line-identical: `diff/4`, `apply_ops`, `next_last_applied`,
  `converged?`, the `%Report{}` structs, and the `Source` adapters all
  mirror each other (the moduledocs say so). The duplication already
  bit once — the trailing-whitespace convergence bug had to be fixed
  twice — and any `next_last_applied` change can silently diverge.
  Fix shape: one engine (working name `Linx.Reconcile.FlatKV`) owning
  the pass structure and ownership semantics, parameterized per
  subsystem by `read`/`write`/`render`/`same_value?`; the public
  per-subsystem modules keep their exact APIs (including cgroup's
  positional scope vs sysctl's `:in` opt) as thin fronts, and the
  Source adapters are untouched. Acceptance: all four existing
  reconcile test suites pass **unchanged** (they define the
  semantics — a test edit means the refactor changed behavior),
  `./sudotest.sh` green, dialyzer clean, net lines down (~120+
  deleted), and the ownership rules (capture-once `:original`,
  failed-set ownership retention, failed-revert retry) documented in
  exactly one place. Trigger: before any third flat-KV reconcile
  surface, or the next time `next_last_applied` needs touching in
  both files; folds into the 0.3.0 cycle.

- **`openat2(RESOLVE_BENEATH)` hardening** for `linx_mount`'s target-file
  creation when used against live (adversarial) containers — the final
  component is already `O_EXCL|O_NOFOLLOW`-protected.

- **Bounded re-dump on `NLM_F_DUMP_INTR` / DONE-errno.** The netlink engines
  now *surface* interrupted and failed dumps (`:dump_interrupted`, a negative
  `dump_done_errno`), and every dump caller propagates them cleanly — but no
  caller yet does the *ideal* thing: a bounded auto re-dump on
  `NLM_F_DUMP_INTR` (libnl's `NLE_DUMP_INTR` retry), and `Rtnl.Reconcile`
  should treat both errors as "skip this cycle" rather than a one-shot
  failure to the caller.

- **A socket-owning connection process**, if concurrent access to one
  `%Socket{}` is ever needed: a GenServer that owns the fd and demuxes
  replies to waiters by seq. The current state only *documents* the
  one-driver-at-a-time limitation, which suffices as long as callers open
  one socket per concurrent user (the docs mandate this).

- **Sysctl/mount ns identity: `pidfd` over re-verify.** `linx_sysctl.c`'s and
  `linx_mount.c`'s post-open stat re-verification *narrows* the pid-reuse
  window rather than eliminating it the way `linx_process.c`'s pinned-dirfd
  approach does. A `pidfd_open` + `pidfd`-relative resolution would be
  strictly stronger; the paths are opaque binaries there (possibly
  bind-mounted netns files), which is why the cheaper re-verify was used.
