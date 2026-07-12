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

## Deferred features

(The `~NFT` text frontend and its parity roadmap were removed on the
`remove-nft` branch — an unconsumed approximation of nft's own frontend that
set expectations of exact parity it couldn't honor. The pipeline DSL is the
authoring surface; the frontend lives in git history if ever wanted again.)

- **`openat2(RESOLVE_BENEATH)` hardening** for `linx_mount`'s target-file
  creation when used against live (adversarial) containers — the final
  component is already `O_EXCL|O_NOFOLLOW`-protected.

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
