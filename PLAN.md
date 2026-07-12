# Linx — plan

Forward-looking work, post-0.2.0. This file captures what's intentionally
deferred. (The detailed per-topic release plans were working scaffolding; they
live in git history under `docs/release/` if needed. The full-codebase
assessment and its remediation checklist live in `docs/code-assessment.md`.)

This is a maintainer doc — it is not shipped in the hex package and does not
render on hexdocs.

## Release

The next release is `0.3.0`. It keeps the owner-flag default because that
matches the documented socket-owned table lifecycle; the changelog migration
section documents `flags: []` and `flags: [:persist]` as explicit alternatives.
The version in `mix.exs` stays at the last published release until the release
commit.

## Verification

Largely closed by the code-assessment remediation pass: CI now runs a
privileged job (full `:integration` suite as root on `ubuntu-24.04`), an
aarch64 leg, and the seccomp kernel-acceptance tests in the default
unprivileged suite. Still open:

- **Deterministic PTY backpressure flush test.** The 1 MiB overflow cap and
  `pty_in_dropped` event are covered with a non-reading workload. The separate
  buffer→`POLLOUT`→flush handoff is still exercised only indirectly by the
  64 KiB flood test; add a reader-controlled workload that proves bytes held
  during backpressure arrive after reading resumes.

- **Privileged, adversarial pid-reuse coverage.** Namespace-entry identity
  re-verification is covered for the happy path, but a racing pid recycle is
  not reproduced. It is difficult to make deterministic; document it as a
  known coverage limit if no reliable harness is built.

## Deferred features

(The `~NFT` text frontend and its parity roadmap were removed on the
`remove-nft` branch — an unconsumed approximation of nft's own frontend that
set expectations of exact parity it couldn't honor. The pipeline DSL is the
authoring surface; the frontend lives in git history if ever wanted again.)

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

- **fd-pinned mount targets (`move_mount(2)`).** `ensure_target_file`'s
  `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)` validates the target
  path at creation time, but the fd is discarded and `mount(2)` re-resolves
  the target *string* — a check-to-use window in which an adversarial
  container can swap a parent directory for a symlink and redirect the
  privileged mount. The race-free mechanism is to keep the validated
  `O_PATH` fd and mount through it (`open_tree` + `move_mount` with
  `MOVE_MOUNT_T_EMPTY_PATH`), and to give the non-create mount, `umount2`,
  and `pivot_root` targets the same treatment. Until then this is a known
  limit against *live* adversarial containers; the typical call precedes
  the workload.
