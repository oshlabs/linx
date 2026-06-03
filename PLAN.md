# Linx — plan

Forward-looking work. The 0.1.0 release preparation is complete — the public API,
docs, error contract, build preflight, and native hardening all landed. This file
captures what's intentionally deferred. (The detailed per-topic release plans were
working scaffolding; they live in git history under `docs/release/` if needed.)

This is a maintainer doc — it is not shipped in the hex package and does not render
on hexdocs.

## Immediate — publish 0.1.0

1. `mix hex.user auth` (or `register`).
2. Make `oshlabs/linx` public so `source_url` / "View Source" resolve.
3. Merge `hex-release-prep` → `main`, tag `v0.1.0`.
4. `mix hex.publish` (package + docs).

**Release gate:** `./sudotest.sh` green on the exact release commit — the kernel
layer is otherwise unverified in CI (see below).

## After 0.1.0 — verification fast-follow

The pure-logic layer is well tested, but every kernel-*mutating* path (rtnl writes,
nf_tables commits, cgroup/mount/user/capability application, and — highest severity —
seccomp enforcement) runs only under `./sudotest.sh`, which CI does not yet run. A
release can currently ship green with a regressed encoder or a fail-open seccomp
miscompile. Close the gap:

- **CI privileged integration job.** Run the `:integration` suite (root + namespaces)
  on a `ubuntu-24.04` runner. Triage what the runner kernel supports, tag the rest
  with capability tags, start the job non-required, promote it once stable. Removes
  the manual-`sudotest` release gate.

- **ASan / UBSan over the native code.** Build the four NIFs and the `linx_process`
  port with `-fsanitize=address,undefined` and run the suite under them — the port
  first (a standalone executable), the NIFs via `LD_PRELOAD` of libasan. First
  backstop for the `c_src` edge-case guards.

- **Property tests for the highest-risk pure code.** A small in-test cBPF evaluator
  that proves a compiled `Linx.Seccomp` filter actually blocks what it should (catches
  a fail-open miscompile — the scariest failure mode, currently only covered by a
  kernel-gated test); plus round-trip properties for the `/proc/<pid>/mountinfo`
  parser and the full netlink `Message` codec.
