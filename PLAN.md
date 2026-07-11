# Linx — plan

Forward-looking work, post-0.2.0. This file captures what's intentionally
deferred. (The detailed per-topic release plans were working scaffolding; they
live in git history under `docs/release/` if needed. The full-codebase
assessment and its remediation checklist live in `docs/code-assessment.md`.)

This is a maintainer doc — it is not shipped in the hex package and does not
render on hexdocs.

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

## Deferred features

The `~NFT` parser/compiler now has its own roadmap to full nftables parity —
see `NFT-PLAN.md`, which is authoritative for `~NFT` state. (Concatenated set
types and pipapo interval concatenations, once listed here, landed 2026-07-02
kernel-verified; the one `~NFT` item below is kept here only until it lands.)

- **`~NFT` ranges over host-byte-order fields** (`meta mark 10-20`): needs a
  byteorder-conversion expression before the set lookup; the compiler
  currently refuses with a clear error rather than mis-encoding.
- **`openat2(RESOLVE_BENEATH)` hardening** for `linx_mount`'s target-file
  creation when used against live (adversarial) containers — the final
  component is already `O_EXCL|O_NOFOLLOW`-protected.
