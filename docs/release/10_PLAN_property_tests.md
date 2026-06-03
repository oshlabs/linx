# 10 — Seccomp enforcement + parser property tests

**Status:** planned · **Gates 0.1.0:** no (fast-follow) · **Topic:** unit-level coverage for the highest-risk pure code

## Problem
The pure-logic core is well property-tested (ip, mac, netlink attrs, nft round-trip, sysctl
keys, cgroup reconcile, rtnl diff, link64), but three high-risk areas have **example tests
only**:

- **Seccomp — fail-open risk.** The compiler is example-tested; whether a compiled filter
  actually *blocks* a syscall is proven only by a kernel-gated integration test
  (`seccomp_test.exs`). A miscompile that falls through to ALLOW would pass all of CI.
  There is **no cBPF evaluator** anywhere in the tree to catch this at the unit level.
- **mountinfo parser** — example-only, despite parsing kernel text with optional fields
  (`mount_test.exs`, `parse_mountinfo`).
- **netlink Message codec** (full frame) — example-only; only the *attribute* layer is
  property-tested (`attr_property_test.exs`).

## Decision / approach
Add property tests in the established `test/linx/**/_property_test.exs` style.

1. **Seccomp fail-open guard — in-test cBPF evaluator.** Write a minimal cBPF interpreter
   in the test: it runs a compiled program over a `seccomp_data` input
   (`{nr, arch, ip, args[6]}`) and returns the verdict, covering the opcodes the compiler
   emits (`BPF_LD` / `BPF_JMP` / `BPF_RET`). Property: for a **random rule set** and random
   `(arch, syscall_nr)`, the program's verdict **equals the rule set's intended verdict**.
   Plus structural invariants: every path terminates in a `RET` (no fallthrough to an
   implicit ALLOW), and all jump offsets are in-bounds. This is what certifies no syscall
   silently slips through.
2. **Seccomp round-trip** — `from_rules(to_rules(filter)) == filter` over random rule sets
   (cheap; complements #1 and exercises the data seam).
3. **mountinfo** — generator for *valid* mountinfo lines including the optional-fields
   section; property: `parse_mountinfo` round-trips fields faithfully; plus robustness
   (malformed/truncated lines don't crash, return a sensible shape).
4. **netlink Message** — generator for messages; property: `encode |> decode == message`,
   complementing the existing attr round-trip.

Kernel **enforcement** stays in the integration test (the real-kernel proof); these add the
per-push, non-privileged guarantees.

## Relationship to 0.1.0
Fast-follow. For 0.1.0, seccomp enforcement is covered by the manual `./sudotest.sh` on the
release commit (topic `09`). `10` makes the fail-open guard a CI check on every push.

## Coupling
- Runs in the existing **non-privileged** matrix job (no root needed) — independent of `09`.
- `02b` tightened the seccomp/parser error specs; the generators should exercise the
  documented error shapes too.

## Concrete changes
- `test/linx/seccomp/compiler_property_test.exs` — the cBPF evaluator + verdict-equivalence
  + structural-invariant properties.
- `test/linx/seccomp/round_trip_property_test.exs` — `from_rules`/`to_rules`.
- `test/linx/mount/mountinfo_property_test.exs` — parser round-trip + robustness.
- `test/linx/netlink/message_property_test.exs` — codec round-trip.
- A small test-support cBPF evaluator module (test-only).

## Acceptance check
- The seccomp property test fails on an injected miscompile (e.g. a deliberately wrong jump
  offset that lets a denied syscall through) — i.e. it genuinely catches fail-open.
- mountinfo and Message round-trip properties pass over generated inputs and don't crash on
  malformed input.
- All new property tests run green in the non-privileged CI job.

## Risk / scope notes
- The cBPF evaluator is the only nontrivial piece (~a small VM for a handful of opcodes);
  scope it to exactly what the compiler emits, not a general BPF machine.
- Pure-Elixir, no kernel — fully CI-runnable, which is the point: it moves the
  highest-severity guarantee (seccomp doesn't fail open) out of the manual integration path.
