# 09 — CI privileged integration job

**Status:** planned · **Gates 0.1.0:** no (fast-follow) · **Topic:** automated verification of the kernel layer

Companion: `09b` (ASan/UBSan), split out.

## Problem
CI runs only the non-integration suite (`ci.yml` final step `mix test --warnings-as-errors`;
`test/test_helper.exs` does `ExUnit.start(exclude: [:integration])`). So **every
kernel-mutating path is unverified in automation** — rtnl link/addr/route writes, nf_tables
commits, cgroup/mount/user/capability application, and — highest severity — **seccomp
enforcement**, which can fail *open* while CI stays green. The 15 `:integration` test files
run only locally via `./sudotest.sh`. `ci.yml` itself admits the gap ("A privileged job is a
planned follow-up").

## Decision / approach (staged; non-required first)
1. **Triage.** On a `ubuntu-24.04` runner with passwordless `sudo`, run the integration
   suite and record what the runner kernel actually supports (user/net/pid/mount
   namespaces, nf_tables + the expression set, cgroup v2 knobs, NFLOG, sysctl writes).
   Tag the genuinely-unsupportable cases with a capability tag (e.g.
   `@tag :requires_nflog`) so they skip with a *visible reason*, never silently.
2. **`integration` job.** Add a second job that installs the needed userspace
   (`iproute2`, `nftables`) and runs the suite the way `sudotest.sh` does:
   `sudo --preserve-env=PATH,HOME,ASDF_DIR env "PATH=$PATH" $(which mix) test
   --include integration` (adjust for the `setup-beam` PATH). Single Elixir/OTP cell is
   fine (the floor); breadth stays on the existing non-privileged matrix.
3. **Gate: non-required first.** Land it **informational** (`continue-on-error` /
   not a required check) so flakiness doesn't block merges during triage; **promote to
   required** once it's green and stable on the supported subset.

## Relationship to 0.1.0
Fast-follow, **not** a 0.1.0 blocker. The 0.1.0 gate is therefore a **documented manual
`./sudotest.sh` on the exact release commit** (already referenced in `02a` and `07`). `09`
is what later removes that manual dependency; until the job is *required*, a green badge
still does not certify the kernel layer.

## Coupling
- `02a` — the rewritten wire-layer error paths (permission failures → structs) are
  verified here.
- `06` — a non-Linux CI leg, if added, surfaces the new friendly OS message.
- `07` / `09b` — the C zero-length fixes get their real backstop from `09b`'s sanitizers,
  which build on this job.
- `10` — new seccomp/parser property tests run in the existing non-privileged job, not here.

## Concrete changes
- `test/**` — capability tags for kernel features the runner lacks; keep `:integration`
  as the umbrella tag.
- `.github/workflows/ci.yml` — new `integration` job (sudo, apt deps, `--include
  integration`), informational at first.
- `sudotest.sh` — reuse as-is locally; the CI step mirrors its invocation.

## Acceptance check
- The `integration` job runs the supported subset green on `ubuntu-24.04`; unsupported
  tests skip with a named capability tag (no silent omissions).
- Seccomp *enforcement* tests run in CI (the fail-open gap is closed in automation).
- Job is informational initially; a follow-up flips it to required once stable.

## Risk / scope notes
- Real work is **discovery**: what the GH runner kernel supports is unknown until run; some
  subsystems may stay local-only and that must be explicit.
- `sudo` + `setup-beam` PATH propagation is the usual friction; `sudotest.sh` already
  solves the local form.
- Single-cell integration is acceptable; the kernel surface, not the Elixir/OTP version, is
  what's under test.
