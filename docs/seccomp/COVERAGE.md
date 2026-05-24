# Linx.Seccomp coverage

What of the kernel's seccomp surface `Linx.Seccomp` exposes today,
what is planned, and what is deferred.

A living doc — update as primitives ship. Status legend:

| | |
|---|---|
| ✅ | done — shipped and tested |
| 🟡 | partial — some sub-features in, others not |
| ⬜ | todo — not yet |
| ⏳ | architected-for — design accommodates it, no code yet |

## Lifecycle / detection

| Feature | Status | Notes |
|---|---|---|
| `supported?/0` | ✅ | S0 — true iff `/proc/self/status` has `Seccomp:` line |
| `arch/0` | ✅ | S0 — returns `:x86_64`, `:aarch64`, or `:unsupported`; cached via `:persistent_term` |

## Syscall table

| Feature | Status | Notes |
|---|---|---|
| Hand-curated ~150-syscall table per arch | ✅ | S0 — see `PLAN.md` "Extending the syscall table" for the procedure |
| x86_64 support | ✅ | S0 — 239 syscalls |
| aarch64 support | ✅ | S0 — 214 syscalls (asm-generic table; no legacy unsuffixed verbs) |
| `to_number/2`, `from_number/2` | ✅ | S0 — atom ↔ number per arch; `:unknown` for unrecognised numbers (forward-compat) |
| `all/1` | ✅ | S0 — every known syscall for the given arch as a MapSet |
| `known?/2` | ✅ | S0 — convenience predicate for caller-side validation |

## Constants

| Feature | Status | Notes |
|---|---|---|
| BPF opcode primitives | ✅ | S0 — `bpf_ld`, `bpf_ldx`, `bpf_jmp`, `bpf_ret`, `bpf_jeq`, `bpf_jgt`, `bpf_jge`, `bpf_jset`, `bpf_ja`, `bpf_w`/`bpf_h`/`bpf_b`, `bpf_abs`/`bpf_imm`, `bpf_k`/`bpf_x`/`bpf_a` |
| `SECCOMP_RET_*` action constants | ✅ | S0 — `:allow`, `:errno`, `:kill_process`, `:kill_thread`, `:trap`, `:log` |
| `action_to_u32/1`, `action_from_u32/1` | ✅ | S0 — wire-format conversion; small POSIX errno table for `:errno` data |
| `AUDIT_ARCH_*` constants | ✅ | S0 — x86_64 (0xC000003E) and aarch64 (0xC00000B7); `audit_arch/1` helper |

## Value types

| Module | Status | Notes |
|---|---|---|
| `Linx.Seccomp.Filter` | ✅ | S0 — `%{arch, bpf, rules, summary}`; compact Inspect |
| `Linx.Seccomp.Error` | ⬜ | S1 — `%{operation, errno, code}`; Exception impl |

## BPF compilation (the risky milestone)

| Feature | Status | Notes |
|---|---|---|
| `allow_list/2` | ⬜ | S1 — defaults to `:kill_process` for non-listed |
| `deny_list/2` | ⬜ | S1 — defaults to `{:errno, :eperm}` for listed denies |
| `from_rules/1` | ⬜ | S1 — data-layer API; what Silo will use |
| `to_rules/1` | ⬜ | S1 — inverse for filters Linx itself built |
| `Builder` (fluent DSL) | ⬜ | S1 — `builder/0 \|> allow/2 \|> deny/3 \|> build/1` |
| Cap-BPF compiler (binary cBPF emit) | ⬜ | S1 — `Linx.Seccomp.Compiler`; golden-byte tests + kernel-acceptance tests |
| Forward-compat: unknown bits in unparsed filters | ⬜ | S1 — `from_number/2` returns `:unknown` for numbers past table |
| Jump-trampoline support (filters > 250 syscalls) | ⏳ | S1 — panic with clear error for now; trampolines later if needed |

## Write side (via Linx.Process agent at the checkpoint)

| Feature | Status | Notes |
|---|---|---|
| `install/2` | ⬜ | S2 — Elixir verb; only valid in `:ready` state |
| Agent-side `apply_seccomp` in `linx_process.c` | ⬜ | S2 — direct `syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, …)` |
| `{:seccomp_install, bpf_blob}` checkpoint command | ⬜ | S2 — forwarded verbatim through p2c (same as K2 cap commands) |
| State-machine guards (only at `:ready`) | ⬜ | S2 — mirrors `proceed/1` / `abort/1` / K2 cap verbs |
| Error stages `:seccomp_install`, `:seccomp_no_new_privs` | ⬜ | S2 — surface via `{:linx_process, :error, errno, stage}` |

## `PR_SET_NO_NEW_PRIVS` support

| Feature | Status | Notes |
|---|---|---|
| `no_new_privs:` opt on `Linx.Process.spawn/1` | ⬜ | S2 — sets NNP early in child_fn, before the command loop |
| `no_new_privs:` opt on `Linx.Process.enter/2` | ⬜ | S2 — same shape |
| `Linx.Seccomp.install/2` auto-sets NNP if unprivileged | ⬜ | S2 — "be helpful" path so callers who forgot the spawn opt don't get a confusing EPERM |

## Composition with other subsystems

| Pairing | Status | Notes |
|---|---|---|
| `Linx.Process` filter install at checkpoint | ⬜ | S2 — reuses the K2 command-protocol scaffolding |
| `Linx.Capabilities` + `Linx.Seccomp` interplay | ⏳ | S2 — documented in EXAMPLES; the composition order (caps then seccomp) matters but no Linx code needs to change |
| `Linx.User` + `Linx.Seccomp` (rootless) | ⏳ | S2 — works with `no_new_privs: true` and seccomp install in the new user ns; documented in EXAMPLES |

## Error reporting

| Mechanism | Status | Notes |
|---|---|---|
| `%Linx.Seccomp.Error{operation, errno, code}` | ⬜ | S1 — caller-side build failures (`:build` operation) |
| `{:linx_process, :error, errno, :seccomp_install}` | ⬜ | S2 — kernel-side install failures |
| `{:linx_process, :error, errno, :seccomp_no_new_privs}` | ⬜ | S2 — `PR_SET_NO_NEW_PRIVS` failures (rare) |
| `{:error, {:unknown_syscall, atom}}` | ⬜ | S1 — caller-side unknown atom |
| `{:error, {:bad_action, term}}` | ⬜ | S1 — caller-side malformed action |
| `{:error, {:duplicate_rule, atom}}` | ⬜ | S1 — caller-side duplicate syscall in a rule list |
| `{:error, {:unsupported_arch, atom}}` | ⬜ | S1 — caller-side filter built for an arch we don't support |

## Deferred — not in `Linx.Seccomp` itself

See `PLAN.md`'s "Deferred — architected-for, not built here" for
reasoning:

- Per-argument matching (`allow_if(:open, &(...))`) — S1.5
- Multi-arch filters (AUDIT_ARCH routing) — future if needed
- `SECCOMP_USER_NOTIF` (userspace decision handlers) — S3 or sibling
- Docker `seccomp.json` parsing — Silo, not Linx
- Filter disassembly from raw BPF — defer until a consumer asks
- `PTRACE_SECCOMP_GET_FILTER` for other processes — niche
