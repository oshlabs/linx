# Linx.Seccomp — implementation plan

> **All three milestones shipped on `seccomp-foundations`.** S0
> scaffolding + S1 BPF compiler + filter verbs + S2 agent-side
> install. This doc records the design notes; `COVERAGE.md` carries
> the live status table; `EXAMPLES.md` carries the runnable recipes.

## Goal

Build the foundations of `Linx.Seccomp`: the kernel's syscall-filter
facility — a per-thread BPF program the kernel runs on every syscall
entry, deciding whether to allow / errno / kill / trap / log — exposed
as Elixir primitives.

This is the third leg of the security-isolation tripod that
`Linx.User` (identity) and `Linx.Capabilities` (privileged operations)
already provide. Together the three make a workload's kernel surface
small, well-defined, and auditable: an attacker who finds a 0-day in
the kernel's capability check still can't reach the relevant code path
if seccomp denies the syscall outright.

The motivating composition (lands fully at S2):

    {:ok, c} = Linx.Process.spawn(argv: ["/usr/sbin/nginx"],
                                   no_new_privs: true)
    {:ok, host_pid} = Linx.Process.host_pid(c)
    receive do {:linx_process, :ready, _} -> :ok end

    filter = Linx.Seccomp.allow_list(
      [:read, :write, :openat, :close, :fstat, :brk, :mmap,
       :munmap, :mprotect, :rt_sigprocmask, :rt_sigaction,
       :rt_sigreturn, :exit_group, :accept4, :bind, :listen,
       :socket, :connect],
      default: :kill_process
    )

    :ok = Linx.Seccomp.install(c, filter)
    :ok = Linx.Process.proceed(c)

After `proceed/1`, nginx runs with that syscall envelope. A bug that
tries to call `execve(2)` (not on the list) kills the process; the
kernel never enters `do_execve`.

`Linx.Seccomp` is **not** a policy engine or a JSON-profile parser.
It exposes "build a BPF filter from atoms; install it at the
checkpoint." Higher-level concerns (mapping Docker `seccomp.json` to
Linx filters; per-image policy resolution; auditing) live in
consumers — the natural home for that is the **Silo** project that
builds on Linx.

## Locked-in design decisions

These were agreed before the PLAN was written; the rest of the
document is built around them. Don't quietly drift on any of these
without surfacing the change.

### D1. Default actions are asymmetric per builder

- **`allow_list/2`** defaults to **`:kill_process`** for non-listed
  syscalls. Allow-lists are contracts ("I have enumerated what's
  safe"); a syscall outside is a bug or attack and should fail
  loudly. Matches modern runc / podman.
- **`deny_list/2`** defaults to **`{:errno, :eperm}`** for listed
  denies. Deny-lists are graceful-degradation lists; matches
  Docker's default profile.

Both defaults are overridable via `default:` opt.

### D2. NNP handling is "both"

- New `no_new_privs: boolean()` option on `Linx.Process.spawn/1`
  and `Linx.Process.enter/2` (default `false`). When `true`, the
  agent does `prctl(PR_SET_NO_NEW_PRIVS, 1)` in the child before
  the checkpoint loop starts. This is the principled home — NNP
  is a spawn-time security posture, not a seccomp concern.
- `Linx.Seccomp.install/2` also sets NNP itself if it sees it's
  not on and the caller isn't `CAP_SYS_ADMIN`. This is the "be
  helpful" path — callers who forgot the spawn opt shouldn't have
  `install/2` fail mysteriously.

In practice almost every seccomp-installing caller wants NNP, so
the auto-set is the right ergonomics. The explicit spawn opt
remains for callers who want NNP without seccomp.

### D3. Syscall atoms are unprefixed

`:read`, `:write`, `:open`, `:openat`, `:execve`, `:setns`,
`:bpf`, `:ptrace`. Not `:sys_read` etc.

- Kernel canonical names are `__NR_read`, `__NR_open` — unprefixed.
  `sys_*` is the kernel's internal C function name, not the
  syscall identity.
- Syscall atoms appear in lists (`allow_list([:read, :write,
  :openat])`), never as message tags — the "ambiguous in mixed
  mailbox" concern that drove `Linx.Capabilities`'s `:cap_*`
  prefix doesn't apply.
- Filters get verbose fast; unprefixed reads better.

### D4. Per-arg matching is deferred

S1 ships allow/deny **by syscall name only**. No `allow_if(:open,
&(&1.flags == :read_only))`-style argument predicates in S1.

- The BPF generator is the highest-risk piece of S1 (wrong bytes
  → silent allow or workload kill). Get it right for the simple
  case first.
- Docker's default ~50-syscall filter is syscall-name-only;
  Chrome's renderer-sandbox filter is mostly syscall-name-only.
  We cover the 80% on day one.
- The DSL design for argument predicates is its own meaningful
  surface (closure? data tuple? mini-language?) that deserves a
  separate design pass. Plan for an S1.5 follow-up branch after
  S2 merges, extending the builder with `allow_if/3` /
  `deny_if/3`.

### D5. Single-arch filters in v1

Each spawned filter targets exactly **one architecture** — the
architecture the agent is running on. No multi-arch routing.

- Linx's spawn always inherits the agent's arch, so the workload's
  arch is known.
- Multi-arch filters (the "check arch first, then route to per-
  arch syscall table" pattern Docker uses for x32-on-x86_64,
  i386-on-x86_64) add real complexity for cases that don't apply
  to Linx's spawning model.
- We support both **x86_64** and **aarch64** as host architectures.
  The right table is picked at filter-build time via `uname -m`
  (or equivalent).

If a future use case demands cross-arch filtering, S1.5 / S2.5
revisits.

### D6. Hand-curated syscall table

`Linx.Seccomp.Syscalls` ships a hand-curated list of ~150 syscalls
that cover (a) the common workload subset (read/write/openat/etc.),
(b) the dangerous-syscall deny-list Docker uses, and (c) the
namespace / capability syscalls Linx itself uses.

This is a deliberate tradeoff: a complete table (~400 syscalls per
arch) is generated noise; the hand-curated subset covers practical
filters and is easy to audit. The module includes explicit comments
documenting how to extend the table (where to source the numbers
from) — see "Extending the syscall table" below.

### D7. Two-layer API — sugar + data

- **Sugar layer** for callers who know what they want at compile
  time: `allow_list/2`, `deny_list/2`, `Builder` with `allow/2`,
  `deny/3`, `build/1`.
- **Data layer** for consumers like Silo that build filters from
  external sources (Docker `seccomp.json`, custom DSLs, runtime
  policy): `from_rules/1` accepting a plain Elixir
  list-of-tuples representation; `to_rules/1` for the inverse
  if cheap.

Silo's job: parse JSON → transform to rules list → call
`Linx.Seccomp.from_rules/1`. Linx never knows about JSON.

## Guiding principles

**Per-thread syscall installation — same as Linx.Capabilities.**
`seccomp(2)` operates on the calling thread. The kernel forbids
cross-thread installation. So the **child agent** in
`linx_process.c` must install the filter, not the BEAM directly.
S2 hooks into the existing checkpoint-window command protocol that
K2 already built — one more command type in an existing dispatch
table.

**Pure-Elixir cBPF generator — no libseccomp dependency.** Linx
hasn't linked a userspace dep beyond what the BEAM gives us, and we
won't start here. The cBPF format is small and well-documented
(`linux/filter.h`); ~10–20 instructions for typical filters. Heavy
unit testing required — wrong bytes either silently allow danger or
kill the workload, both bad.

**MapSets of `:cap_*`-style atoms — same shape as Capabilities.**
Syscall atoms in lists or MapSets at the API; binary cBPF on the
wire. Conversion isolated to `Linx.Seccomp.Syscalls`.

**Errors as structs.** `%Linx.Seccomp.Error{operation, errno,
code}` mirrors `Linx.Capabilities.Error` / `Linx.User.Error`.
Operations include `:install`, `:set_no_new_privs`, `:build`. Pre-
exec kernel failures from the agent surface via
`{:linx_process, :error, errno, stage}` with new stages
`:seccomp_install`, `:seccomp_no_new_privs`.

**No `:in` option.** Filter install is checkpoint-bound to the
spawned session, same as the K2 cap verbs. No setns dance.

**AGENTS.md style throughout:** `@moduledoc`/`@doc`/`@spec`
everywhere; cite `seccomp(2)`, `prctl(2)`, `bpf(2)`, the
`linux/seccomp.h` and `linux/filter.h` headers in comments where
interpretation is non-obvious.

## Module structure

```
Linx.Seccomp                       — Public API:
                                       supported?/0, install/2,
                                       allow_list/2, deny_list/2,
                                       from_rules/1, to_rules/1,
                                       arch/0.

Linx.Seccomp.Filter                — %Linx.Seccomp.Filter{
                                       arch, bpf, rules, summary}
                                     value type. `bpf` is the raw
                                     binary; `rules` is the data-
                                     layer representation; `arch`
                                     is the target arch atom. Custom
                                     Inspect.

Linx.Seccomp.Builder               — The fluent DSL:
                                       Linx.Seccomp.builder()
                                         |> allow(:read)
                                         |> deny(:ptrace, errno: :eperm)
                                         |> build(default: :kill_process)

Linx.Seccomp.Syscalls              — @moduledoc false. Per-arch
                                     hand-curated tables, plus
                                     arch/0, to_number/2,
                                     from_number/2, all/1. Includes
                                     explicit comments on how to
                                     extend the table.

Linx.Seccomp.Constants             — @moduledoc false. BPF opcodes
                                     (BPF_LD, BPF_LDX, BPF_JMP,
                                     BPF_RET, …) and SECCOMP_RET_*
                                     action constants. Used by the
                                     cBPF generator.

Linx.Seccomp.Compiler              — @moduledoc false. Takes a
                                     normalised rules list and emits
                                     a binary cBPF program in the
                                     kernel's struct sock_fprog wire
                                     format. The risky bit.

Linx.Seccomp.Error                 — %Linx.Seccomp.Error{operation,
                                     errno, code} + Exception impl
                                     + from_posix/2. Operations:
                                     :build (caller-side compile
                                     failures), :install /
                                     :set_no_new_privs (agent-side,
                                     but the struct is also used
                                     for normalising errors that
                                     come back through Linx.Process).
```

C-side: `c_src/linx_process.c` gains:
- New stage atoms `STAGE_SECCOMP_INSTALL` / `STAGE_SECCOMP_NO_NEW_PRIVS`
- New `apply_seccomp(fprog_data, fprog_len)` helper in the child
- New `apply_no_new_privs()` helper in the child
- New branch in `child_read_command()` for `{:seccomp_install, fprog_binary}`
- New branch in `await_proceed()` to forward the frame to p2c
- Optionally `apply_no_new_privs()` called early in child_fn if
  the `no_new_privs` field in `struct child_args` is set (the
  spawn-time NNP path)
- `struct child_args` gains a `no_new_privs` bool field
- `decode_request` parses an `:no_new_privs` boolean from the
  request map

## The kernel surface

| Source | Read | Write |
|---|---|---|
| `prctl(PR_GET_SECCOMP)` | mode (0=disabled, 1=strict, 2=filter) | — |
| `prctl(PR_GET_NO_NEW_PRIVS)` | 0 or 1 | — |
| `seccomp(SECCOMP_GET_ACTION_AVAIL)` | does kernel support this RET action? | — |
| `prctl(PR_SET_NO_NEW_PRIVS, 1)` | — | sets NNP on calling thread |
| `seccomp(SECCOMP_SET_MODE_FILTER, flags, &fprog)` | — | installs filter on calling thread |
| `/proc/self/status` | `Seccomp:` line | (read-only) |

For S0 we use the procfs `Seccomp:` line for `supported?/0` (same
pattern as `Linx.Capabilities.supported?/0`).

## Sequencing — milestones

### S0 — Scaffolding + constants + arch detection

**Module skeletons** (stubs returning `{:error, :not_yet_implemented}`
for verbs that land later):

- `Linx.Seccomp` public module with `@moduledoc` + stubs for
  `install/2`, `allow_list/2`, `deny_list/2`, `from_rules/1`,
  `to_rules/1`.
- `Linx.Seccomp.Builder` — same, stubs for `builder/0`, `allow/2`,
  `deny/3`, `build/1`.

**Real S0 surface:**

- `Linx.Seccomp.supported?/0` — `true` iff
  `/proc/self/status` contains a `Seccomp:` line. True on every
  Linux ≥ 3.5.
- `Linx.Seccomp.arch/0` — returns one of `:x86_64`, `:aarch64`, or
  `:unsupported`. Resolved at runtime via `:erlang.system_info(:os_type)`
  + `:os.cmd('uname -m')` (or `:erlang.system_info(:machine)`,
  whichever proves more reliable). Cached after first call.
- `Linx.Seccomp.Syscalls` (`@moduledoc false`) with:
  - The ~150-syscall hand-curated table per arch (see "Extending
    the syscall table" below for the procedure to extend).
  - `arch/0` — wraps `Linx.Seccomp.arch/0`.
  - `to_number/2` — `(:read, :x86_64) → 0`; `(:read, :aarch64) → 63`.
    Returns `nil` for unknown atoms or unsupported arch.
  - `from_number/2` — inverse; returns `:unknown` for unknown
    numbers (forward-compat with future kernel syscalls).
  - `all/1` — all known syscalls for the given arch as a MapSet.
- `Linx.Seccomp.Constants` (`@moduledoc false`) with:
  - BPF opcode constants: `bpf_ld()`, `bpf_w()`, `bpf_abs()`,
    `bpf_ldx()`, `bpf_jmp()`, `bpf_jeq()`, `bpf_ret()`, `bpf_k()`,
    `bpf_a()`. (Functions rather than module attributes so they
    can compose into instructions.)
  - `SECCOMP_RET_*` action constants: `:allow`, `:errno`,
    `:kill_process`, `:kill_thread`, `:trap`, `:log`. Plus
    `action_to_u32/1` and `action_from_u32/1` for the wire format
    (e.g. `:allow → 0x7fff0000`).
  - The `arch` numeric values: `AUDIT_ARCH_X86_64 = 0xC000003E`,
    `AUDIT_ARCH_AARCH64 = 0xC00000B7`.
- `%Linx.Seccomp.Filter{}` struct with `@enforce_keys [:arch,
  :bpf, :rules]` + optional `:summary` field. Compact Inspect:
  `#Linx.Seccomp.Filter<x86_64 41 syscalls, 12 BPF insns>`.

**Tests (plain):**

- `supported?/0` returns boolean; agrees with the canonical check.
- `arch/0` returns one of `:x86_64`, `:aarch64`, `:unsupported`.
- `Syscalls.to_number/2` for known cases on both arches.
- `Syscalls.from_number/2` returns `:unknown` for bogus numbers.
- `Syscalls.all/1` size matches table size for each arch.
- `Constants` action round-trips: `action_to_u32(:allow) |>
  action_from_u32() == :allow` for every action.
- `%Filter{}` `@enforce_keys` enforcement + Inspect rendering.
- Stubs return `{:error, :not_yet_implemented}`.

**Docs in this milestone:**

- `docs/seccomp/PLAN.md` (this doc).
- `docs/seccomp/COVERAGE.md` — every planned surface in ⬜.
- `docs/seccomp/REFERENCES.md` — `seccomp(2)`, `prctl(2)`,
  `bpf(2)`, `linux/seccomp.h`, `linux/filter.h`, Kernel's
  `Documentation/userspace-api/seccomp_filter.rst`.
- `docs/seccomp/EXAMPLES.md` skeleton with the headline
  composition + supported?/0 + arch/0 examples.

Wire `docs/seccomp/*.md` into `mix.exs` `docs.extras` + groups.
Add `Linx.Seccomp` + `Linx.Seccomp.Filter` to
`groups_for_modules`.

### S1 — BPF builder + compiler

**The risky milestone.** A wrong cBPF program either silently
allows dangerous syscalls or kills the workload — both bad. Heavy
unit testing required.

- `Linx.Seccomp.Compiler` (`@moduledoc false`):
  - Takes a normalised rules list and the target arch.
  - Emits a binary cBPF program as a `<<bytes::binary>>` ready to
    be packed into `struct sock_fprog`.
  - Generated structure (the standard pattern):

        # 1. Load arch (offset 4 in struct seccomp_data) into A.
        # 2. Compare to AUDIT_ARCH_<host>; if mismatch, RET KILL.
        # 3. Load syscall number (offset 0) into A.
        # 4. For each rule, JEQ syscall_no, jump to action label.
        # 5. Otherwise RET <default action>.
        # 6. Action labels at the bottom: RET <action> | <errno>.

  - Uses jump-distance computation to handle the fact that BPF
    jumps are forward-only with 8-bit offsets (max jump = 255
    instructions). For filters with > ~250 syscalls, the
    compiler needs to insert jump-trampolines. Document this; the
    hand-curated 150-syscall table fits comfortably under the
    limit so we can defer the trampoline path to a future
    refinement (panic with a clear error if exceeded).

- `Linx.Seccomp.allow_list/2`:

      def allow_list(syscalls, opts \\ []) do
        default = Keyword.get(opts, :default, :kill_process)
        rules = Enum.map(syscalls, &{:allow, &1})
        from_rules({rules, default})
      end

- `Linx.Seccomp.deny_list/2`:

      def deny_list(syscalls, opts \\ []) do
        default = Keyword.get(opts, :default, :allow)
        deny_action = Keyword.get(opts, :deny_action, {:errno, :eperm})
        rules = Enum.map(syscalls, &{deny_action, &1})
        from_rules({rules, default})
      end

- `Linx.Seccomp.from_rules/1`:
  - Accepts `{rules, default_action}` where `rules` is a list of
    `{action, syscall_atom}` tuples.
  - Validates: each syscall atom is known on the current arch;
    each action is well-formed (`:allow`, `:kill_process`,
    `{:errno, _errno_atom}`, etc.).
  - On success returns `{:ok, %Filter{}}`.
  - On caller-side errors returns `{:error, {:unknown_syscall,
    atom}}`, `{:error, {:bad_action, term}}`,
    `{:error, {:duplicate_rule, atom}}`.

- `Linx.Seccomp.to_rules/1` — inverse where reasonable. Given a
  `%Filter{}` we built ourselves, returns the rules list. For an
  externally-supplied raw BPF blob (future Silo use case), this
  is "not supported, the filter doesn't carry rule metadata."
  Document the limitation.

- `Linx.Seccomp.Builder`:

      Linx.Seccomp.builder()
      |> Linx.Seccomp.Builder.allow(:read)
      |> Linx.Seccomp.Builder.allow(:write)
      |> Linx.Seccomp.Builder.deny(:ptrace, errno: :eperm)
      |> Linx.Seccomp.Builder.build(default: :kill_process)
      # => {:ok, %Linx.Seccomp.Filter{}}

  Internal representation is the rules list; `build/1` just calls
  `from_rules/1` on it.

- `Linx.Seccomp.Error` struct + Exception impl, `from_posix/2`.

**Testing strategy** (the heart of S1):

1. **Plain unit tests** for `allow_list/2`, `deny_list/2`,
   `from_rules/1`, `Builder` — input validation, rule
   normalisation, error shapes.

2. **Plain unit tests** for the `Compiler`: golden tests that
   compare emitted BPF bytes against hand-verified expected
   bytes for small filters (empty, single syscall, multi-
   syscall). Use the kernel headers as truth for the wire
   constants.

3. **Kernel-acceptance tests**: spawn a child via `:os.cmd` or
   `Port.open` that runs a small C-style helper (or even
   `python3 -c '...'` invoking the seccomp libc bindings) that
   reads a filter from stdin and calls `seccomp(2)`. If the
   kernel returns `EINVAL` the filter is malformed; if it
   returns 0 the filter is structurally accepted (doesn't
   guarantee semantic correctness but catches all the cBPF
   encoding bugs). These tests are tagged `:integration`
   because they spawn an external process; they don't need
   root because `seccomp` accepts filters from any process.

4. **End-to-end semantic tests** lands in S2 — actually install
   the filter and observe behaviour on a real workload.

**Tests for S1:** roughly 30-50 tests covering input validation,
rule normalisation, error shapes, and at least 5-8 golden-byte
tests against known-good cBPF.

### S2 — Agent-side install + Linx.Process integration

The smaller, more mechanical milestone because the K2 protocol
scaffolding already exists.

**C side** (`c_src/linx_process.c`):

- New STAGE enum values + `stage_name` cases:
  - `STAGE_SECCOMP_INSTALL = 6` (after STAGE_CAP_SET_AMBIENT = 5)
  - `STAGE_SECCOMP_NO_NEW_PRIVS = 7`

- New helpers in the child:
  - `apply_no_new_privs(void)` — `prctl(PR_SET_NO_NEW_PRIVS, 1)`.
  - `apply_seccomp(const void *bpf, size_t len)` — packs the BPF
    blob into `struct sock_fprog` and calls
    `syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &fprog)`.
    Direct syscall (not the libc wrapper) to avoid depending on
    glibc ≥ 2.27.

- `struct child_args` gains a `no_new_privs` bool field.
- `decode_request` parses an optional `:no_new_privs` boolean
  from the request map.
- In `child_fn`, if `ca->no_new_privs`, call
  `apply_no_new_privs()` very early (before the command loop) —
  the kernel allows NNP to be set at any time and once it's on
  later seccomp installs don't need CAP_SYS_ADMIN.
- New branch in `child_read_command()` for
  `{:seccomp_install, bpf_blob}`:
  - If NNP isn't already on and we're unprivileged, call
    `apply_no_new_privs()` first (the "be helpful" path from
    D2).
  - Call `apply_seccomp(bpf_blob, byte_size)`.
  - On either failure, `child_fail(c2p_w, errno, STAGE_*)`.
- `await_proceed()` gains a branch for `{:seccomp_install, _}`
  tuples — forward verbatim to p2c (same shape as cap commands).

**BEAM side** (`lib/linx/process.ex`):

- New `no_new_privs:` opt on `spawn/1` and `enter/2` — adds the
  boolean to the request map shipped to the agent.
- Three or four new `handle_call` clauses for `{:seccomp_install,
  bpf_blob}` mirroring the K2 cap-command shape (state-machine
  guards: `:not_ready` / `:running` / `:already_terminated`;
  forward to port at `:ready`).

**BEAM side** (`lib/linx/seccomp.ex`):

- `install/2`:

      def install(session, %Linx.Seccomp.Filter{} = filter) do
        GenServer.call(session, {:seccomp_install, filter.bpf})
      end

  Same error shapes as the K2 cap verbs.

**Moduledoc updates** in `lib/linx/process.ex`: extend the
"Error stages" section with `:seccomp_install` and
`:seccomp_no_new_privs`.

**Tests:**

- **Plain:** state-machine guards (install/2 returns :not_ready
  pre-checkpoint, :running post-execve, :already_terminated
  post-terminal). Input validation (install/2 rejects
  non-Filter args).
- **Integration (`./sudotest.sh`):**
  - Spawn `/bin/cat` with stdio :pty, install a tight allow_list
    that allows the syscalls /bin/cat actually uses (read,
    write, openat, close, exit_group, …); confirm /bin/cat
    runs to completion when given stdin.
  - Spawn `/bin/sleep 60`, install a filter that denies
    `:nanosleep` with `{:errno, :eperm}`; confirm /bin/sleep
    exits non-zero immediately rather than sleeping.
  - Spawn a workload, install a filter that denies a syscall
    with `:kill_process`; confirm the workload dies with the
    expected signal (SIGSYS).
  - Spawn a workload with `no_new_privs: true` on `spawn/1`;
    confirm the seccomp install succeeds even though the agent
    isn't `CAP_SYS_ADMIN` (the integration test does run as
    root via `sudotest.sh`, but the *child* in a fresh
    user namespace effectively isn't).
  - Confirm that a malformed BPF blob (test-constructed) surfaces
    as `{:linx_process, :error, EINVAL, :seccomp_install}`.

## Testing

Same three bands as the other subsystems:

- **Unit.** Constants tables; cBPF encoder golden tests; rule
  validation; struct shapes; state-machine assertions on the new
  verbs. Plain `mix test`.
- **Kernel acceptance.** S1 lands tests that hand a generated
  filter to a throwaway helper process which calls
  `seccomp(SECCOMP_SET_MODE_FILTER, ...)` and reports back
  whether the kernel accepted it. `:integration` tagged but
  doesn't need root.
- **End-to-end.** S2 lands integration tests that install
  filters on real workloads and observe behaviour. `:integration`
  tagged; runs via `./sudotest.sh`.
- **Manual / `docs/seccomp/EXAMPLES.md`.** The headline
  composition: spawn nginx, install an allow_list for its known
  syscalls, observe the workload runs correctly.

## Extending the syscall table

`Linx.Seccomp.Syscalls` ships a hand-curated subset. To add a
syscall:

### For x86_64

1. Get the syscall number from
   `arch/x86/entry/syscalls/syscall_64.tbl` in the kernel tree
   (e.g.
   https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_64.tbl),
   or from your local `/usr/include/asm/unistd_64.h`. Each line
   is `<number> <abi> <name> <entry-point>`; you want the
   `<name>` and `<number>` for the `common` or `64` abi.

2. Add the atom-to-number mapping to the `@x86_64` map in
   `lib/linx/seccomp/syscalls.ex`.

### For aarch64

1. aarch64 uses the generic syscall table at
   `include/uapi/asm-generic/unistd.h` (e.g.
   https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/unistd.h).
   Numbers are defined as `#define __NR_<name> <number>`.

2. Add the atom-to-number mapping to the `@aarch64` map.

### Verifying

Run the round-trip tests after editing:

    mix test test/linx/seccomp_test.exs

The `to_number/2` and `from_number/2` round-trip tests catch
table inconsistencies (e.g. a number appearing twice, or an atom
missing from one arch).

### Adding a new architecture

(Not planned for v1.) Steps would be:

1. Add an arch atom to `Linx.Seccomp.Syscalls.arch/0`'s match
   list.
2. Add the `AUDIT_ARCH_<NEW>` constant to
   `Linx.Seccomp.Constants`. Find the value in
   `include/uapi/linux/audit.h` in the kernel tree.
3. Add a per-arch syscall map following the existing
   convention.
4. Add the arch to the supported-arches type spec on `arch/0`
   and update tests.

## Deferred — architected-for, not built here

- **Per-argument matching** (`allow_if(:open, &(&1.flags == :rdonly))`)
  — S1.5 follow-up. Per D4.
- **Multi-arch filters** (route on AUDIT_ARCH first, then per-arch
  syscall table) — defer until a real Linx use case appears.
  Per D5.
- **`SECCOMP_USER_NOTIF`** — delegating decisions to userspace
  handlers. A whole second feature surface; great for advanced
  sandboxing but unrelated to the basic story. Future S3 or
  sibling module `Linx.Seccomp.UserNotify`.
- **Docker `seccomp.json` parsing** — belongs in Silo, not Linx.
  Linx's `from_rules/1` is the seam Silo would call after parsing
  the JSON. Per D7.
- **Filter introspection beyond `to_rules/1`** — disassembling
  arbitrary BPF blobs back to a rules form. Doable but rarely
  needed; defer until a consumer asks.
- **`/proc/<pid>/status`-style filter inspection for an existing
  process** — `Seccomp:` line gives mode but not the filter
  contents. Linux exposes filters via `ptrace(PTRACE_SECCOMP_GET_FILTER)`
  which we'd need CAP_SYS_PTRACE for. Niche; defer.
- **Filter introspection via `seccomp(SECCOMP_GET_NOTIF_*)`** —
  not actually about filter introspection; it's part of the
  USER_NOTIF mechanism. Bundled there.
- **`prctl(PR_GET_NO_NEW_PRIVS)` query verb** — could ship a
  `Linx.Process.no_new_privs?/1` accessor. Useful but small;
  defer to a separate "Linx.Process accessors" follow-up.

## Decisions reference

| ID | Decision | Rationale |
|---|---|---|
| D1 | `allow_list` default `:kill_process`; `deny_list` default `{:errno, :eperm}` | Asymmetric semantics match builder intent |
| D2 | NNP via spawn opt **and** auto-set in install/2 | Principled home + helpful ergonomics |
| D3 | Unprefixed syscall atoms (`:read`, not `:sys_read`) | Matches kernel naming; reads better in lists |
| D4 | Per-arg matching deferred to S1.5 | Reduce S1 risk; ship 80% solution first |
| D5 | Single-arch filters in v1; x86_64 + aarch64 only | Multi-arch doesn't fit Linx's spawning model |
| D6 | Hand-curated ~150-syscall table per arch | Auditable; extension procedure documented |
| D7 | Two-layer API: sugar (`allow_list`) + data (`from_rules`) | Silo and other consumers get a clean seam |

## Why this fits Linx (and not Silo)

The line: **Linx exposes the kernel primitive; Silo composes
primitives into policy.**

- "Build a BPF filter from a list of syscall atoms" — kernel
  primitive surface. **Linx.**
- "Install a filter on this process at the right moment" —
  kernel primitive surface. **Linx.**
- "Parse this Docker `seccomp.json` file" — policy / format
  adapter. **Silo.**
- "Look up which syscalls nginx 1.24 needs and emit a
  Linx.Seccomp.allow_list for them" — policy. **Silo.**
- "Track which workloads have which filters; allow operator
  override at runtime" — orchestration. **Silo.**

The `from_rules/1` / `to_rules/1` pair is the seam between
them. Silo translates whatever external representation it
chooses into a `[{action, syscall_atom}, ...]` list and hands
it to Linx. Linx never knows about JSON, YAML, image labels,
or operator UX.
