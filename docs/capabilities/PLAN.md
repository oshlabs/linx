# Linx.Capabilities — implementation plan

> **Not yet shipped.** Work lives on branch `capabilities-foundations`.
> Milestones K0–K2 land independently; each commits + pushes per the
> Linx-wide "commit per milestone" rule.

## Goal

Build the foundations of `Linx.Capabilities`: the kernel's
capability surface — the five per-process cap sets (effective,
permitted, inheritable, bounding, ambient) and the syscalls that
manipulate them (`capget(2)`, `capset(2)`, `prctl(PR_CAPBSET_*)`,
`prctl(PR_CAP_AMBIENT_*)`) — exposed as Elixir primitives. Two
complementary use modes:

  * **Inspection** — read any process's cap sets from
    `/proc/<pid>/status` for debugging, monitoring, or security
    auditing.
  * **Drop-before-execve** — strip capabilities from a workload
    *before* it `execve`s, via agent-side checkpoint commands.
    The bread-and-butter of security-conscious container
    runtimes: spawn a workload but ensure it never starts with
    `CAP_SYS_ADMIN`.

The motivating composition:

    {:ok, c} = Linx.Process.spawn(argv: ["/usr/sbin/nginx"], stdio: :pty)
    receive do {:linx_process, :ready, _} -> :ok end

    # Strip everything the workload doesn't need before execve.
    keep = [:cap_net_bind_service]
    :ok = Linx.Capabilities.set_thread_sets(c,
            effective: keep, permitted: keep, inheritable: [])
    :ok = Linx.Capabilities.drop_bounding(c, all_except(keep))

    :ok = Linx.Process.proceed(c)

After `proceed/1`, the nginx workload runs with exactly
`cap_net_bind_service` and nothing else — even if its binary has
file caps that would otherwise grant more.

`Linx.Capabilities` is **not** a security-policy engine. It
exposes "drop these caps from this set on this session." Policy
(which workloads need which caps; how to audit drift) lives in a
consumer.

## Guiding principles

**Two layers — read (host-side) and write (agent-side).** The
read side parses `/proc/<pid>/status` from the host; it works
against any live process without cooperation from the target.
The write side is fundamentally different: capability
manipulation is per-thread (`capset(2)` and the `prctl` cap
calls all operate on the *calling thread*), so the *child agent*
has to do its own cap configuration. We add a small handful of
checkpoint-time commands to `linx_process.c` for the agent to
apply before `execve`.

**MapSets of atoms.** Cap sets are 64-bit kernel bitmasks of
~41 named capabilities. In Elixir they show up as `MapSet`s of
`:cap_*` atoms (`MapSet.new([:cap_net_admin, :cap_sys_admin])`).
Set operations (`MapSet.union/2`, `MapSet.difference/2`) come
free; the bitmask conversion happens in one place. Pattern
matching on cap atoms is natural; pattern matching on a u64 is
not.

**The atom names mirror the kernel.** `CAP_NET_ADMIN` becomes
`:cap_net_admin`. The `:cap_` prefix is kept so the atom is
unambiguous in a mailbox of mixed message types.

**`%Linx.Capabilities.State{}` is the read-side value type.**
Five MapSet-valued fields: `:effective`, `:permitted`,
`:inheritable`, `:bounding`, `:ambient`. Returned by `read/1`.
Inspect renders compactly.

**Errors as structs.** `%Linx.Capabilities.Error{path, operation,
errno, code}` mirrors `Linx.Mount.Error` / `Linx.User.Error`.
Operations: `:read` for the host-side parser; pre-exec failures
from agent-side cap manipulation arrive via `Linx.Process`'s
existing `{:linx_process, :error, errno, stage}` shape with new
stage atoms (`:cap_drop_bounding`, `:cap_set_thread`,
`:cap_set_ambient`).

**No `:in` option.** `/proc/<pid>/status` reads work via the
host's view of procfs (no setns), just like `Linx.User`'s map
files. Write paths go through the agent at the checkpoint, not
via cross-namespace setns.

**File capabilities (xattrs on binaries) deferred.** A distinct
concern from per-process caps — file caps configure *binaries*,
not *running workloads*. Useful but a separate audience; later
milestone or follow-up module.

**AGENTS.md style throughout:** `@moduledoc`/`@doc`/`@spec`
everywhere; cite `capabilities(7)`, `capset(2)`, `prctl(2)` in
comments where interpretation is non-obvious.

## Module structure

```
Linx.Capabilities                — public API: supported?/0,
                                   read/1, drop_bounding/2,
                                   set_thread_sets/2, set_ambient/2.

Linx.Capabilities.State          — %Linx.Capabilities.State{
                                     effective, permitted,
                                     inheritable, bounding,
                                     ambient}; each field is a
                                   MapSet of :cap_* atoms.
                                   Returned by read/1.

Linx.Capabilities.Constants      — the 41-entry atom ↔ bit table,
                                   plus all/0 (every known cap),
                                   to_bits/1, from_bits/1.
                                   @doc false utility module --
                                   consumers go through
                                   Linx.Capabilities.

Linx.Capabilities.Error          — %Linx.Capabilities.Error{path,
                                   operation, errno, code} +
                                   Exception impl.
```

C-side: `c_src/linx_process.c` gains three new
post-`:ready`-pre-`:proceed` commands in K2 (see below).

## The kernel surface

| Source | Read | Write |
|---|---|---|
| `/proc/<pid>/status` | five `Cap*:` hex lines per process | (read-only) |
| `capget(2)` | calling thread's E/P/I sets | — |
| `capset(2)` | — | calling thread's E/P/I sets |
| `prctl(PR_CAPBSET_DROP)` | — | drop a cap from the calling thread's bounding set |
| `prctl(PR_CAP_AMBIENT_RAISE)` | — | add a cap to the calling thread's ambient set |
| `prctl(PR_CAP_AMBIENT_CLEAR_ALL)` | — | clear the ambient set |

Linx wraps the read side via pure Elixir file parsing; the
write side lives in `linx_process.c` (the agent runs as the
child thread, so its `capset`/`prctl` calls affect the workload
about to execve).

## Sequencing — milestones

### K0 — Scaffolding + constants table

- `Linx.Capabilities` module skeleton (`@moduledoc`, public API
  stubs returning `{:error, :not_yet_implemented}`).
- `Linx.Capabilities.supported?/0` — true iff
  `/proc/self/status` contains a `CapBnd:` line (true on every
  Linux ≥ 2.6.25).
- `Linx.Capabilities.Constants` (`@doc false`) with the 41-entry
  table:
  - `all/0` — every `:cap_*` atom we know.
  - `to_bit/1` — `:cap_net_admin → 12`.
  - `from_bit/1` — `12 → :cap_net_admin`.
  - `to_bits/1` — a MapSet of atoms → u64 integer.
  - `from_bits/1` — u64 integer → MapSet of atoms.
- `%Linx.Capabilities.State{}` struct with five MapSet-valued
  fields + `@enforce_keys`. Custom Inspect:
  `#Linx.Capabilities.State<eff=42 prm=42 inh=0 bnd=42 amb=0>`
  (cap counts per set, for at-a-glance).
- `docs/capabilities/{PLAN,EXAMPLES,COVERAGE,REFERENCES}.md`
  skeletons (this doc; the others stubbed).
- Wire `docs/capabilities/*.md` into `mix.exs` `docs.extras` +
  groups.
- **Tests:** Plain — `supported?/0` returns boolean. Constants
  table: `to_bit(:cap_net_admin) == 12`,
  `to_bits(MapSet.new([:cap_chown, :cap_net_admin])) == 0x1001`,
  `from_bits(0x1001)` round-trips. `%State{}` `@enforce_keys`
  + Inspect rendering. Stubs return `:not_yet_implemented`.

### K1 — Read side from `/proc/<pid>/status`

- `Linx.Capabilities.Error` — `{path, operation, errno, code}`
  struct + Exception impl + `from_posix/3`. Operation:
  `:read`.
- `Linx.Capabilities.read(pid)` — reads `/proc/<pid>/status`,
  parses the five `Cap*:` lines, returns
  `{:ok, %Linx.Capabilities.State{}}`. Bogus pid →
  `{:error, %Error{operation: :read, errno: :enoent}}`.
- Parser handles the standard kernel format:
  `CapBnd:\t000001ffffffffff\n` and tolerant of any whitespace.
- **Tests:**
  - Plain unit: parser against a fixture `/proc/<pid>/status`
    blob (with various bit-patterns); read against
    `/proc/self/status` (the BEAM's own caps) returns a valid
    `%State{}`; bogus pid returns structured error.
  - Plain unit: `from_bits/to_bits` round-trip for each named
    cap individually and for representative combinations.

### K2 — Write side via agent commands at the checkpoint

- `c_src/linx_process.c` `await_proceed` learns three new
  checkpoint-window commands (in addition to the existing
  `:proceed`, `:abort`, `:pty_winsize`):
  - `{:cap_drop_bounding, [:cap_*, ...]}` — for each named cap,
    `prctl(PR_CAPBSET_DROP, cap_number, 0, 0, 0)`. Bounding-set
    drops are one-way.
  - `{:cap_set_thread, e, p, i}` where `e`, `p`, `i` are u64
    bitmasks — `capset(3, capabilities_data_t)` writes the
    effective/permitted/inheritable sets directly.
  - `{:cap_set_ambient, [:cap_*, ...]}` — clears the ambient
    set with `prctl(PR_CAP_AMBIENT_CLEAR_ALL)`, then raises each
    requested cap via `prctl(PR_CAP_AMBIENT_RAISE, cap, ...)`.
  - All three are idempotent if called multiple times (well —
    bounding drops are *cumulative*; calling drop_bounding
    twice with the same caps is a no-op the second time).
  - Pre-exec failures surface as `{:status, :error, errno,
    stage}` with stages `:cap_drop_bounding`, `:cap_set_thread`,
    `:cap_set_ambient`.
- Elixir-side public verbs on `Linx.Capabilities`:
  - `drop_bounding(session, caps)` — caps is a MapSet or list
    of `:cap_*` atoms; sends `{:cap_drop_bounding, ...}` to the
    agent.
  - `set_thread_sets(session, opts)` — opts is keyword with
    `:effective`, `:permitted`, `:inheritable` (any subset
    omitted is left unchanged).
  - `set_ambient(session, caps)` — replaces the ambient set
    with exactly `caps` (the kernel doesn't let you remove
    individual ambient caps without clearing all, so this is
    the natural shape).
  - All three are `GenServer.call`s on the Linx.Process
    session pid, only valid in the `:ready` (parked) state;
    `{:error, :running}` post-execve, `{:error, :not_ready}`
    pre-checkpoint, `{:error, :already_terminated}` post.
    Same state-machine rules as `proceed/1` / `abort/1`.
- **Tests:**
  - Plain (`mix test`): state-machine assertions (no caller
    can call the new verbs post-`:running`); MapSet vs list
    input acceptance; unknown cap atom rejected as
    `{:bad_capability, atom}`.
  - Integration (`:integration`, `./sudotest.sh`): spawn
    `/bin/sleep`, drop a known cap from the bounding set, read
    the workload's `/proc/<host_pid>/status` after `:running`,
    assert the cap is gone. Same pattern for ambient and the
    three thread sets. Verify drop_bounding is irreversible
    (after dropping CAP_SYS_ADMIN, a re-add via thread sets
    fails).

## Testing

Same three bands as the other subsystems:

- **Unit.** Constants table round-trips; parser fixtures; struct
  shapes; state-machine assertions on the new write verbs. Plain
  `mix test`.
- **Integration.** Anything that actually applies caps to a real
  workload — `:integration` tag, run via `./sudotest.sh`. Each
  test spawns its own Linx.Process session.
- **Manual / `docs/capabilities/EXAMPLES.md`.** The headline
  composition: spawn a workload, strip everything except
  `:cap_net_bind_service`, read back `/proc/<host_pid>/status`,
  confirm only the requested cap remains.

## Deferred — architected-for, not built here

- **File capabilities (`security.capability` xattrs).**
  Configures *binaries*, not running workloads. Useful but a
  distinct audience and surface (xattr(7) + setcap(8)). Future
  K3 or separate module `Linx.Capabilities.File`.
- **`SECBIT_*` securebits.** `prctl(PR_SET_SECUREBITS)` controls
  rare cap-related flags like `SECBIT_KEEP_CAPS` and
  `SECBIT_NO_SETUID_FIXUP`. Edge-case; out of scope for K0–K2.
- **`PR_SET_NO_NEW_PRIVS`.** Related-but-separate kernel
  feature (prevents `execve` from gaining privilege via file
  caps or set-user-ID). Probably its own one-line wrapper
  somewhere in `Linx.Process` rather than under Capabilities.
- **`/proc/<pid>/task/<tid>/status` for per-thread cap
  reading.** Linx.Capabilities reads the main thread; multi-
  threaded inspection is a niche concern.
- **Cap inheritance via execve (file-cap interaction).**
  Documented behaviour but not actively manipulated by Linx;
  consumers read `capabilities(7)` for the full transition
  rules.

## Decisions

1. **Three milestones (K0/K1/K2).** Scaffolding +
   constants → read side → write via agent. Same shape as
   `Linx.User`'s three.
2. **MapSet of atoms.** Idiomatic Elixir set semantics; the
   bit ↔ atom conversion is a thin layer at the edge.
3. **Cap atoms keep the `:cap_` prefix.** Mirrors the kernel
   (`CAP_NET_ADMIN` → `:cap_net_admin`); unambiguous in
   mixed-message mailboxes.
4. **Read side is pure Elixir file I/O.** No NIF for read.
5. **Write side via agent checkpoint commands.** Capability
   manipulation is per-thread; the child agent is the right
   actor.
6. **No `:in` option.** Reads use procfs from the host; writes
   are checkpoint-bound to the spawned session.
7. **File caps deferred.** Distinct concern (binaries vs
   processes); future milestone or sibling module.
8. **Errors as structs** for the read path
   (`Linx.Capabilities.Error`); pre-exec errors for the write
   path reuse `Linx.Process`'s existing
   `{:linx_process, :error, errno, stage}` shape with new
   stage atoms.
