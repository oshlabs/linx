# Linx.User — implementation plan

> **Not yet shipped.** Work lives on branch `user-foundations`.
> Milestones U0–U2 land independently; each commits + pushes per the
> Linx-wide "commit per milestone" rule.

## Goal

Build the foundations of `Linx.User`: the kernel's user-namespace
configuration surface — `/proc/<pid>/uid_map`, `/proc/<pid>/gid_map`,
`/proc/<pid>/setgroups` — exposed as Elixir primitives. The driving
use case is **rootless containers**: spawn a workload with the
`:user` namespace, write uid/gid mappings from the host, then
proceed. Inside the container the workload is root (with full caps
in *that* user ns); outside it's an unprivileged user.

The motivating composition, from the project README's headline
transcript and onward:

    {:ok, c} = Linx.Process.spawn(
                 argv: ["/bin/bash"],
                 namespaces: [:user, :mount, :pid, :uts, :ipc],
                 stdio: :pty)
    host_pid = receive do {:linx_process, :ready, p} -> p end

    # "root inside ↔ me outside" -- the canonical rootless mapping.
    :ok = Linx.User.deny_setgroups(host_pid)
    :ok = Linx.User.set_uid_map(host_pid, [{0, my_uid, 1}])
    :ok = Linx.User.set_gid_map(host_pid, [{0, my_gid, 1}])

    Linx.Process.proceed(c)

Today the headline transcript shows `whoami` → `nobody` (the
kernel's default when no map is written). With `Linx.User` it would
show `whoami` → `root` — the inside view — while the host still
sees an unprivileged process.

`Linx.User` is **not** a container runtime or a setuid-helper
substitute. It exposes "write this mapping to this pid's user ns".
Multi-range mappings via `newuidmap(1)` / `newgidmap(1)` / subuid /
subgid live in a consumer (or a follow-up).

## Guiding principles

**Pure Elixir, no NIF.** Every operation in this subsystem is a
single `File.write/2` or `File.read/1` against
`/proc/<pid>/{uid_map,gid_map,setgroups}`. The kernel handles all
the namespace targeting based on the path; no `setns(2)`, no
`unshare(2)`, no throwaway thread. Smallest subsystem in Linx by
a wide margin (~200 lines including tests).

**No `:in` option.** Unlike `Linx.Mount` (where mount/umount must
be called from *inside* the target namespace), uid/gid maps are
written via procfs from the host. The verbs just take a `pid` as
their first argument — the target child's host pid. No setns
needed, no `:in` option.

**The `setgroups` order is mandatory.** Per
`user_namespaces(7)`: when an unprivileged caller (no CAP_SETGID
in the parent user ns) writes gid_map, the kernel requires
`/proc/<pid>/setgroups` first contain `"deny"` — otherwise the
gid_map write returns EPERM. Privileged callers may skip it. We
expose `deny_setgroups/1` as a primitive *and* a `setup_maps/2`
convenience that does the canonical sequence in the right order.

**uid_map / gid_map are write-once.** Once a map has been written
for a user ns, subsequent writes return EPERM. This is a kernel
property, not a Linx choice — but it means the configuration
window is real: write the maps at the checkpoint, before
`proceed/1`, and never again.

**Errors as structs.** `%Linx.User.Error{path, operation, errno,
code}`, same shape as `Linx.Mount.Error` / `Linx.Cgroup.Error`.
Operations: `:set_uid_map`, `:set_gid_map`, `:deny_setgroups`,
`:read_uid_map`, `:read_gid_map`. Plus `{:bad_map, reason}` for
input-validation failures (matching Mount's `:bad_flag`).

**AGENTS.md style throughout:** `@moduledoc`/`@doc`/`@spec`
everywhere; structs with `@enforce_keys`; one module per file;
cite `user_namespaces(7)` and `Documentation/admin-guide/...` in
comments where interpretation is non-obvious.

## Module structure

```
Linx.User                       — public API: supported?/0,
                                  deny_setgroups/1, set_uid_map/2,
                                  set_gid_map/2, read_uid_map/1,
                                  read_gid_map/1, setup_maps/2.

Linx.User.Map                   — %Linx.User.Map{inside, outside,
                                  length} value type; parsed entries
                                  returned by read_*. `Inspect`
                                  renders compactly:
                                  #Linx.User.Map<0..0 -> 1000..1000>.

Linx.User.Error                 — %Linx.User.Error{path, operation,
                                  errno, code} + Exception impl +
                                  from_posix/3 builder.
```

No NIF, no C source, no compile task. Pure Elixir.

## The procfs surface

| File | Read | Write |
|---|---|---|
| `/proc/<pid>/uid_map` | space-separated `inside_id outside_id length` lines | same format; **write-once** |
| `/proc/<pid>/gid_map` | same | same; **must be preceded by `setgroups=deny`** if unprivileged |
| `/proc/<pid>/setgroups` | `"allow"` or `"deny"` | `"deny"` (preferred); `"allow"` only when privileged |

The kernel's documentation for these is in `user_namespaces(7)`
under "User and group ID mappings: uid_map and gid_map".

## Sequencing — milestones

Each milestone is an independently reviewable commit; tests ship
with the code that needs them; commit + push per milestone.

### U0 — Scaffolding

- `Linx.User` module skeleton (`@moduledoc`, public API stubs
  returning `{:error, :not_yet_implemented}`).
- `Linx.User.supported?/0` returns `true` iff
  `/proc/self/uid_map` exists (true on any kernel ≥ 3.8).
- `docs/user/{PLAN,EXAMPLES,COVERAGE,REFERENCES}.md` skeletons
  (this doc; the others stubbed for fill-in as primitives ship).
- Wire `docs/user/*.md` into `mix.exs` `docs.extras` + groups.
- **Tests:** `supported?/0` returns a boolean. Plain `mix test`,
  no root.

### U1 — Write side

- `Linx.User.Error` — struct + `Exception` impl + `from_posix/3`
  builder mapping `File`'s posix atoms to our error shape with
  `path` and `operation` set.
- `Linx.User.set_uid_map(pid, mappings)` — writes
  `/proc/<pid>/uid_map`. `mappings` is a list of
  `{inside_id, outside_id, length}` non-negative integer tuples
  (or single `{inside, outside, length}` tuple as shorthand).
  Validates input before the write; invalid input returns
  `{:error, {:bad_map, reason}}` — distinct from kernel-level
  failures.
- `Linx.User.set_gid_map(pid, mappings)` — same shape.
- `Linx.User.deny_setgroups(pid)` — writes `"deny"` to
  `/proc/<pid>/setgroups`.
- **Tests:**
  - Plain: input validation (non-list, negative numbers,
    zero-length entries, wrong-arity tuples) → `:bad_map`
    errors. Bogus pid → `%Error{operation, errno: :enoent}`.
  - Integration (`:integration`, run via `./sudotest.sh`): spawn
    a `Linx.Process` workload with `namespaces: [:user]`, wait
    for `:ready`, write the maps, proceed, observe via
    `/proc/<child>/uid_map` that the mapping is in place.

### U2 — Read side + `setup_maps/2` convenience

- `Linx.User.Map` — `%Linx.User.Map{inside, outside, length}`
  with `@enforce_keys` on all three fields. Custom `Inspect`:
  `#Linx.User.Map<0..0 -> 1000..1000>` for a 1-length map,
  `#Linx.User.Map<0..65535 -> 100000..165535>` for a range.
- `Linx.User.read_uid_map(pid)` — reads + parses; returns
  `{:ok, [%Linx.User.Map{}, ...]}` or `{:error, %Error{}}`. An
  empty file returns `{:ok, []}` — that's a user ns whose
  mappings haven't been written yet (kernel-default "nobody"
  applies).
- `Linx.User.read_gid_map(pid)` — same.
- `Linx.User.setup_maps(pid, opts)` — convenience wrapper that
  does the canonical `deny_setgroups → set_uid_map →
  set_gid_map` sequence in order. Opts: `:uid` (mappings list),
  `:gid` (mappings list), `:setgroups` (default `:deny`,
  `:skip` to leave it alone for privileged callers).
- **Tests:**
  - Plain: round-trip parsing of representative map blobs
    (single-line, multi-line, edge-case whitespace handling).
    `Linx.User.Map` Inspect rendering.
  - Integration: full headline rootless dance through
    `setup_maps/2` — spawn, setup, proceed, observe `whoami`
    inside reports `root` (uid 0 inside; outside is the test
    runner's host uid). `read_uid_map/1` round-trips the
    written value.

## Testing

Same three bands as the other subsystems:

- **Unit.** Module loading, struct shapes, `Error` formatting,
  `Map` parsing + Inspect, input validation (`:bad_map`). Plain
  `mix test`.
- **Integration.** Anything that touches `/proc/<pid>/...` for a
  spawned `Linx.Process` workload — `:integration` tag, run via
  `./sudotest.sh`. Each test creates its own session and reaps it
  with `abort/1` or `signal/2`.
- **Manual / `docs/user/EXAMPLES.md`.** The headline
  rootless-bash demo with `whoami` showing `root` (vs `nobody`
  pre-`Linx.User`).

## Deferred — architected-for, not built here

- **`newuidmap(1)` / `newgidmap(1)` integration.** Setuid
  helpers from the `uidmap` package; unprivileged callers use
  them with `/etc/subuid` and `/etc/subgid` to set up
  *multi-range* uid maps that span more than one ID. Required
  for full rootless container parity with `runc rootless` mode
  (mapping a whole range like `0..65535` inside ↔ `100000..165535`
  outside). Not in scope for foundations; future U3 / follow-up
  module.
- **Capability management** (`capset(2)` / `capget(2)` / file
  caps via `xattr`). Distinct subsystem `Linx.Capabilities` —
  often paired with user namespaces, conceptually separate.
- **`/proc/sys/kernel/unprivileged_userns_clone`**, `userns_creates`
  knobs. Host-level policy, not per-namespace. Read via
  `File.read/1` if a consumer needs them.
- **`Linx.User.into_namespace/2`** — entering a target user
  namespace via setns. Niche; would mirror `Linx.Process.enter/2`'s
  approach but for user ns only. Out of scope.

## Decisions

1. **Pure Elixir.** No NIF, no Port. The procfs surface is plain
   file I/O.
2. **No `:in` option.** uid_map/gid_map are written via
   `/proc/<host_pid>/...` from the host's view; no setns needed.
   Verbs take a `pid` as the target.
3. **Three primitives + one convenience.** `deny_setgroups/1`,
   `set_uid_map/2`, `set_gid_map/2` for callers who know what
   they're doing; `setup_maps/2` for the 95% case.
4. **Errors as structs.** `%Linx.User.Error{path, operation,
   errno, code}` matching `Linx.Cgroup.Error` / `Linx.Mount.Error`.
5. **`%Linx.User.Map{}` as the value type.** Inspect renders the
   range as `inside_start..inside_end -> outside_start..outside_end`
   for legibility on multi-line maps.
6. **Input validation distinct from kernel errors.**
   `{:error, {:bad_map, reason}}` for caller mistakes;
   `{:error, %Linx.User.Error{}}` for kernel rejections.
   Mirrors `Linx.Mount`'s `:bad_flag` / `%Error{}` distinction.
7. **No `:in`-style cross-namespace ops.** uid_map writes are
   inherently host-side. If a consumer needs to write maps for a
   namespace they entered, they're already in trouble — the
   kernel only lets you write maps for a *child's* user ns from
   *outside* it.
