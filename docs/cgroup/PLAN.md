# Linx.Cgroup — implementation plan

> **Not yet shipped.** Work lives on branch `cgroup-foundations`.
> Milestones C0–C4 land independently; each commits + pushes per the
> Linx-wide "commit per milestone" rule.

## Goal

Build the foundations of `Linx.Cgroup`: a small set of cgroup v2
**primitives** — create a cgroup, place processes into it, set resource
limits, read counters, freeze and thaw — packaged so a consumer (a
container engine, a workload supervisor, an observability tool) can
compose them with `Linx.Process`'s checkpoint protocol to wrap any
spawned workload in resource isolation.

The motivating composition: in the same checkpoint window that
`Linx.Netlink` already uses to configure a child's netns from the
host, place the child's host pid into a cgroup and apply limits —
*then* `proceed/1`. The child execs already constrained.

`Linx.Cgroup` is **not** a container runtime. It exposes "create this
cgroup, put this pid in it, set this limit, read this counter."
Policy — what to limit per workload, how cgroups are named, how
delegation is bootstrapped — lives in the consumer, not here.

## Guiding principles

**cgroupfs is the API.** cgroup v2 exposes its entire interface as a
read/write filesystem under `/sys/fs/cgroup`. Every operation in this
subsystem is plain `File.read/1` / `File.write/2` against a path. No
NIF, no Port, no `:os.cmd("cgcreate ...")` — just the filesystem the
kernel already exposes.

**v2 only.** Linx targets modern Linux. cgroup v1 (the legacy
controller-per-mount hierarchy) is *not* supported. `Linx.Cgroup.supported?/0`
returns true iff `/sys/fs/cgroup/cgroup.controllers` is readable — the
canonical "this host is on the unified hierarchy" check.

**Primitives, not policy.** The caller chooses the path. We do not
hardcode `/sys/fs/cgroup/linx/<name>` (the way silo hardcoded
`/sys/fs/cgroup/silo/<name>`). A consumer building a container engine
on Linx picks `/sys/fs/cgroup/myengine/...` or whatever convention they
want; we accept any absolute path.

**Composition with `Linx.Process` via the checkpoint.** No change to
`Linx.Process`. The caller does:

```elixir
{:ok, c} = Linx.Process.spawn(argv: [...], namespaces: [...])
host_pid = receive do {:linx_process, :ready, p} -> p end

{:ok, cg} = Linx.Cgroup.create("/sys/fs/cgroup/myorg/web-42")
:ok = Linx.Cgroup.set_memory_max(cg, 256 * 1024 * 1024)
:ok = Linx.Cgroup.add_process(cg, host_pid)

:ok = Linx.Process.proceed(c)
```

`add_process/2` is the only cross-subsystem touchpoint, and it goes
through cgroupfs (`<cg>/cgroup.procs` accepts a pid as text). There is
*no* code change in `Linx.Process` for cgroup integration — the existing
checkpoint is the integration surface.

The same trick works for `enter/2`-style exec sessions: place the new
host_pid into an existing container's cgroup before `proceed/1`.

**Errors as structs.** Per the project-wide "errors are structs" rule:
a `Linx.Cgroup.Error` struct carries `path`, `operation` (`:create` /
`:write` / `:read` / `:destroy` / `:add_process` / …), `errno` (POSIX
atom), and `code` (integer). Pattern-matching on `errno` works the
same as on `%Linx.Netlink.Error{errno: :enodev}`.

**Typed setters + a raw escape hatch.** Common limits get typed
helpers (`set_memory_max/2`, `set_pids_max/2`, `set_cpu_max/2`) that
handle the special values cleanly (atom `:max` → `"max"`, integer →
bytes, tuple → `cpu.max`'s "quota period" two-int form). Unusual
fields stay reachable via `write/3` and `read/2`.

**AGENTS.md style throughout:** `@moduledoc`/`@doc`/`@spec` everywhere;
structs with `@enforce_keys`; one module per file; cite the kernel doc
(`Documentation/admin-guide/cgroup-v2.rst`) in comments where the
interpretation is non-obvious.

## Module structure

```
Linx.Cgroup                    — the public API: supported?/0, create/1,
                                 destroy/1, add_process/2, write/3, read/2,
                                 freeze/1, thaw/1, set_memory_max/2,
                                 set_pids_max/2, set_cpu_max/2,
                                 enable_controllers/2, stats/1.

Linx.Cgroup.Error              — %Linx.Cgroup.Error{path, operation,
                                 errno, code}, implements Exception.

Linx.Cgroup.Stats              — %Linx.Cgroup.Stats{cpu_usec,
                                 cpu_user_usec, cpu_system_usec,
                                 cpu_nr_throttled, cpu_throttled_usec,
                                 memory_current, memory_peak,
                                 pids_current}; `nil` for fields the
                                 host doesn't expose.
```

No NIF, no C source, no compile task. Pure Elixir.

## The cgroupfs surface

Every interface file Linx writes touches one of:

| Path | Read | Write |
|---|---|---|
| `<cg>/cgroup.procs` | space-separated pids in this cgroup | move a pid in by writing its decimal text |
| `<cg>/cgroup.freeze` | `"0"` / `"1"` | `"1"` freezes; `"0"` thaws |
| `<cg>/cgroup.subtree_control` | enabled controllers | `+memory +pids` (enable) / `-memory` (disable) |
| `<cg>/cgroup.controllers` | controllers available here | (read-only) |
| `<cg>/memory.max` | current limit (or `"max"`) | bytes (int) or `"max"` |
| `<cg>/memory.current` | current usage in bytes | (read-only) |
| `<cg>/memory.peak` | peak usage in bytes | (read-only; kernel ≥ 5.19) |
| `<cg>/pids.max` | current limit (or `"max"`) | int or `"max"` |
| `<cg>/pids.current` | current count | (read-only) |
| `<cg>/cpu.max` | `"quota period"` (or `"max period"`) | `"<quota> <period>"` or `"max <period>"` |
| `<cg>/cpu.stat` | keyed counters (usage_usec, …) | (read-only) |

Anything else is reachable through `write/3` / `read/2` without needing
typed support in this module.

## Sequencing — milestones

Each milestone is an independently reviewable commit; tests ship with
the code that needs them; commit + push per milestone.

### C0 — Scaffolding

- `Linx.Cgroup` module skeleton (`@moduledoc`, public API stubs
  returning `{:error, :not_yet_implemented}`).
- `Linx.Cgroup.supported?/0` returns true iff
  `/sys/fs/cgroup/cgroup.controllers` exists.
- `docs/cgroup/{PLAN,EXAMPLES,COVERAGE,REFERENCES}.md` skeletons (this
  doc; the others stubbed for fill-in as primitives ship).
- Wire `docs/cgroup/*.md` into `mix.exs` `docs.extras` and groups.
- **Tests:** `supported?/0` returns a boolean. Plain `mix test`,
  no root.

### C1 — Lifecycle & raw I/O

- `Linx.Cgroup.Error` — struct + `Exception` impl + `from_posix/3`
  builder mapping `File`'s posix atoms to our error shape with `path`
  and `operation` set.
- `create/1` — `mkdir(path)` treating `EEXIST` as success (so create
  is idempotent).
- `destroy/1` — `rmdir(path)`; succeeds only when the cgroup is empty
  (the kernel enforces this), error otherwise.
- `add_process/2` — `File.write(<cg>/cgroup.procs, "<pid>")`.
- `read/2`, `write/3` — raw escape hatch for any interface file;
  `read/2` trims trailing whitespace, returns `{:ok, string}` or
  `{:error, %Error{}}`.
- **Tests:**
  - Plain: `Error` struct round-trips; `Exception.message/1` reads
    cleanly; missing paths return structured errors.
  - Integration (`:integration`, run via `./sudotest.sh`): full
    create → write → read → destroy round-trip against a real cgroup
    under a per-test parent (`/sys/fs/cgroup/linx-test-<n>`); cleanup
    in `on_exit`.

### C2 — Freeze / thaw + typed limit setters

- `freeze/1` writes `"1"` to `cgroup.freeze`; `thaw/1` writes `"0"`.
- `set_memory_max/2` — accepts an integer (bytes) or the atom `:max`.
- `set_pids_max/2` — same shape; integer or `:max`.
- `set_cpu_max/2` — accepts `{quota, period}` (microseconds) or
  `:max` (with the default period). Formats per `cpu.max`'s
  `"<quota> <period>"` text.
- **Tests:** integration freezes a running workload, asserts
  `cgroup.freeze` reads back `"1"`, thaws, asserts `"0"`. Limit
  setters round-trip through `read/2` to confirm the kernel accepted
  them.

### C3 — Stats

- `Linx.Cgroup.Stats` struct with the curated fields from silo's
  carry-over. `Inspect` renders compactly:
  `#Linx.Cgroup.Stats<cpu=12.3s mem=42M pids=3>`.
- `stats/1` reads `cpu.stat` (keyed), `memory.current`, `memory.peak`,
  `pids.current`. Each field is `nil` if its source is unavailable
  (controller not enabled, kernel too old, etc.).
- **Tests:** plain unit covers parsing of a fake `cpu.stat` blob;
  integration spawns a workload, reads `stats/1`, asserts
  `memory_current > 0` and `pids_current >= 1` (the workload itself).

### C4 — Controller delegation

- `enable_controllers/2` writes `+memory +pids +cpu …` to
  `<parent>/cgroup.subtree_control`. Each controller is written
  individually so a partial failure doesn't lose state for the
  successful ones; the function returns either `:ok` or
  `{:partial, [{controller, %Error{}}, …]}` listing which controllers
  the kernel rejected (typically: not delegated from the parent).
- **Tests:** integration enables `+memory +pids` under a fresh parent
  cgroup, reads back `cgroup.subtree_control`, asserts both are
  present.

## Testing

Same three bands as the other subsystems:

- **Unit.** Module loading, struct shapes, `Error` formatting, the
  no-cgroup-v2 path (`supported?/0` on a hypothetical v1-only host).
  Plain `mix test`.
- **Integration.** Anything that touches real cgroupfs — tagged
  `:integration`, run via `./sudotest.sh`. Each test creates a
  uniquely-named cgroup under `/sys/fs/cgroup/linx-test-<n>` and
  cleans up in `on_exit`.
- **Manual / docs/cgroup/EXAMPLES.md.** End-to-end composition with
  `Linx.Process` — spawn a memory-hungry shell, apply `memory.max`,
  watch it get killed by the OOM killer.

## Deferred — architected-for, not built here

- **cgroup v1.** The legacy multi-mount hierarchy. Not supported.
  Consumers needing it can shell out to `cgcreate(1)` or build their
  own helper; this isn't a Linx concern.
- **`CLONE_NEWCGROUP`.** That's a *namespace* flag and lives on
  `Linx.Process` already (we list `:cgroup` in the namespaces atom
  set); it has nothing to do with the cgroupfs management here.
- **Less-common controllers** — `rdma`, `hugetlb`, `misc`,
  `io` (per-device limits), `memory.swap.max`, `memory.zswap.max`,
  `cpu.uclamp`, `cpu.weight`, `cpuset.cpus` / `cpuset.mems`. All
  reachable via `write/3` / `read/2`; typed setters can grow as
  needed.
- **Event monitoring.** `memory.events`, `pids.events`, OOM
  notification. Future milestone — wants either polling or
  `inotify(7)` and warrants its own design pass.
- **`cgroup.kill`.** Kernel ≥ 5.14 has a write-`"1"` "kill everything
  in this cgroup atomically" file. Easy to add; deferred until a
  consumer asks (signal-via-cgroup is novel enough that the policy
  needs to come from them).
- **Stats deltas / sampling helpers.** `stats/1` returns a snapshot.
  Computing rates, smoothing, etc. is the consumer's job.

## Decisions

1. **No NIF, no Port.** cgroupfs is plain file I/O. No subprocess
   machinery to maintain.
2. **v2 only.** Modern Linux. If v1 support is ever requested we'd add
   a separate `Linx.Cgroup.V1` module; the v2 surface is the default.
3. **Caller-chosen paths.** No `/sys/fs/cgroup/linx/` parent baked in.
   A consumer's naming convention is the consumer's choice.
4. **No agent change for composition.** `Linx.Process` does not learn
   `:cgroup` as a spawn option. Host-side placement at the checkpoint
   covers the use case with no cross-subsystem coupling. (We
   considered baking it into `linx_process.c` à la silo's
   `silo-init`; rejected as a needless coupling.)
5. **Errors are structs.** `%Linx.Cgroup.Error{}` everywhere, never
   raw `{:error, :enoent}` tuples from `File`. Follows
   `Linx.Netlink.Error`'s precedent.
6. **Stats as a struct, not a map.** Matches `Linx.Tty.WindowSize` and
   the rtnetlink resources; gives `Inspect` something to render.
7. **Typed + raw.** Typed setters for the common limits; `write/3` /
   `read/2` for everything else. Both first-class.
