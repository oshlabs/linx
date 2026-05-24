# Linx.Cgroup coverage

What of cgroup v2's surface `Linx.Cgroup` exposes today, what is
planned, and what is deferred.

A living doc — update as primitives ship. Status legend:

| | |
|---|---|
| ✅ | done — shipped and tested |
| 🟡 | partial — some sub-features in, others not |
| ⬜ | todo — not yet |
| ⏳ | architected-for — design accommodates it, no code yet |

## Lifecycle

| Feature | Status | Notes |
|---|---|---|
| `supported?/0` | ✅ | C0 — true iff `/sys/fs/cgroup/cgroup.controllers` exists |
| `create/1` | ✅ | C1 — idempotent (treats `EEXIST` as success) |
| `destroy/1` | ✅ | C1 — succeeds only on empty cgroups (kernel enforces) |
| `add_process/2` | ✅ | C1 — writes pid to `<cg>/cgroup.procs` |
| `read/2` | ✅ | C1 — raw escape hatch; trims trailing whitespace |
| `write/3` | ✅ | C1 — raw escape hatch |

## Freeze / thaw

| Feature | Status | Notes |
|---|---|---|
| `freeze/1` | ✅ | C2 — `cgroup.freeze` ← `"1"` |
| `thaw/1` | ✅ | C2 — `cgroup.freeze` ← `"0"` |

## Resource limits

| Controller | Typed setter | Status | Notes |
|---|---|---|---|
| `memory.max` | `set_memory_max/2` | ✅ | C2 — int (bytes) or `:max` |
| `pids.max` | `set_pids_max/2` | ✅ | C2 — int or `:max` |
| `cpu.max` | `set_cpu_max/2` | ✅ | C2 — `{quota, period}` (µs) or `:max` |
| Others (`io.*`, `cpuset.*`, `memory.swap.max`, …) | (via `write/3`) | ⏳ | typed setters can grow |

## Stats

| Field | Status | Source |
|---|---|---|
| `cpu_usec` / `cpu_user_usec` / `cpu_system_usec` | ✅ | C3 — `cpu.stat` |
| `cpu_nr_throttled` / `cpu_throttled_usec` | ✅ | C3 — `cpu.stat` (populated when `cpu.max` is set) |
| `memory_current` / `memory_peak` | ✅ | C3 — `memory.current` / `memory.peak` |
| `pids_current` | ✅ | C3 — `pids.current` |

## Delegation

| Feature | Status | Notes |
|---|---|---|
| `enable_controllers/2` | ⬜ | C4 — `+memory +pids +cpu …` → `cgroup.subtree_control` |

## Composition with other subsystems

| Pairing | Status | Notes |
|---|---|---|
| `Linx.Process` workload placed at checkpoint | ✅ | C1 — caller wires it via `add_process/2`; no `Linx.Process` change |

## Error reporting

| Mechanism | Status | Notes |
|---|---|---|
| `%Linx.Cgroup.Error{path, operation, errno, code}` | ✅ | C1 |
| `Exception` impl for `raise`-able paths | ✅ | C1 |

## Value types

| Module | Status | Notes |
|---|---|---|
| `Linx.Cgroup.Error` | ✅ | C1 — POSIX-atom errno + path + operation |
| `Linx.Cgroup.Stats` | ✅ | C3 — curated counters; `nil` for unavailable fields |

## Deferred — not in `Linx.Cgroup` itself

See `PLAN.md`'s "Deferred — architected-for, not built here" for the
full list with reasoning:

- cgroup v1 (legacy multi-mount hierarchy)
- Event monitoring (`memory.events`, OOM notification)
- `cgroup.kill` (atomic-kill file)
- Stats deltas / rate computation
- Per-controller typed setters beyond memory/pids/cpu
