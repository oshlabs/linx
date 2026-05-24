# Linx.Capabilities coverage

What of the kernel's capability surface `Linx.Capabilities`
exposes today, what is planned, and what is deferred.

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
| `supported?/0` | ⬜ | K0 — true iff `/proc/self/status` has `CapBnd:` |

## Constants

| Feature | Status | Notes |
|---|---|---|
| 41-entry atom ↔ bit table | ⬜ | K0 — kernel capabilities through `:cap_checkpoint_restore` (CAP_LAST_CAP = 40 on recent kernels) |
| `to_bit/1`, `from_bit/1` | ⬜ | K0 — single-cap conversions |
| `to_bits/1`, `from_bits/1` | ⬜ | K0 — MapSet ↔ u64 bitmask |
| `all/0` | ⬜ | K0 — every known cap as a MapSet |

## Read side

| Feature | Status | Notes |
|---|---|---|
| `read/1` (`{:pid, n}`) | ⬜ | K1 — parses all five `Cap*:` lines from `/proc/<n>/status` |
| `read/1` against `:self` | ⬜ | K1 — convenience for `/proc/self/status` |
| Empty / missing pid handling | ⬜ | K1 — structured `%Error{}` |

## Write side (via Linx.Process agent at the checkpoint)

| Feature | Status | Notes |
|---|---|---|
| `drop_bounding/2` | ⬜ | K2 — one-way drops via `prctl(PR_CAPBSET_DROP)` |
| `set_thread_sets/2` | ⬜ | K2 — `capset(2)` for effective/permitted/inheritable |
| `set_ambient/2` | ⬜ | K2 — `prctl(PR_CAP_AMBIENT_CLEAR_ALL)` + `RAISE` for each named cap |
| Agent commands in `linx_process.c` | ⬜ | K2 — `{:cap_drop_bounding, [...]}`, `{:cap_set_thread, e, p, i}`, `{:cap_set_ambient, [...]}` |
| State-machine guards (only at `:ready`) | ⬜ | K2 — mirrors `abort/1` / `proceed/1` shape |
| Error stages (`:cap_drop_bounding`, etc.) | ⬜ | K2 — surface via `{:linx_process, :error, errno, stage}` |

## Composition with other subsystems

| Pairing | Status | Notes |
|---|---|---|
| `Linx.Process` cap configuration at checkpoint | ⬜ | K2 — new agent commands; no other Process changes |

## Value types

| Module | Status | Notes |
|---|---|---|
| `Linx.Capabilities.State` | ⬜ | K0 — `%{effective, permitted, inheritable, bounding, ambient}` (MapSet-valued) |
| `Linx.Capabilities.Error` | ⬜ | K1 — POSIX-atom errno + path + operation |

## Error reporting

| Mechanism | Status | Notes |
|---|---|---|
| `%Linx.Capabilities.Error{path, operation, errno, code}` | ⬜ | K1 — read-side failures |
| `{:linx_process, :error, errno, stage}` for write-side | ⬜ | K2 — stages `:cap_drop_bounding`, `:cap_set_thread`, `:cap_set_ambient` |
| `{:bad_capability, atom}` for unknown cap atoms | ⬜ | K2 — input validation, distinct from kernel errors |

## Deferred — not in `Linx.Capabilities` itself

See `PLAN.md`'s "Deferred — architected-for, not built here" for
reasoning:

- File capabilities (`security.capability` xattr on binaries)
- `SECBIT_*` securebits (`prctl(PR_SET_SECUREBITS)`)
- `PR_SET_NO_NEW_PRIVS` (related but conceptually separate)
- Per-thread cap reading via `/proc/<pid>/task/<tid>/status`
- File-cap-based inheritance modelling on `execve`
