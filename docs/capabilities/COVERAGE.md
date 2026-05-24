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
| `supported?/0` | ✅ | K0 — true iff `/proc/self/status` has `CapBnd:` |

## Constants

| Feature | Status | Notes |
|---|---|---|
| 41-entry atom ↔ bit table | ✅ | K0 — kernel capabilities through `:cap_checkpoint_restore` (CAP_LAST_CAP = 40 on kernels ≥ 5.8) |
| `to_bit/1`, `from_bit/1` | ✅ | K0 — single-cap conversions; `from_bit/1` returns `:unknown` for bits past the table |
| `to_bits/1`, `from_bits/1` | ✅ | K0 — MapSet ↔ u64 bitmask; `to_bits/1` raises on unknown atoms, `from_bits/1` silently drops unknown bits (forward-compat) |
| `all/0` | ✅ | K0 — every known cap as a MapSet |
| `last_cap/0` | ✅ | K0 — the kernel's `CAP_LAST_CAP` value (40) |

## Read side

| Feature | Status | Notes |
|---|---|---|
| `read/1` against a pid | ✅ | K1 — parses all five `Cap*:` lines from `/proc/<n>/status` |
| `read/1` against `:self` | ✅ | K1 — convenience for `/proc/self/status` |
| Out-of-range / dead pid | ✅ | K1 — structured `%Error{errno: :enoent}` |
| Malformed status (missing `Cap*:`) | ✅ | K1 — structured `%Error{errno: :bad_status}` |
| Forward-compat for future caps | ✅ | K1 — unknown bits silently dropped + single `Logger.warning` per read |
| `parse_status/2` (fixture-testable) | ✅ | K1 — `@doc false` parser exposed for unit tests; consumers use `read/1` |

## Write side (via Linx.Process agent at the checkpoint)

| Feature | Status | Notes |
|---|---|---|
| `drop_bounding/2` | ✅ | K2 — one-way drops via `prctl(PR_CAPBSET_DROP)` per set bit |
| `set_thread_sets/2` | ✅ | K2 — `capset(2)` (v3, 64-bit) for effective/permitted/inheritable; all three keys required |
| `set_ambient/2` | ✅ | K2 — `prctl(PR_CAP_AMBIENT_CLEAR_ALL)` + `RAISE` per cap (replaces, not adds) |
| Child cap-command loop in `linx_process.c` | ✅ | K2 — `child_read_command()` reads framed `:proceed` / `{:cap_*, _}` from p2c; `apply_cap_*` helpers run capset/prctl in the child thread |
| Forward cap commands in `await_proceed` | ✅ | K2 — agent forwards the ei frame verbatim to the child; poll() on c2p surfaces child failures during the checkpoint window |
| State-machine guards (only at `:ready`) | ✅ | K2 — mirrors `abort/1` / `proceed/1` shape: `:not_ready` / `:running` / `:already_terminated` |
| Error stages (`:cap_drop_bounding`, etc.) | ✅ | K2 — surface as `{:linx_process, :error, errno, :cap_drop_bounding \| :cap_set_thread \| :cap_set_ambient}` |
| `{:bad_capability, atom}` input validation | ✅ | K2 — caller-side rejection of unknown atoms before any session interaction |
| `{:bad_thread_sets, {:missing, key}}` | ✅ | K2 — `set_thread_sets/2` requires all three keys explicitly |

## Composition with other subsystems

| Pairing | Status | Notes |
|---|---|---|
| `Linx.Process` cap configuration at checkpoint | ✅ | K2 — three new checkpoint-window agent commands; wire protocol on p2c upgraded from single 'P' byte to ei frames |

## Value types

| Module | Status | Notes |
|---|---|---|
| `Linx.Capabilities.State` | ✅ | K0 — `%{effective, permitted, inheritable, bounding, ambient}` (MapSet-valued); compact Inspect rendering |
| `Linx.Capabilities.Error` | ✅ | K1 — `%{path, operation, errno, code}`; Exception impl; `from_posix/3` builder |

## Error reporting

| Mechanism | Status | Notes |
|---|---|---|
| `%Linx.Capabilities.Error{path, operation, errno, code}` | ✅ | K1 — read-side failures (`:enoent`, `:eacces`, `:bad_status`, …) |
| `{:linx_process, :error, errno, stage}` for write-side | ✅ | K2 — stages `:cap_drop_bounding`, `:cap_set_thread`, `:cap_set_ambient`; agent polls c2p during checkpoint window so failures surface immediately |
| `{:bad_capability, atom}` for unknown cap atoms | ✅ | K2 — caller-side input validation, distinct from kernel errors |
| `{:bad_thread_sets, {:missing, key}}` for missing thread-set keys | ✅ | K2 — `set_thread_sets/2` requires `:effective`, `:permitted`, `:inheritable` all explicit |

## Deferred — not in `Linx.Capabilities` itself

See `PLAN.md`'s "Deferred — architected-for, not built here" for
reasoning:

- File capabilities (`security.capability` xattr on binaries)
- `SECBIT_*` securebits (`prctl(PR_SET_SECUREBITS)`)
- `PR_SET_NO_NEW_PRIVS` (related but conceptually separate)
- Per-thread cap reading via `/proc/<pid>/task/<tid>/status`
- File-cap-based inheritance modelling on `execve`
