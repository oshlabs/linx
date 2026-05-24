# Linx.User coverage

What of the kernel's user-namespace configuration surface
`Linx.User` exposes today, what is planned, and what is deferred.

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
| `supported?/0` | ✅ | U0 — true iff `/proc/self/uid_map` exists (kernel ≥ 3.8) |

## Write side

| Feature | Status | Notes |
|---|---|---|
| `deny_setgroups/1` | ✅ | U1 — writes `"deny"` to `/proc/<pid>/setgroups`; required before `set_gid_map/2` from an unprivileged caller |
| `set_uid_map/2` | ✅ | U1 — writes `/proc/<pid>/uid_map`; write-once |
| `set_gid_map/2` | ✅ | U1 — writes `/proc/<pid>/gid_map`; write-once |
| Input validation (`{:bad_map, reason}`) | ✅ | U1 — non-list, negative ids, zero length, wrong-arity tuples |

## Read side

| Feature | Status | Notes |
|---|---|---|
| `read_uid_map/1` | ✅ | U2 — parses `/proc/<pid>/uid_map` into `[%Linx.User.Map{}]` |
| `read_gid_map/1` | ✅ | U2 — parses `/proc/<pid>/gid_map` similarly |
| Empty-map handling (`{:ok, []}`) | ✅ | U2 — pre-write user ns reports an empty file |

## Convenience

| Feature | Status | Notes |
|---|---|---|
| `setup_maps/2` | ✅ | U2 — canonical sequence: `deny_setgroups → set_uid_map → set_gid_map`; opts `:uid`, `:gid`, `:setgroups` |

## Composition with other subsystems

| Pairing | Status | Notes |
|---|---|---|
| `Linx.Process` rootless mapping at checkpoint | ✅ | U1 — caller writes maps between `:ready` and `proceed/1`; no `Linx.Process` change needed |

## Value types

| Module | Status | Notes |
|---|---|---|
| `Linx.User.Map` | ✅ | U2 — `%{inside, outside, length}` with compact Inspect |
| `Linx.User.Error` | ✅ | U1 — POSIX-atom errno + path + operation |

## Error reporting

| Mechanism | Status | Notes |
|---|---|---|
| `%Linx.User.Error{path, operation, errno, code}` | ✅ | U1 |
| `Exception` impl for `raise`-able paths | ✅ | U1 |
| `{:bad_map, reason}` for input mistakes | ✅ | U1 — distinct from kernel-level errors |

## Deferred — not in `Linx.User` itself

See `PLAN.md`'s "Deferred — architected-for, not built here" for the
full list with reasoning:

- `newuidmap(1)` / `newgidmap(1)` integration (multi-range
  unprivileged mappings via subuid/subgid)
- Capability management (`capset(2)` / `capget(2)`) — distinct
  subsystem `Linx.Capabilities`
- Host-level policy knobs (`/proc/sys/kernel/unprivileged_userns_clone`)
- Entering a target user namespace via setns (mirrors
  `Linx.Process.enter/2`'s shape)
