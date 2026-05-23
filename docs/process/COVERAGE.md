# Linx.Process coverage

What of the Linux process-lifecycle surface `Linx.Process` exposes today,
what is planned, and what is deferred.

A living doc — update as primitives ship. Status legend:

| | |
|---|---|
| ✅ | done — shipped and tested |
| 🟡 | partial — some sub-features in, others not |
| ⬜ | todo — not yet |
| ⏳ | architected-for — design accommodates it, no code yet |

## Core lifecycle

| Feature | Status | Notes |
|---|---|---|
| `spawn/1` — `clone(2)` with namespace flags | ✅ | P1 |
| Checkpoint protocol (`:ready` → `release/1` → `:running`) | ✅ | P1 |
| Lifecycle events (`:exited` / `:signaled` / `:error`) | ✅ | P1 |
| Input validation on opts | ✅ | P1 |
| `release/1` | ✅ | P1 |
| `signal/2` (queued before `:running`) | ✅ | P2 — buffered pre-running, forwarded post |
| `wait/1` (synchronous wait for terminal event) | ✅ | P2 — with timeout in `wait/2` |
| Exit status via `waitpid(2)` | ✅ | P1 (drives `:exited` / `:signaled`) |
| `info/1` (state snapshot) | ⬜ | grows with the GenServer state |
| `enter/2` (`setns(2)` + `execve`) | ⬜ | P3 |

## Namespaces (as `CLONE_NEW*` flags on `spawn/1`)

| Namespace | Atom | Status | Notes |
|---|---|---|---|
| Network | `:net` | ✅ | P1 — verified with `Linx.Netlink` in integration test |
| Mount | `:mount` | 🟡 | P1 — flag works; mount setup belongs in `Linx.Mount` |
| PID | `:pid` | 🟡 | P1 — flag works; PID 1 supervision belongs to a consumer (see `mini_init` in `PLAN.md`) |
| UTS | `:uts` | ✅ | P1 |
| IPC | `:ipc` | ✅ | P1 |
| User | `:user` | 🟡 | P1 — flag works; id-map setup deferred (see `PLAN.md`) |
| Cgroup | `:cgroup` | ✅ | P1 |
| Time | `:time` | ✅ | P1 |

## Stdio plumbing

| Directive | Status | Notes |
|---|---|---|
| `:inherit` (default) | ✅ | implicit — agent doesn't touch fds 0/1/2 |
| `:devnull` | ⬜ | P4 |
| `{:connect_unix, path}` | ⬜ | P4 |
| `{:pty, opts}` (PTY master back to BEAM) | ⬜ | P4 — interactive pumping is `Linx.Tty` |

## Composition with other subsystems

| Pairing | Status | Notes |
|---|---|---|
| `Linx.Netlink` opens a socket in the new netns via `{:pid, child_pid}` | ✅ | P1 integration test |
| `Linx.Mount` for rootfs / pivot_root | ⏳ | future subsystem |
| `Linx.Cgroup` placement before the workload runs | ⏳ | future subsystem |
| `Linx.Tty` `attach/2` pumping bytes to/from a PTY master | ⏳ | future subsystem |

## Deferred — not in `Linx.Process` itself

See `PLAN.md`'s "Deferred — architected-for, not built here" for the full list with reasoning:

- Stdio listener + mailbox apparatus (consumer policy)
- Cgroup placement (lands with `Linx.Cgroup`)
- User-namespace id maps + idmapped rootfs (hardening; large surface)
- `mini_init` PID-1 shim (just argv; supply from upstream or runtime project)
- `unshare/1` (no use case the existing `spawn/1` doesn't cover)
