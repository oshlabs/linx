# Linx.Mount coverage

What of the kernel's mount surface `Linx.Mount` exposes today, what
is planned, and what is deferred.

A living doc — update as primitives ship. Status legend:

| | |
|---|---|
| ✅ | done — shipped and tested |
| 🟡 | partial — some sub-features in, others not |
| ⬜ | todo — not yet |
| ⏳ | architected-for — design accommodates it, no code yet |

## Read side

| Feature | Status | Notes |
|---|---|---|
| `list/0` | ✅ | M0 — parse `/proc/self/mountinfo` |
| `list/1` (`{:pid, n}`) | ✅ | M0 — parse `/proc/<n>/mountinfo` |
| `list/1` (`{:path, p}`) | ✅ | M0 — reads any mountinfo-format file |
| Octal-escape decoding (`\040` etc.) | ✅ | M0 — paths with spaces, tabs, newlines, backslashes |
| Optional fields (`shared:`, `master:`, …) | ✅ | M0 — exposed as a list of `{:tag, n}` / `:unbindable` |

## Core verbs

| Verb | Status | Notes |
|---|---|---|
| `mount/4` | ✅ | M1 — `mount(2)` via NIF (BEAM's mount ns only; `:in` lands in M3) |
| `umount/2` | ✅ | M1 — `umount2(2)` via NIF (BEAM's mount ns only; `:in` lands in M3) |
| `bind/3` | ✅ | M2 — `mount(MS_BIND)` |
| `remount/2` | ✅ | M2 — `mount(MS_REMOUNT)`; for propagation changes use `mount/4` with `:private` / `:shared` / `:slave` / `:unbindable` directly (not with `:remount`) |
| `move/2` | ✅ | M2 — `mount(MS_MOVE)` |
| `pivot_root/3` | ⬜ | M4 — `pivot_root(2)` with CWD-handling on throwaway thread |

## Mount flags (the `:flags` opt to `mount/4`)

| Atom | `MS_*` constant | Status | Notes |
|---|---|---|---|
| `:ro` | `MS_RDONLY` | ✅ | M1 |
| `:nosuid` | `MS_NOSUID` | ✅ | M1 |
| `:nodev` | `MS_NODEV` | ✅ | M1 |
| `:noexec` | `MS_NOEXEC` | ✅ | M1 |
| `:sync` | `MS_SYNCHRONOUS` | ✅ | M1 |
| `:remount` | `MS_REMOUNT` | ✅ | M1 (driven by `remount/2` in M2) |
| `:mandlock` | `MS_MANDLOCK` | ✅ | M1 |
| `:dirsync` | `MS_DIRSYNC` | ✅ | M1 |
| `:noatime` | `MS_NOATIME` | ✅ | M1 |
| `:nodiratime` | `MS_NODIRATIME` | ✅ | M1 |
| `:bind` | `MS_BIND` | ✅ | M1 (driven by `bind/3` in M2) |
| `:move` | `MS_MOVE` | ✅ | M1 (driven by `move/2` in M2) |
| `:rec` | `MS_REC` | ✅ | M1 — recursive variant |
| `:silent` | `MS_SILENT` | ✅ | M1 |
| `:private` | `MS_PRIVATE` | ✅ | M1 — propagation |
| `:shared` | `MS_SHARED` | ✅ | M1 — propagation |
| `:slave` | `MS_SLAVE` | ✅ | M1 — propagation |
| `:unbindable` | `MS_UNBINDABLE` | ✅ | M1 — propagation |
| `:relatime` | `MS_RELATIME` | ✅ | M1 |
| `:strictatime` | `MS_STRICTATIME` | ✅ | M1 |
| `:lazytime` | `MS_LAZYTIME` | ✅ | M1 |

## Umount flags (the `:flags` opt to `umount/2`)

| Atom | `UMOUNT_*` / `MNT_*` constant | Status | Notes |
|---|---|---|---|
| `:force` | `MNT_FORCE` | ✅ | M1 |
| `:detach` | `MNT_DETACH` | ✅ | M1 — lazy unmount |
| `:expire` | `MNT_EXPIRE` | ✅ | M1 |
| `:no_follow` | `UMOUNT_NOFOLLOW` | ✅ | M1 |

## Cross-namespace `:in` option

| Verb | Status | Notes |
|---|---|---|
| `mount/4` `:in` | ✅ | M3 — throwaway-thread `unshare(CLONE_FS)` + `setns(CLONE_NEWNS)` + `mount(2)` |
| `umount/2` `:in` | ✅ | M3 |
| `bind/3` `:in` | ✅ | M3 |
| `remount/2` `:in` | ✅ | M3 |
| `move/2` `:in` | ✅ | M3 — note: source must not be in a shared peer group (kernel constraint) |
| `pivot_root/3` `:in` | ⬜ | M4 |
| `list/1` cross-ns (via `{:pid, _}`) | ⬜ | M0 — reads `/proc/<n>/mountinfo`; no setns needed |

## Composition with other subsystems

| Pairing | Status | Notes |
|---|---|---|
| `Linx.Process` mount-at-checkpoint via `in: {:pid, host_pid}` | ✅ | M3 — no `Linx.Process` change required |
| `Linx.Process` mount-post-proceed in a running container | ✅ | M3 — same shape; setns is lifecycle-agnostic |

## Value types

| Module | Status | Notes |
|---|---|---|
| `Linx.Mount.Entry` | ✅ | M0 — parsed `/proc/<pid>/mountinfo` line |
| `Linx.Mount.Error` | ✅ | M1 — POSIX-atom errno + path + operation |

## Error reporting

| Mechanism | Status | Notes |
|---|---|---|
| `%Linx.Mount.Error{path, operation, errno, code}` | ✅ | M1 |
| `Exception` impl for `raise`-able paths | ✅ | M1 |

## Deferred — not in `Linx.Mount` itself

See `PLAN.md`'s "Deferred — architected-for, not built here" for the
full list with reasoning:

- New mount API (`fsopen` / `fsmount` / `open_tree` / `move_mount` /
  `mount_setattr`) — possibly a separate `Linx.Mount.New` module
- Typed parsing of `mount_options` / `super_options` strings
- Mount-id-based reference (`umount_by_id/2`)
- Mount-event notification (`mount_notify(2)` or inotify-on-mountinfo)
- Filesystem-specific `data` string helpers (cifs, nfs, etc.)
