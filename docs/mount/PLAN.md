# Linx.Mount — implementation plan

> ✅ **M0–M4 shipped** on branch `mount-foundations` — ready to
> merge to `main`. The full surface is in: `list/0`, `list/1`, the
> mountinfo parser, `mount/4`, `umount/2`, `bind/3`, `remount/2`,
> `move/2`, `pivot_root/3`, the cross-namespace `:in` option,
> plus the `Linx.Mount.Entry` and `Linx.Mount.Error` value
> types. `COVERAGE.md` is the canonical "what's in / what's
> deferred" tracker.

## Goal

Build the foundations of `Linx.Mount`: the kernel's filesystem-mount
surface — `mount(2)`, `umount2(2)`, `pivot_root(2)`, and the read-side
`/proc/.../mountinfo` parser — exposed as Elixir primitives. The
primitives compose with `Linx.Process`: mount inside a child's fresh
`:mount` namespace via the existing checkpoint window *or* at any
later point during the child's life.

The driving use case is the "`ps` shows host processes" caveat in the
README transcript: a child with a fresh `:mount` namespace still
inherits the host's mount table. Remounting `/proc` inside its
namespace is what makes `ps` finally show only container processes.
`Linx.Mount.mount("proc", "/proc", "proc", in: {:pid, host_pid})` is
the line that fixes it.

Beyond `/proc`: rootfs setup (bind-mount an OCI rootfs and `pivot_root`
into it), hot-mounting volumes into running containers, debugging
mountinfo on stuck workloads — anywhere `mount(8)` is useful, `Linx.Mount`
is the BEAM-native equivalent.

`Linx.Mount` is **not** a container rootfs builder, image layer manager,
or OCI runtime. It exposes "mount this filesystem here", "bind this",
"pivot_root to here". Policy — what to mount for a given workload, how
to compose layers, how to size tmpfs — lives in a consumer, not here.

## Guiding principles

**Classic API first.** Linux has two mount APIs: the classic
`mount(2)` / `umount2(2)` / `pivot_root(2)` (stable since forever,
what every shell tool uses), and the "new mount API" introduced in
~5.2 (`fsopen` / `fsmount` / `fsconfig` / `open_tree` / `move_mount` /
`mount_setattr` — more composable, better cross-namespace ergonomics
via mount fds). We start with the classic API because it's
universally documented, every consumer of mount(8) maps to it cleanly,
and the namespace machinery we need (setns + mount on a throwaway
thread) is identical to the netlink-in-netns pattern we already
have. The new API can come as a follow-up module (`Linx.Mount.New`?)
or extension when a concrete consumer asks.

**One NIF, single-call syscalls.** `mount(2)`, `umount2(2)`, and
`pivot_root(2)` are single syscalls that operate on the calling
thread. They don't fork, don't corrupt the BEAM. A NIF
(`Linx.Mount.Native`, mirroring `Linx.Netlink.Socket.Native` and
`Linx.Tty.Native`) is the right tool. No external agent process.

**Cross-namespace via the same setns-on-a-thread dance as netlink.**
For the "mount inside a target process's mount namespace" case, the
NIF spawns a throwaway pthread, calls `setns(2)` to enter the
target's mount (and optionally pid + user) namespace, performs the
mount, and exits. The BEAM never leaves its own namespace; the
operation lands in the target's. This works for **any process whose
namespace files exist** — parked at a `Linx.Process` checkpoint, fully
running after `proceed/1`, or any other live pid. The `:in` option is
lifecycle-agnostic.

**`/proc/.../mountinfo` is the read path.** No NIF for reading —
mountinfo is a plain text file. `Linx.Mount.list/0` parses
`/proc/self/mountinfo`; `Linx.Mount.list({:pid, n})` parses
`/proc/<n>/mountinfo`. The parser handles octal-escaped paths (mountinfo's
quoting convention for spaces, tabs, newlines, backslashes), shared/private/
slave/unbindable propagation, and the optional-fields section.

**Errors as structs.** `%Linx.Mount.Error{path, operation, errno, code}`,
same shape as `%Linx.Cgroup.Error{}` and `%Linx.Netlink.Error{}`.
Pattern-match on `:errno` and `:operation` for specific failures.

**AGENTS.md style throughout:** `@moduledoc`/`@doc`/`@spec` everywhere;
domain data as structs with `@enforce_keys`; one module per file;
cite man pages and the kernel's `Documentation/filesystems/...` where
interpretation is non-obvious.

## Module structure

```
Linx.Mount                      — public API: mount/4, umount/2, bind/3,
                                  remount/2, move/2, pivot_root/2,
                                  list/0, list/1.

Linx.Mount.Native               — the NIF: mount(2), umount2(2),
                                  pivot_root(2), each with an optional
                                  namespace-target argument.

Linx.Mount.Entry                — %Linx.Mount.Entry{} for a parsed
                                  /proc/<pid>/mountinfo line.

Linx.Mount.Error                — %Linx.Mount.Error{path, operation,
                                  errno, code} + Exception impl.

  build
  c_src/linx_mount.c            — NIF source.
  lib/mix/tasks/compile.linx_mount.ex
                                — sibling to compile.netlink_nif and
                                  compile.linx_tty.
```

## The NIF contract

Single-call wrappers around the three relevant syscalls plus the
setns dance. Each function takes an explicit `namespace_fd` (or
`-1` for "use current") so the Elixir side controls namespace
acquisition uniformly.

**`mount(source, target, fstype, flags, data, namespace_fd) → :ok | {:error, errno}`**

`mount(2)` with the standard six arguments. `namespace_fd` of `-1`
mounts in the caller's namespace. A non-negative fd causes the NIF to
spawn a throwaway pthread, `setns(namespace_fd, CLONE_NEWNS)`, perform
the mount, and exit the thread. Identical structure to
`linx_netlink_open_in_pidns` (the netlink throwaway-thread trick).

**`umount(target, flags, namespace_fd) → :ok | {:error, errno}`**

`umount2(2)`. Flags include `MNT_FORCE`, `MNT_DETACH`, `MNT_EXPIRE`,
`UMOUNT_NOFOLLOW`.

**`pivot_root(new_root, put_old, namespace_fd) → :ok | {:error, errno}`**

`pivot_root(2)`. The constraint that the calling thread's CWD be
inside `new_root` is handled by the throwaway thread: it `chdir`s into
`new_root` after `setns`, then calls `pivot_root`. Elixir's working
directory is unaffected (it lives in a different thread).

**`open_nsfd(pid, kind) → {:ok, fd} | {:error, errno}`**

Opens `/proc/<pid>/ns/<kind>` and returns the raw fd for passing into
mount/umount/pivot_root above. Elixir-side close via
`close_nsfd(fd)`. Letting Elixir cache an nsfd for a session means we
don't repeatedly open/close it on each mount op.

## Sequencing — milestones

Each milestone is an independently reviewable commit; tests ship with
the code that needs them; commit + push per milestone.

### M0 — Scaffolding & the read side

- `Linx.Mount` module skeleton (`@moduledoc`, public API stubs
  returning `{:error, :not_yet_implemented}` for the mutating verbs).
- `Linx.Mount.Entry` struct: `mount_id`, `parent_id`, `device`,
  `root`, `mount_point`, `mount_options`, `propagation`,
  `fstype`, `source`, `super_options`. Custom `Inspect`:
  `#Linx.Mount.Entry<proc on /proc (rw,relatime)>`.
- `Linx.Mount.list/0` parses `/proc/self/mountinfo`.
- `Linx.Mount.list/1` parses `/proc/<pid>/mountinfo` via a
  `{:pid, n}` argument.
- The mountinfo parser handles:
  - The 11-field shape per `proc(5)`.
  - Octal-escaped paths (`\040` for space, etc.).
  - The variable-length "optional fields" section terminated by `-`.
  - Multiple propagation flags (`shared:42 master:7` → list).
- `docs/mount/{PLAN,EXAMPLES,COVERAGE,REFERENCES}.md` skeletons.
- Wire `docs/mount/*.md` into `mix.exs` `docs.extras` + groups; add
  `Linx.Mount.Entry` to `groups_for_modules`.
- **Tests:**
  - Plain: parser against fixtures (representative mountinfo blobs
    with escapes, multi-line propagation, optional fields).
  - Integration: `list/0` on the test host returns a non-empty list
    that includes at least `/proc` and `/` (every Linux system has
    these).

### M1 — NIF + `mount/4` + `umount/2` + `Linx.Mount.Error`

- `Linx.Mount.Native` — NIF init, `version/0`,
  `mount/6` (native arity, takes `nsfd = -1` for caller's namespace),
  `umount/3`.
- `c_src/linx_mount.c` — minimal NIF wrapping `mount(2)` and
  `umount2(2)`. No setns dance yet — that lands in M3.
- `lib/mix/tasks/compile.linx_mount.ex` — sibling to
  `compile.netlink_nif` / `compile.linx_tty`.
- `mix.exs` `:compilers` gains `:linx_mount`.
- `Linx.Mount.Error` — struct + `Exception` impl + `from_posix/3`,
  matching `Linx.Cgroup.Error`'s shape. Operations:
  `:mount`, `:umount`, `:pivot_root`.
- `Linx.Mount.mount(source, target, fstype, opts)` — Elixir-side
  wrapper. Opts: `:flags` (list of atoms like `:ro`, `:nodev`,
  `:nosuid`, `:noexec`, …, mapped to `MS_*` constants), `:data`
  (filesystem-specific string).
- `Linx.Mount.umount(target, opts)` — opts: `:flags` (`:force`,
  `:detach`, `:expire`, `:no_follow`).
- **Tests:**
  - Plain: opts validation (unknown flag atom → `:einval`); errors
    against non-existent paths.
  - Integration: mount `tmpfs` at a freshly-created temporary
    directory, observe it in `Linx.Mount.list/0`, umount, observe
    it gone. Cleanup in `on_exit`.

### M2 — Convenience verbs

- `Linx.Mount.bind(source, target, opts)` — `mount(source, target,
  "", [:bind | opts])`.
- `Linx.Mount.remount(target, opts)` — `mount("", target, "",
  [:remount | opts])`.
- `Linx.Mount.move(source, target)` — `mount(source, target, "",
  [:move])`.
- All three are thin wrappers; the heavy lifting is `mount/4`.
- **Tests:** integration — bind a directory, observe in mountinfo;
  remount it read-only, observe `ro` in `:mount_options`; move it,
  observe new path; clean up.

### M3 — Cross-namespace via `:in`

- Every mutating verb gains an `:in` option:
  - `:self` (default) — the BEAM's mount namespace.
  - `{:pid, n}` — the mount namespace of pid `n` (target process
    must exist; namespace files at `/proc/<n>/ns/mnt` must be
    readable).
  - `{:path, p}` — an explicit path to a namespace file.
- `Linx.Mount.Native` gains the setns-on-a-throwaway-thread
  machinery in `c_src/linx_mount.c`. Same pattern as
  `linx_netlink_open_in_pidns` in `c_src/netlink_socket.c`:
  `pthread_create` + `setns(CLONE_NEWNS)` + the syscall + thread
  exits.
- `Linx.Mount.list/1` doesn't need this — it reads
  `/proc/<n>/mountinfo` directly, no setns required.
- **Tests:**
  - Integration: spawn `/bin/sleep 60` with `namespaces: [:mount, :pid]`,
    proceed, then `Linx.Mount.mount("proc", "/proc", "proc", in: {:pid, host_pid})`,
    `Linx.Mount.list({:pid, host_pid})` and assert the new `/proc`
    entry is present.
  - Integration: the same trick *at* the checkpoint (between
    `:ready` and `proceed/1`) — confirm the mount lands before the
    workload sees it.
  - Document the `:user` namespace caveat in `EXAMPLES.md`: a
    rootless BEAM can't mount into a container that's in a separate
    user ns; `EPERM` is expected.

### M4 — `pivot_root/2`

- `Linx.Mount.pivot_root(new_root, put_old, opts)` —
  wraps `pivot_root(2)`. Opts include `:in` (same shape as M3) plus
  `:chdir_into_new_root` (default `true`) — pivot_root requires the
  calling thread's CWD to be inside `new_root`; we chdir on the
  throwaway thread so the BEAM's CWD is unaffected.
- Document the pivot_root constraints in `EXAMPLES.md`: `new_root`
  must be a mount point (typically a bind mount of itself);
  `put_old` must be a directory under `new_root`; the old root must
  not have shared propagation flowing into `new_root`.
- **Tests:**
  - Integration: build a minimal "rootfs" in a tmpdir (bind-mount it
    to itself to make it a mount point, create `put_old/`), spawn a
    `/bin/true`-like workload in a fresh `:mount` namespace, pivot
    via `in: {:pid, host_pid}`, observe via mountinfo, clean up.

## Testing

Same three bands as the other subsystems:

- **Unit.** Mountinfo parser against fixtures (octal escapes,
  optional fields, multiple propagation flags). Plain `mix test`.
- **Integration.** Anything that calls `mount(2)`/`umount(2)`/
  `pivot_root(2)` — `:integration` tag, run via `./sudotest.sh`.
  Each test creates a uniquely-named tmpdir and a uniquely-named
  cgroup-less namespace, cleans up in `on_exit`.
- **Manual / `docs/mount/EXAMPLES.md`.** End-to-end compositions —
  the `/proc` remount at the checkpoint, rootfs choreography for a
  rootless container, hot-volume injection into a running workload.

## Deferred — architected-for, not built here

- **New mount API** — `fsopen` / `fsmount` / `fsconfig` / `open_tree`
  / `move_mount` / `mount_setattr`. Modern, more composable, but the
  classic API covers every use case we have today and is the well-
  trodden path. Future `Linx.Mount.New` if a consumer needs it.
- **Filesystem-specific data quoting.** Many filesystems (cifs, nfs)
  take complex `data` strings with embedded commas, equals, and
  spaces. We pass through whatever the caller gives us; consumers
  building those strings can format themselves. A future
  `Linx.Mount.Data` helper might add typed support for the common
  ones if there's demand.
- **Mount-id-based references.** mountinfo entries have stable mount
  IDs. A future `Linx.Mount.umount_by_id/2` could take an ID instead
  of a path — useful when multiple mounts share a path. Not built
  here.
- **Notification / inotify on mountinfo.** Watching mount events as
  they happen. Would want either `mount_notify(2)` (kernel ≥ 5.x) or
  poll-on-mountinfo; out of scope for foundations.
- **Mount option parsing.** mountinfo's `mount_options` and
  `super_options` strings are exposed verbatim as binary. A consumer
  wanting to parse them into a map is welcome to; we don't bake a
  particular shape in.

## Decisions

1. **Classic API only.** Modern Linux (kernel ≥ 4.x). The new mount
   API stays out of `Linx.Mount` proper; a separate module if
   needed.
2. **NIF, not Port.** Single-call syscalls. The throwaway-thread
   setns dance fits cleanly inside a NIF body. Mirrors the
   netlink-in-netns pattern.
3. **`:in` option taking `:self` / `{:pid, n}` / `{:path, p}`,
   uniformly across every mutating verb.** Same shape as
   `Linx.Netlink.Rtnl.open/1` — and works for any-time mount, not
   just at a `Linx.Process` checkpoint.
4. **No `Linx.Process` change for composition.** The checkpoint is
   the *common* integration window, but the design works equally
   for any post-`proceed/1` time. Setns is lifecycle-agnostic.
5. **Errors as structs.** `%Linx.Mount.Error{path, operation, errno,
   code}` per the project-wide rule.
6. **mountinfo is the source of truth for read-side.** `/proc/mounts`
   exists but is less detailed; `/proc/.../mountinfo` is what we
   parse.
7. **`pivot_root` is its own milestone.** Has enough quirks (CWD,
   mount-point requirement, propagation flow) to warrant a focused
   implementation pass.
