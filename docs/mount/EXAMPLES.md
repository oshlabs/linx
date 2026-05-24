# Linx.Mount examples

Hands-on examples of `Linx.Mount` — the filesystem-mount primitives.

Read-side operations (`list/0`, `list/1`) work in a plain `iex -S
mix` session. Anything that *changes* the mount table — `mount/4`,
`umount/2`, `bind/3`, `remount/2`, `move/2`, `pivot_root/3` — needs
the calling thread to have `CAP_SYS_ADMIN` in the target user
namespace (root in the simple case). Start with `./sudorun.sh iex
-S mix`.

> ✅ **All foundation milestones shipped (M0–M4).** Read side,
> mutating verbs, cross-namespace `:in`, `pivot_root/3`, errors,
> the `Entry` and `Error` value types. See `PLAN.md` for what
> was built and `COVERAGE.md` for what's deferred.

## Reading the mount table

`list/0` parses `/proc/self/mountinfo` into a list of
`%Linx.Mount.Entry{}`:

```elixir
iex> {:ok, mounts} = Linx.Mount.list()
{:ok, [
  #Linx.Mount.Entry<ext4 on / (rw,relatime)>,
  #Linx.Mount.Entry<devtmpfs on /dev (rw,nosuid)>,
  #Linx.Mount.Entry<tmpfs on /dev/shm (rw,nosuid,nodev)>,
  #Linx.Mount.Entry<proc on /proc (rw,nosuid,nodev,noexec,relatime)>,
  ...
]}
```

Each entry exposes the 10 fields the kernel records per
`proc(5)`'s mountinfo format — mount id, parent id, device,
root, mount point, mount options, propagation, fstype, source,
super options:

```elixir
iex> root = Enum.find(mounts, & &1.mount_point == "/")
iex> root
#Linx.Mount.Entry<ext4 on / (rw,relatime)>

iex> root.fstype
"ext4"
iex> root.source
"/dev/mapper/cryptroot"
iex> root.propagation
[{:shared, 1}]
iex> root.mount_options
"rw,relatime"
```

### Reading another namespace's mounts

`list/1` with `{:pid, n}` reads `/proc/<n>/mountinfo` — useful for
inspecting a container's mount table without entering its
namespace. This is just a file read; no setns required (`list/1`
runs entirely in the BEAM's own namespace; only the mutating
verbs in M3+ need the throwaway-thread setns dance).

```elixir
iex> {:ok, ct_mounts} = Linx.Mount.list({:pid, container_pid})
iex> Enum.map(ct_mounts, & &1.mount_point)
["/", "/proc", "/dev", "/sys", "/tmp", ...]
```

`{:path, p}` works against any mountinfo-formatted file (useful
for testing parsers, replaying captures, or pointing at
non-standard locations):

```elixir
iex> Linx.Mount.list({:path, "/proc/self/mountinfo"})
{:ok, [...]}
```

Errors:

- `{:error, :enoent}` — the file doesn't exist (pid no longer
  alive, path wrong).
- `{:error, :eacces}` — the BEAM can't read that file (typically
  another user's `/proc/<pid>/`).

In M1 these get wrapped in `%Linx.Mount.Error{}` for consistency
with the mutating verbs.

### Propagation entries

The 7th field of mountinfo carries zero or more propagation tags
— per `mount_namespaces(7)`:

| Entry shape | Meaning |
|---|---|
| `{:shared, n}` | This mount is in shared peer group `n` |
| `{:master, n}` | This mount is a slave of peer group `n` |
| `{:propagate_from, n}` | Propagation source for a slave mount; rare |
| `:unbindable` | Bind mounts of this mount aren't allowed |

A mount can be both shared and slave at once (`[{:shared, 42}, {:master, 7}]`).

### Octal-escaped paths

mountinfo escapes spaces, tabs, newlines, and backslashes in the
`root`, `mount_point`, and `source` fields — kernel writes
`\\040` for space, `\\011` for tab, `\\012` for newline, `\\134`
for backslash. `Linx.Mount` decodes them transparently:

```elixir
# A mount at "/mnt/with spaces" (kernel mountinfo says "/mnt/with\\040spaces"):
iex> entry.mount_point
"/mnt/with spaces"
```

## (Will land with M1 — basic mount + umount)

## Bind, remount, move

Three convenience verbs over `mount/4` for the most common
mutating patterns.

### `bind/3` — make a directory visible at another path

```elixir
iex> File.mkdir_p!("/tmp/scratch/src")
iex> File.mkdir_p!("/tmp/scratch/dst")
iex> File.write!("/tmp/scratch/src/hello", "")

iex> Linx.Mount.bind("/tmp/scratch/src", "/tmp/scratch/dst")
:ok
iex> File.exists?("/tmp/scratch/dst/hello")
true

iex> Linx.Mount.umount("/tmp/scratch/dst")
:ok
```

The bind shows up in mountinfo with the underlying filesystem
type (whatever `src` lives on) and a `root` field pointing at the
original directory:

```elixir
iex> {:ok, mounts} = Linx.Mount.list()
iex> Enum.find(mounts, & &1.mount_point == "/tmp/scratch/dst")
#Linx.Mount.Entry<ext4 on /tmp/scratch/dst (rw,relatime)>
```

`flags: [:rec]` makes the bind recursive — any submounts under
`source` are also bound under `target`:

```elixir
iex> Linx.Mount.bind("/proc/self", "/tmp/scratch/proc-self", flags: [:rec])
:ok
```

### `remount/2` — change flags on an existing mount

The classic use case is making a bind mount read-only after the
fact. **The `:bind` flag is required** when remounting a bind —
without it the kernel tries to remount the underlying filesystem
instead.

```elixir
iex> Linx.Mount.bind("/tmp/scratch/src", "/tmp/scratch/dst")
:ok
iex> Linx.Mount.remount("/tmp/scratch/dst", flags: [:bind, :ro])
:ok

iex> File.write("/tmp/scratch/dst/foo", "")
{:error, :erofs}

# But the underlying source stays writable:
iex> File.write("/tmp/scratch/src/foo", "")
:ok
```

#### Note: `remount/2` is not for propagation changes

Propagation flags (`:private`, `:shared`, `:slave`, `:unbindable`)
are a *separate* mount(2) call form in the kernel — not combined
with `MS_REMOUNT`. Use `mount/4` directly with just the
propagation flag:

```elixir
# Change a mount's propagation to private (detach it from any
# shared peer group it's in):
iex> Linx.Mount.mount("", "/tmp/scratch", "", flags: [:private])
:ok
```

A dedicated `make_private/2` / `make_shared/2` / etc. helper API
may grow in a follow-up; the `mount/4` form is the canonical
escape hatch today and matches what `mount --make-private` does
in shell scripts.

### `move/2` — atomically relocate a mount

```elixir
iex> Linx.Mount.bind("/tmp/scratch/src", "/tmp/scratch/dst")
:ok
iex> Linx.Mount.move("/tmp/scratch/dst", "/tmp/scratch/moved")
:ok

iex> {:ok, mounts} = Linx.Mount.list()
iex> Enum.find(mounts, & &1.mount_point == "/tmp/scratch/moved")
#Linx.Mount.Entry<ext4 on /tmp/scratch/moved (rw,relatime)>
```

**Mind propagation:** `move/2` returns `:einval` if the source
mount, its parent, or the destination's parent has *shared*
propagation. Most distros mount `/tmp` as `shared:1`, so a bind
inside `/tmp` inherits the shared peer group and `move/2` will
refuse it.

Workaround when you control the parent: mount a tmpfs (or
self-bind a directory), mark it private, then everything inside
is in a fresh single-mount peer group:

```elixir
iex> base = "/tmp/scratch-move"
iex> File.mkdir_p!(base)
iex> Linx.Mount.mount("none", base, "tmpfs")
:ok
iex> Linx.Mount.mount("", base, "", flags: [:private])
:ok

iex> # now move/2 between paths inside `base` works freely
iex> File.mkdir_p!("#{base}/src"); File.mkdir_p!("#{base}/dst")
iex> Linx.Mount.bind("#{base}/src", "#{base}/dst")
iex> Linx.Mount.move("#{base}/dst", "#{base}/moved")
:ok
```

## Mounting into another namespace

Every mutating verb takes an `:in` option naming the mount
namespace to operate on:

  * `:self` (default) — the BEAM's own mount namespace.
  * `{:pid, n}` — pid `n`'s mount namespace. Reads
    `/proc/<n>/ns/mnt`.
  * `{:path, p}` — an explicit path to a namespace file
    (typically `/proc/<n>/ns/mnt` but anywhere works).

The mechanism is a throwaway pthread that does
`unshare(CLONE_FS)` to detach from the BEAM's shared
`fs_struct`, then `setns(2)` into the target namespace, then the
syscall, then exits. The BEAM's own scheduler threads never
enter the target namespace.

### Headline use case: remount `/proc` inside a container

The "ps shows host processes" caveat in the project README — a
child spawned with `namespaces: [:mount, :pid]` still sees the
host's `/proc` because the mount namespace was a *copy* of the
host's mount table at spawn time. The fix:

```elixir
iex> {:ok, c} = Linx.Process.spawn(
...>   argv: ["/bin/bash"],
...>   namespaces: [:mount, :pid, :uts, :ipc, :user],
...>   stdio: :pty
...> )
iex> host_pid = receive do {:linx_process, :ready, p} -> p end

# Mount a fresh /proc inside the child's own mount namespace.
# Now `ps` inside the container shows only container processes.
iex> :ok = Linx.Mount.mount("proc", "/proc", "proc", in: {:pid, host_pid})

iex> :ok = Linx.Process.proceed(c)
iex> :ok = Linx.Tty.attach(:controlling, c)
```

### Lifecycle-agnostic: hot-mount into a running container

The setns mechanism works against *any* live process whose
namespace files exist — parked at a checkpoint, fully running,
sleeping, doesn't matter. So mounts can be added at any point in
a workload's life:

```elixir
# Bind a host data volume into a running container, on demand.
iex> :ok = Linx.Mount.bind("/data/cache", "/cache", in: {:pid, container_pid})
```

Same pattern works for `umount/2`, `bind/3`, `remount/2`, and
`move/2`.

### Inspecting another namespace's mount table

`list/1` with `{:pid, n}` doesn't need the setns dance — it just
reads `/proc/<n>/mountinfo` from the BEAM's namespace, which
already reflects the target's mount table. Useful for inspecting
or debugging a container's mounts without touching them:

```elixir
iex> Linx.Mount.list({:pid, container_pid})
{:ok, [
  #Linx.Mount.Entry<ext4 on / (rw,relatime)>,
  #Linx.Mount.Entry<proc on /proc (rw,relatime)>,
  #Linx.Mount.Entry<tmpfs on /tmp (rw,nosuid)>,
  ...
]}
```

### Error stages for cross-namespace failures

When `:in` is in play, failures can happen at extra stages
beyond the target syscall — they surface in
`%Linx.Mount.Error{operation: ...}`:

  * `:open_ns` — the namespace file doesn't exist (typically
    `{:pid, n}` where `n` is no longer alive).
  * `:unshare` — couldn't detach the worker thread's
    `fs_struct`. Extremely unlikely; the only known cause is
    process resource limits.
  * `:setns` — the kernel refused the namespace entry. Most
    common: lacking `CAP_SYS_ADMIN` in the target user
    namespace (rootless containers — see "Rootless caveat"
    below).
  * `:thread` — couldn't create the worker thread; typically
    `EAGAIN` from thread-creation pressure.

```elixir
iex> Linx.Mount.mount("proc", "/proc", "proc", in: {:pid, 9_999_999})
{:error,
 %Linx.Mount.Error{
   path: "/proc/9999999/ns/mnt",
   operation: :open_ns,
   errno: :enoent,
   code: 2
 }}
```

The `:path` field on cross-namespace failures is the namespace
file (not the mount target) — that's the thing that actually
failed.

### Rootless caveat

`Linx.Process` workloads spawned with the `:user` namespace
become unprivileged inside their own user namespace. The
throwaway thread that performs the mount runs as the BEAM's
identity — which is root on a system-level BEAM, but not on a
rootless one. If the BEAM is itself unprivileged and the
container has its own `:user` namespace, `setns(CLONE_NEWNS)`
into the container's mount namespace requires `CAP_SYS_ADMIN` in
*that* namespace — which the BEAM doesn't have unless it also
entered the container's user namespace first.

Practical implication: cross-namespace mounts work cleanly when
the BEAM is system-level root. Rootless setups need the BEAM to
participate in the container's user namespace, which is outside
this subsystem's scope.

### Why the worker thread `unshare`s first

The kernel's mount-namespace setns refuses any thread whose
`fs_struct` is shared with other threads (returns `EINVAL`).
Every scheduler thread in the BEAM shares one `fs_struct`, so a
naked `setns(CLONE_NEWNS)` from a throwaway pthread fails. The
NIF therefore calls `unshare(CLONE_FS)` on the worker thread
first — that detaches the thread's filesystem-attrs view from
the BEAM, satisfying the kernel's check. When the thread exits,
its private `fs_struct` is discarded; the BEAM's scheduler
threads are completely unaffected. Same trick that `nsenter(1)`
uses when it switches mount namespaces.

## Pivoting the root

`pivot_root/3` swaps the mount-namespace's root: makes
`new_root` the new `/` and stashes the old root tree at
`put_old`. It's the kernel call container runtimes use to switch
a workload into a custom rootfs before `execve`.

The syscall is the pickiest in the mount API — there's a setup
ritual to satisfy its constraints. Here's the headline pattern,
running entirely inside a freshly-spawned child via `:in`:

```elixir
iex> alias Linx.Process, as: P
iex> alias Linx.Mount

iex> rootfs = "/run/myorg/web-42"
iex> File.mkdir_p!(rootfs)
iex> File.mkdir_p!(Path.join(rootfs, "old_root"))
# ... populate rootfs with bin/, lib/, etc/, ... before pivoting

iex> {:ok, c} = P.spawn(argv: ["/init"], namespaces: [:mount, :pid, :uts, :ipc])
iex> host_pid = receive do {:linx_process, :ready, p} -> p end

# Detach the child's mount subtree from the host's shared peer
# groups -- pivot_root rejects shared propagation on ancestors.
# `mount --make-rprivate /` is the runc/docker idiom.
iex> :ok = Mount.mount("", "/", "", flags: [:private, :rec], in: {:pid, host_pid})

# Make new_root a mount point (pivot_root requires it). Doing the
# bind inside the child's namespace means it has no peer group
# with anything on the host.
iex> :ok = Mount.bind(rootfs, rootfs, in: {:pid, host_pid})

# The pivot itself.
iex> :ok = Mount.pivot_root(rootfs, Path.join(rootfs, "old_root"), in: {:pid, host_pid})

# Final cleanup: discard the old root tree entirely.
iex> :ok = Mount.umount("/old_root", flags: [:detach], in: {:pid, host_pid})

# Release the workload -- it execs /init from inside the new rootfs.
iex> :ok = P.proceed(c)
```

### Kernel constraints

`pivot_root(2)` returns `EINVAL` unless *all* of these hold:

  * `new_root` is a directory and a mount point.
  * `put_old` is a directory and a path under `new_root`.
  * `put_old` has no other filesystem mounted on it.
  * Neither `new_root`'s parent nor the current root's mount has
    shared propagation flowing into the other.
  * `new_root` and the current root are different mounts.

The setup ritual above satisfies all of them.

### CWD handling

pivot_root requires the calling thread's CWD to be inside
`new_root`. The NIF runs on a worker thread that `unshare`s its
`fs_struct` and `chdir`s into `new_root` before the syscall — so
the BEAM's CWD stays at whatever it was. The chdir is a
worker-thread concern; the caller doesn't observe it. Same
`unshare(CLONE_FS)` trick the M3 cross-namespace path uses.

### Error stages

Beyond the `:pivot_root` stage itself, `pivot_root/3` can fail
at:

  * `:chdir` — couldn't enter `new_root` (doesn't exist, isn't a
    directory). `:path` field carries `new_root`.
  * `:open_ns` / `:unshare` / `:setns` / `:thread` — same as
    other cross-namespace verbs. `:path` field carries the
    namespace path.

```elixir
iex> Linx.Mount.pivot_root("/nope", "/nope/old")
{:error,
 %Linx.Mount.Error{
   path: "/nope",
   operation: :chdir,
   errno: :enoent,
   code: 2
 }}
```

### After pivot: what the workload sees

Inside the new rootfs the workload sees:

  * `/` — the contents of what used to be `new_root`.
  * `/old_root` — the old root tree, exactly as it was.

A real init then typically `umount`s `/old_root` (as in the
example above, via `in:` from outside, or from inside its own
namespace) to free the old rootfs entirely.
