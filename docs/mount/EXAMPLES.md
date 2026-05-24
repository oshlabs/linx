# Linx.Mount examples

Hands-on examples of `Linx.Mount` — the filesystem-mount primitives.

Read-side operations (`list/0`, `list/1`) work in a plain `iex -S
mix` session. Anything that *changes* the mount table — `mount/4`,
`umount/2`, `bind/3`, `remount/2`, `move/2`, `pivot_root/3` — needs
the calling thread to have `CAP_SYS_ADMIN` in the target user
namespace (root in the simple case). Start with `./sudorun.sh iex
-S mix`.

> 🚧 **Partial.** M0–M3 ship now: the read side, the mutating
> verbs (`mount/4`, `umount/2`, `bind/3`, `remount/2`, `move/2`),
> the cross-namespace `:in` option, and `%Linx.Mount.Error{}`.
> `pivot_root/3` (M4) is the last remaining piece. See `PLAN.md`
> for the roadmap.

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

## (Will land with M4 — pivot_root)
