# Linx.Mount examples

Hands-on examples of `Linx.Mount` — the filesystem-mount primitives.

Read-side operations (`list/0`, `list/1`) work in a plain `iex -S
mix` session. Anything that *changes* the mount table — `mount/4`,
`umount/2`, `bind/3`, `remount/2`, `move/2`, `pivot_root/3` — needs
the calling thread to have `CAP_SYS_ADMIN` in the target user
namespace (root in the simple case). Start with `./sudorun.sh iex
-S mix`.

> 🚧 **Partial.** M0 (the read side: `list/0`, `list/1`, the
> `Entry` struct) ships now. Mutating verbs (`mount/4`,
> `umount/2`, `bind/3`, `remount/2`, `move/2`, `pivot_root/3`) and
> the cross-namespace `:in` option land in M1–M4. See `PLAN.md`
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

## (Will land with M2 — bind / remount / move)

## (Will land with M3 — mounting into another namespace via `:in`)

## (Will land with M4 — pivot_root)

## (Will land with M1 — basic mount + umount)

## (Will land with M2 — bind / remount / move)

## (Will land with M3 — mounting into another namespace via `:in`)

## (Will land with M4 — pivot_root)
