# Linx.User examples

Hands-on examples of `Linx.User` — the user-namespace configuration
primitives.

Read-only operations (`read_uid_map/1`, `read_gid_map/1`,
`supported?/0`) work in a plain `iex -S mix` session against any
process's `/proc/<pid>/...`. **Write** operations need either
`CAP_SETUID` / `CAP_SETGID` in the parent user ns (typically root)
*or* a single-line identity map that the kernel allows for
unprivileged callers.

## Detecting user-namespace support

```elixir
iex> Linx.User.supported?()
true
```

`supported?/0` returns true iff `/proc/self/uid_map` exists — true
on any kernel ≥ 3.8. Linx targets modern Linux; on a supported
system this should always be `true`.

## Writing uid/gid maps

The headline rootless flow: spawn a workload in a fresh `:user`
namespace, write maps from the host while the child is parked at
the checkpoint, then proceed.

```elixir
iex> alias Linx.Process, as: P
iex> alias Linx.User

iex> {:ok, c} =
...>   P.spawn(
...>     argv: ["/bin/bash"],
...>     namespaces: [:user, :mount, :pid, :uts, :ipc],
...>     stdio: :pty
...>   )

# The :ready event's pid is the child's *own* view of itself --
# = 1 inside a fresh :pid namespace. For procfs writes we need
# the host's view: that's P.host_pid/1.
iex> receive do {:linx_process, :ready, _child_view} -> :ok end
iex> {:ok, host_pid} = P.host_pid(c)

# "root inside ↔ me outside" -- the canonical rootless mapping.
iex> :ok = User.deny_setgroups(host_pid)
iex> :ok = User.set_uid_map(host_pid, [{0, my_host_uid, 1}])
iex> :ok = User.set_gid_map(host_pid, [{0, my_host_gid, 1}])

iex> :ok = P.proceed(c)
iex> :ok = Linx.Tty.attach(:controlling, c)
```

Inside the attached bash:

```
[root@... /]$ whoami
root
```

Without the maps the workload would still spawn — but the kernel
would default the inside identity to `nobody` (uid 65534), as in
the headline transcript from the project README.

### The `{inside, outside, length}` shape

Each entry maps a contiguous range of IDs:

```elixir
# A single uid (rootless idiom):
[{0, 1000, 1}]               # uid 0 inside ↔ uid 1000 outside

# A range (privileged or via newuidmap; full identity for a 65k
# range starting at 100000):
[{0, 100_000, 65_536}]       # 0..65535 inside ↔ 100000..165535 outside

# Multiple ranges in one map (allowed by the kernel, written
# atomically):
[{0, 1000, 1}, {1, 100_000, 65_535}]
```

The kernel writes are **write-once** per user namespace — a
second call returns `EPERM`. Plan the whole map in one call.

### Why `deny_setgroups/1` first?

Per `user_namespaces(7)`: an unprivileged caller (no
`CAP_SETGID` in the parent user ns) can't write `gid_map` while
the namespace still permits `setgroups(2)`. Writing `"deny"` to
`/proc/<pid>/setgroups` first is the kernel-mandated dance.
Privileged callers can skip it, but the call is idempotent and
costless — so the canonical sequence (and the
`setup_maps/2` convenience) always does the deny first.

```elixir
# Skip the deny only if you're sure you have CAP_SETGID in the
# parent user ns. The Linx.User docs default to including it.
:ok = User.deny_setgroups(host_pid)
:ok = User.set_uid_map(host_pid, uid_maps)
:ok = User.set_gid_map(host_pid, gid_maps)
```

### Errors

Two distinct error shapes — caller mistakes vs kernel rejections:

```elixir
# Caller-side input mistake -- caught before any /proc write:
iex> User.set_uid_map(host_pid, [])
{:error, {:bad_map, :empty}}

iex> User.set_uid_map(host_pid, [{0, 1000}])
{:error, {:bad_map, {:bad_entry, {0, 1000}}}}

iex> User.set_uid_map(host_pid, [{-1, 1000, 1}])
{:error, {:bad_map, {:bad_entry, {-1, 1000, 1}}}}

# Kernel rejection -- structured Linx.User.Error:
iex> User.set_uid_map(host_pid, [{0, 1000, 1}])  # second call
{:error,
 %Linx.User.Error{
   path: "/proc/.../uid_map",
   operation: :set_uid_map,
   errno: :eperm,
   code: 1
 }}

iex> User.set_uid_map(9_999_999, [{0, 1000, 1}])  # dead pid
{:error,
 %Linx.User.Error{
   path: "/proc/9999999/uid_map",
   operation: :set_uid_map,
   errno: :enoent,
   code: 2
 }}
```

Pattern-match on `:errno` and `:operation` to handle specific
failures:

```elixir
case User.set_uid_map(pid, mappings) do
  :ok ->
    :mapped

  {:error, %User.Error{errno: :eperm}} ->
    # Either write-once already done, or the map was too broad
    # for an unprivileged caller (needs CAP_SETUID or
    # newuidmap(1) for multi-range subuid).
    :no_perm

  {:error, %User.Error{errno: :enoent}} ->
    # Target pid is gone.
    :pid_dead

  {:error, {:bad_map, reason}} ->
    # Input validation -- caller mistake, didn't hit the kernel.
    {:invalid_input, reason}
end
```

The `Exception` impl makes `raise` and `Exception.message/1` work
on `%Linx.User.Error{}` too:

```elixir
iex> err = Linx.User.Error.from_posix(:eperm, "/proc/1/uid_map", :set_uid_map)
iex> Exception.message(err)
"user set_uid_map failed on /proc/1/uid_map: eperm (errno 1)"
```

## Reading uid/gid maps

`read_uid_map/1` and `read_gid_map/1` parse `/proc/<pid>/{uid,gid}_map`
into a list of `%Linx.User.Map{}` structs:

```elixir
iex> Linx.User.read_uid_map(host_pid)
{:ok, [#Linx.User.Map<0 -> 1000>]}

# Multi-range identity (the runc-style rootless layout):
iex> Linx.User.read_uid_map(host_pid)
{:ok, [
  #Linx.User.Map<0 -> 0>,
  #Linx.User.Map<1..65535 -> 100000..165535>
]}

# A user ns whose maps haven't been written yet -- the file
# exists but is empty; the kernel defaults the workload's
# identity to "nobody".
iex> Linx.User.read_uid_map(host_pid)
{:ok, []}
```

The `Inspect` impl picks its format by length:

| Length | Renders as |
|---|---|
| 1 | `#Linx.User.Map<0 -> 1000>` (compact, no range syntax) |
| > 1 | `#Linx.User.Map<0..65535 -> 100000..165535>` (range form, inclusive end) |

The struct itself is just three fields — `:inside`, `:outside`,
`:length` — and a `%Linx.User.Map{}` round-trips cleanly back to a
`{inside, outside, length}` tuple if you want to hand it to
`set_uid_map/2` on a different pid:

```elixir
{:ok, maps} = Linx.User.read_uid_map(source_pid)
mappings = Enum.map(maps, &{&1.inside, &1.outside, &1.length})
:ok = Linx.User.set_uid_map(target_pid, mappings)
```

### Errors

Same shape as the write verbs — `%Linx.User.Error{operation:
:read_uid_map | :read_gid_map}` for kernel-level failures:

```elixir
iex> Linx.User.read_uid_map(9_999_999)
{:error,
 %Linx.User.Error{
   path: "/proc/9999999/uid_map",
   operation: :read_uid_map,
   errno: :enoent,
   code: 2
 }}
```

The parser silently drops malformed lines (forward-compatible
against any future kernel additions to the format) — so the
returned `[%Map{}]` is always well-formed.

## The `setup_maps/2` convenience

For the canonical rootless dance, `setup_maps/2` does
`deny_setgroups → set_uid_map → set_gid_map` in one call:

```elixir
:ok = Linx.User.setup_maps(host_pid,
  uid: [{0, my_host_uid, 1}],
  gid: [{0, my_host_gid, 1}]
)
```

Equivalent to:

```elixir
:ok = Linx.User.deny_setgroups(host_pid)
:ok = Linx.User.set_uid_map(host_pid, [{0, my_host_uid, 1}])
:ok = Linx.User.set_gid_map(host_pid, [{0, my_host_gid, 1}])
```

### Options

| Option | Required? | Meaning |
|---|---|---|
| `:uid` | yes | mappings list, same shape as `set_uid_map/2` |
| `:gid` | yes | mappings list, same shape as `set_gid_map/2` |
| `:setgroups` | default `:deny` | `:deny` writes "deny" to setgroups; `:skip` leaves it alone (for privileged callers) |

### Failure semantics

Returns the first error encountered, with the failing step's
`:operation` (or a `:bad_setup` / `:bad_setgroups` /
`:bad_map` shape for caller mistakes):

```elixir
{:error, {:bad_setup, {:missing, :uid}}}    # required opt missing
{:error, {:bad_setgroups, :sometimes}}      # bad :setgroups value
{:error, {:bad_map, _}}                     # bad uid/gid input
{:error, %Linx.User.Error{operation: :deny_setgroups, ...}}
{:error, %Linx.User.Error{operation: :set_uid_map, ...}}
{:error, %Linx.User.Error{operation: :set_gid_map, ...}}
```

Steps that ran successfully before a later step failed are **not
rolled back** — the kernel's write-once semantics on uid_map /
gid_map make rollback impossible anyway, and `deny_setgroups` is
idempotent. The error's `:operation` tells you exactly where the
sequence stopped.

## Full end-to-end: rootless bash in a browser-ready container

Combining everything across `Linx.Process` + `Linx.Mount` +
`Linx.User` for the headline composition. The workload becomes
*root inside its own user namespace*, with `/proc` remounted so
`ps` shows container processes:

```elixir
iex> alias Linx.Process, as: P
iex> alias Linx.{Mount, User, Tty}

iex> {:ok, c} =
...>   P.spawn(
...>     argv: ["/bin/bash"],
...>     namespaces: [:user, :mount, :pid, :uts, :ipc],
...>     stdio: :pty
...>   )

# With :pid in the namespaces list, the :ready event's pid is
# the child's *own* view (= 1). For procfs writes we need the
# host's view of the child -- P.host_pid/1 returns that.
iex> receive do {:linx_process, :ready, _child_view} -> :ok end
iex> {:ok, host_pid} = P.host_pid(c)

# Set up the rootless mapping at the checkpoint.
iex> my_uid = System.cmd("id", ["-u"]) |> elem(0) |> String.trim() |> String.to_integer()
iex> my_gid = System.cmd("id", ["-g"]) |> elem(0) |> String.trim() |> String.to_integer()
iex> :ok = User.setup_maps(host_pid, uid: [{0, my_uid, 1}], gid: [{0, my_gid, 1}])

# Give the container its own /proc (also at the checkpoint).
#
# NOTE: this step requires the BEAM to have CAP_SYS_ADMIN in the
# child's user namespace -- i.e. the BEAM must be running as the
# system root, not just "root inside the new user ns". A rootless
# BEAM (uid 1000) will get EPERM here. The runc-style workaround
# in that case is to have the workload itself do the /proc
# remount after its execve (where it has full caps in its own
# user ns); see docs/mount/EXAMPLES.md for the rootless caveat.
iex> :ok = Mount.mount("proc", "/proc", "proc", in: {:pid, host_pid})

# Release -- the workload execs already inside its own user ns
# with the right identity, and with a /proc that only shows
# container processes.
iex> :ok = P.proceed(c)
iex> Tty.attach(:controlling, c)
```

Inside the attached bash:

```
[root@... /]# whoami
root
[root@... /]# ps
    PID TTY          TIME CMD
      1 pts/0    00:00:00 bash
      ...
```

The headline transcript from the project README, but now with
**root inside** and a **container-only `/proc` view** — both
fixes layered on top of the original via the same checkpoint
window that everything else composes through.
