# Linx.User examples

Hands-on examples of `Linx.User` — the user-namespace configuration
primitives.

Read-only operations (`read_uid_map/1`, `read_gid_map/1`,
`supported?/0`) work in a plain `iex -S mix` session against any
process's `/proc/<pid>/...`. **Write** operations need either
`CAP_SETUID` / `CAP_SETGID` in the parent user ns (typically root)
*or* a single-line identity map that the kernel allows for
unprivileged callers.

> 🚧 **Partial.** U0–U1 ship now: scaffolding, `supported?/0`,
> the write side (`deny_setgroups/1`, `set_uid_map/2`,
> `set_gid_map/2`), and `%Linx.User.Error{}`. Read side and
> `setup_maps/2` (U2) land in a follow-up. See `PLAN.md` for the
> roadmap.

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
iex> host_pid = receive do {:linx_process, :ready, p} -> p end

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
costless — so the canonical sequence (and the eventual
`setup_maps/2` convenience in U2) always does the deny first.

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

## (Will land with U2 — read side + setup_maps/2)
