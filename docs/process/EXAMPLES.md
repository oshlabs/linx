# Linx.Process examples

Hands-on examples of `Linx.Process` — the clone-with-namespaces and
related process-lifecycle primitives.

Anything that creates a non-`:user` namespace needs `CAP_SYS_ADMIN`, so
run with `./sudorun.sh` or as root. Plain `spawn` without namespaces works
unprivileged.

## Quick start

```elixir
iex> alias Linx.Process, as: P

# Spawn a child, no namespaces -- equivalent to a fork+exec.
iex> {:ok, child} = P.spawn(argv: ["/bin/echo", "hello"])
{:ok, #PID<0.123.0>}

iex> flush()
{:linx_process, :ready, 41234}     # checkpoint: the child's host pid
```

Every spawn returns the GenServer pid that owns the child. The GenServer
sends lifecycle messages to the owner (default: the caller); inspect them
with `flush()` in iex.

## The checkpoint

The child blocks at a checkpoint between `clone()` and `execve()` so the
host side can do setup before the workload runs. `release/1` lets it
proceed.

```elixir
iex> {:ok, child} = P.spawn(argv: ["/bin/echo", "hello"])
iex> receive do {:linx_process, :ready, _} -> :ok end
:ok

# ... do host-side work here, e.g. move a netlink interface into the
# child's netns, write cgroup state, etc. (See "Composing with
# Linx.Netlink" below.)

iex> P.release(child)
:ok

iex> flush()
{:linx_process, :running}
{:linx_process, :exited, 0}
```

Lifecycle events the owner receives over a session:

- `{:linx_process, :ready, child_pid}` — child reached the checkpoint
- `{:linx_process, :running}` — child has `execve`'d
- `{:linx_process, :exited, code}` — workload exited normally
- `{:linx_process, :signaled, signum}` — workload was killed by a signal
- `{:linx_process, :error, errno, stage}` — pre-exec failure (e.g.
  `errno = 2` and `stage = :execve` for `ENOENT`)

Every session ends with exactly one terminal event, after which the
GenServer stops with reason `:normal`.

## Spawning into fresh namespaces

The `:namespaces` option chooses which kinds of namespace the child gets
fresh. Each maps to a `CLONE_NEW*` flag.

```elixir
iex> {:ok, child} = P.spawn(
...>   argv: ["/bin/sleep", "30"],
...>   namespaces: [:net, :uts, :ipc]
...> )
{:ok, #PID<0.124.0>}
```

Available namespace atoms: `:net`, `:mount`, `:pid`, `:uts`, `:ipc`,
`:user`, `:cgroup`, `:time`. All but `:user` require `CAP_SYS_ADMIN`.

The pid the owner receives in `{:linx_process, :ready, child_pid}` is the
child's pid *as the child sees it*: 1 inside a fresh `:pid` namespace,
otherwise its host pid.

## Composing with `Linx.Netlink`

The motivating use case: spawn a child into a fresh netns, set the netns
up from the host while the child waits at the checkpoint, then release.

```elixir
iex> alias Linx.Process, as: P
iex> alias Linx.Netlink.{Rtnl, Socket}
iex> alias Linx.Netlink.Rtnl.{Address, Link, Route}

# Spawn with a fresh netns; the child blocks at the checkpoint.
iex> {:ok, child} = P.spawn(argv: ["/bin/sleep", "60"], namespaces: [:net])
iex> receive do {:linx_process, :ready, host_pid} -> host_pid end
41234

# Host-side: create a macvlan and move it into the child's netns as eth0.
iex> {:ok, host} = Rtnl.open()
iex> :ok = Link.create_macvlan(host, "ct0", "eth0", :bridge)
iex> :ok = Link.move_to_netns(host, "ct0", 41234)

# Inside the child's netns: configure eth0.
iex> {:ok, ns} = Rtnl.open({:pid, 41234})
iex> :ok = Link.set_up(ns, "lo")
iex> :ok = Address.add(ns, "ct0", "10.0.0.5", 24)
iex> :ok = Link.set_up(ns, "ct0")
iex> :ok = Route.add_default(ns, "10.0.0.1")

# Release the child — it now exec's the workload with a fully configured
# network already in place.
iex> P.release(child)
:ok

iex> flush()
{:linx_process, :running}
```

## Error paths

```elixir
# Bad argv (no such binary) — execve fails after release.
iex> {:ok, child} = P.spawn(argv: ["/this/does/not/exist"])
iex> receive do {:linx_process, :ready, _} -> :ok end
iex> P.release(child)
iex> flush()
{:linx_process, :error, 2, :execve}     # ENOENT = 2

# Input validation rejects bad opts before any system call.
iex> P.spawn([])
{:error, :argv_required}

iex> P.spawn(argv: ["/bin/true"], namespaces: [:typo])
{:error, {:bad_namespaces, [:typo]}}
```

## Not yet implemented

`enter/2` (P3), `signal/2` + `wait/1` (P2), `info/1`, `pty_master/1`
(P4) and `:stdio` directives are still stubs — they return
`{:error, :not_yet_implemented}` for now. See `PLAN.md` for the
roadmap.
