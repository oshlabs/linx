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
host side can do setup before the workload runs. `proceed/1` lets it
proceed.

```elixir
iex> {:ok, child} = P.spawn(argv: ["/bin/echo", "hello"])
iex> receive do {:linx_process, :ready, _} -> :ok end
:ok

# ... do host-side work here, e.g. move a netlink interface into the
# child's netns, write cgroup state, etc. (See "Composing with
# Linx.Netlink" below.)

iex> P.proceed(child)
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
up from the host while the child waits at the checkpoint, then proceed/1.

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

# Advance the child past the checkpoint — it now exec's the workload
# with a fully configured network already in place.
iex> P.proceed(child)
:ok

iex> flush()
{:linx_process, :running}
```

## Signals and synchronous waits

```elixir
# Send SIGTERM (15) to a running workload.
iex> {:ok, child} = P.spawn(argv: ["/bin/sleep", "60"])
iex> receive do {:linx_process, :ready, _} -> :ok end
iex> P.proceed(child)
iex> receive do {:linx_process, :running} -> :ok end
iex> P.signal(child, 15)
:ok
iex> receive do {:linx_process, :signaled, n} -> n end
15
```

Signals sent before the workload has `execve`'d are *buffered* and
flushed in order at the moment of `:running`:

```elixir
iex> {:ok, child} = P.spawn(argv: ["/bin/sleep", "60"])
iex> receive do {:linx_process, :ready, _} -> :ok end

# Buffered -- the workload doesn't exist yet.
iex> P.signal(child, 15)
:ok

iex> P.proceed(child)
iex> flush()
{:linx_process, :running}
{:linx_process, :signaled, 15}      # the buffered SIGTERM landed
```

`wait/1` is the synchronous way to learn the terminal outcome (or
block until it arrives). It can be called before or after the terminal
event has been delivered as a message:

```elixir
iex> {:ok, child} = P.spawn(argv: ["/bin/true"])
iex> receive do {:linx_process, :ready, _} -> :ok end
iex> P.proceed(child)
iex> P.wait(child)
{:ok, {:exited, 0}}

# wait/2 with a timeout returns {:error, :timeout} if the workload is
# still alive after `timeout` ms -- the session is *not* affected.
iex> {:ok, child} = P.spawn(argv: ["/bin/sleep", "60"])
iex> receive do {:linx_process, :ready, _} -> :ok end
iex> P.proceed(child)
iex> P.wait(child, 100)
{:error, :timeout}

iex> P.signal(child, 9)                       # clean up
iex> P.wait(child)
{:ok, {:signaled, 9}}
```

## Aborting a parked session

`abort/1` is the alternative to `proceed/1` from the `:ready` state.
Where `proceed/1` releases the cloned child past the checkpoint so it
`execve`s the workload, `abort/1` discards the session entirely — the
child never runs.

```elixir
iex> {:ok, c} = P.spawn(argv: ["/bin/sleep", "60"], namespaces: [:net])
iex> receive do {:linx_process, :ready, host_pid} -> host_pid end

# ... host-side setup runs here. Suppose it fails or we decide to
# cancel: instead of proceed/1, call abort/1.
iex> P.abort(c)
:ok

iex> flush()
{:linx_process, :aborted}

iex> P.wait(c)
{:ok, :aborted}
```

`abort/1` emits a distinct terminal event `{:linx_process, :aborted}`
that joins `:exited` / `:signaled` / `:error` as a fourth outcome.
`wait/1` returns `{:ok, :aborted}` for aborted sessions.

### Why a separate verb (and not just `signal/2`)

Signals sent before `:running` are *buffered* — they queue in the
GenServer state and replay once the workload `execve`s. A SIGKILL to
a parked session never actually kills the parked child; it sits in
the buffer waiting for an execve that you didn't intend to happen.

`abort/1` operates on the agent's pre-execve state directly: the
agent closes the child's wakeup pipe so the child sees EOF and
`_exit`s, reaps it via `waitpid`, then emits `:aborted`. No execve,
no buffered-signal dance.

### State semantics

| Session state | `abort/1` returns |
|---|---|
| Pre-`:ready` | `:ok` — buffered, fires at the checkpoint |
| `:ready` (parked) | `:ok` — immediate abort |
| `:running` | `{:error, :running}` — past the line; use `signal/2` |
| Already terminal | `{:error, :already_terminated}` |

The pre-`:ready` buffering mirrors `signal/2`'s shape — both verbs
let you express intent before the agent is ready to act on it.

### Use cases

- **Setup-time rollback.** Your container engine starts spawning,
  discovers a problem during checkpoint setup (cgroup creation
  failed, a mount errored, network setup raised), and wants to
  cancel the workload cleanly.
- **Checkpoint-only verification.** A test that wants to confirm
  the namespaces were created correctly without actually running
  anything in them — e.g. the `Linx.Mount` M4 pivot_root test
  pivots the child's mount namespace, verifies via mountinfo, and
  aborts.
- **User-cancellation flow.** A consumer of Linx that's spawning
  on the user's behalf and the user pressed Cancel before the
  workload started.

## Entering an existing process's namespaces

`enter/2` runs a new workload *inside* an existing target's namespaces
— the equivalent of `nsenter --target <pid> -- <cmd>` or `docker exec`.

```elixir
# Spawn a long-running container with a fresh netns.
iex> {:ok, ct} = P.spawn(argv: ["/bin/sleep", "60"], namespaces: [:net])
iex> receive do {:linx_process, :ready, target_pid} -> target_pid end
41234
iex> P.proceed(ct)
iex> receive do {:linx_process, :running} -> :ok end

# Run a probe inside that container's namespaces.
iex> {:ok, probe} = P.enter(41234, argv: ["/bin/sh", "-c", "ip -o link | wc -l"])
iex> receive do {:linx_process, :ready, _} -> :ok end
iex> P.proceed(probe)
iex> P.wait(probe)
{:ok, {:exited, 0}}   # the shell printed "1\n" -- only `lo` in there

# Clean up the container.
iex> P.signal(ct, 9)
iex> P.wait(ct)
{:ok, {:signaled, 9}}
```

By default `enter/2` joins *every* namespace the target has — every
file under `/proc/<target>/ns/`. Pass `:namespaces` to narrow it:

```elixir
# Join only the target's net namespace; mount/pid/etc. stay the
# caller's (so /sbin/ip is still resolvable from the host's rootfs).
iex> P.enter(target_pid, namespaces: [:net], argv: ["/bin/sh", "-c", "..."])
```

Pre-exec failures from enter carry namespace-specific stage atoms —
`:setns_user`, `:open_ns_pid`, etc. — so the failing namespace is
visible in `{:linx_process, :error, errno, stage}`:

```elixir
iex> P.enter(99999999, argv: ["/bin/true"])    # bogus target pid
iex> flush()
{:linx_process, :error, 2, :open_ns_user}      # ENOENT opening /proc/.../ns/user
```

## Error paths

```elixir
# Bad argv (no such binary) — execve fails after proceed/1.
iex> {:ok, child} = P.spawn(argv: ["/this/does/not/exist"])
iex> receive do {:linx_process, :ready, _} -> :ok end
iex> P.proceed(child)
iex> flush()
{:linx_process, :error, 2, :execve}     # ENOENT = 2

# Input validation rejects bad opts before any system call.
iex> P.spawn([])
{:error, :argv_required}

iex> P.spawn(argv: ["/bin/true"], namespaces: [:typo])
{:error, {:bad_namespaces, [:typo]}}
```

## Stdio plumbing

By default the workload inherits the BEAM's fds 0/1/2. The `:stdio`
option chooses something else, either via an atom shorthand applying
to all three fds or via a per-fd keyword list.

### `:devnull` — silence the workload

```elixir
iex> {:ok, c} = P.spawn(argv: ["/bin/echo", "this won't be seen"], stdio: :devnull)
iex> P.proceed(c)
iex> P.wait(c)
{:ok, {:exited, 0}}
```

### `{:connect_unix, path}` — pipe a single fd to an AF_UNIX listener

The caller opens the listener *before* `spawn/1`; the workload
`connect(2)`s to it. Useful for capturing stdout/stderr to a
GenServer, a file, anywhere.

```elixir
iex> path = "/tmp/linx-demo.sock"
iex> {:ok, listener} = :gen_tcp.listen(0, [{:ifaddr, {:local, path}}, :binary, {:active, false}])

iex> {:ok, c} = P.spawn(
...>   argv: ["/bin/echo", "hello from a workload"],
...>   stdio: [stdout: {:connect_unix, path}]
...> )
iex> receive do {:linx_process, :ready, _} -> :ok end
iex> P.proceed(c)

iex> {:ok, sock} = :gen_tcp.accept(listener, 2_000)
iex> :gen_tcp.recv(sock, 0, 2_000)
{:ok, "hello from a workload\n"}
```

### `:pty` — a PTY shared across all three fds

The agent creates a PTY pair in the parent process, makes the child
the session leader with the slave as controlling tty, and proxies
bytes between the master end and the BEAM through the existing
control channel. Reads arrive as owner events:

```elixir
iex> {:ok, c} = P.spawn(argv: ["/bin/echo", "hi"], stdio: :pty)
iex> receive do {:linx_process, :ready, _} -> :ok end
iex> P.proceed(c)

iex> receive do {:linx_process, :pty_out, b} -> b end
"hi\r\n"          # PTY-cooked output translates LF to CRLF

iex> P.wait(c)
{:ok, {:exited, 0}}
```

Writes go through `pty_write/2`:

```elixir
iex> {:ok, c} = P.spawn(argv: ["/bin/cat"], stdio: :pty)
iex> receive do {:linx_process, :ready, _} -> :ok end
iex> P.proceed(c)
iex> P.pty_write(c, "hello\n")
:ok
iex> receive do {:linx_process, :pty_out, b} -> b end
"hello\r\nhello\r\n"   # cat echoes (PTY echoes the input, then cat writes it)

iex> P.signal(c, 9)
iex> P.wait(c)
{:ok, {:signaled, 9}}
```

### Setting the PTY's window size

A PTY-mode session's window size starts at whatever the kernel
defaulted to when the agent opened the slave (usually 0x0). Set it
explicitly with `pty_set_winsize/2`, either before `proceed/1` (so the
workload sees the right size from the moment it `execve`s) or
post-running (so a runtime update reaches the workload via `SIGWINCH`):

```elixir
iex> {:ok, c} = P.spawn(argv: ["/bin/sh", "-c", "stty size"], stdio: :pty)
iex> receive do {:linx_process, :ready, _} -> :ok end
iex> P.pty_set_winsize(c, {24, 80, 0, 0})           # rows, cols, xpix, ypix
:ok
iex> P.proceed(c)
iex> receive do {:linx_process, :pty_out, b} -> b end
"24 80\r\n"
```

A struct (or any map) with `:rows`/`:cols`/`:xpixel`/`:ypixel` fields
also works — `Linx.Tty.WindowSize` is the canonical such struct:

```elixir
iex> P.pty_set_winsize(c, %{rows: 42, cols: 132, xpixel: 0, ypixel: 0})
:ok
```

This is the primitive the [`Linx.Tty`](../tty/) subsystem composes
with — `Linx.Tty.attach/2` calls `pty_set_winsize/2` automatically at
entry, seeding the workload with the caller's terminal size.

## Not yet implemented

`info/1` is still a stub. See `PLAN.md` for the roadmap.
