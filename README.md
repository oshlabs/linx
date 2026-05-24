# Linx

**Linux kernel interfaces for Elixir.**

A library of low-level Linux primitives — netlink sockets, process and namespace lifecycle, terminal/PTY control, cgroup v2 resource limits, filesystem mounts — exposed as idiomatic Elixir. The aim is to make these feel as natural to drive from the BEAM as anything in the standard library.

Linx is a library of **primitives**, not a runtime. A container engine, a network orchestrator, or an observability tool is a *consumer* of Linx; the runtime concepts (images, supervision policies, request routing) live in those projects.

> ⚠️ **Early days.** Linx is still pre-1.0 — APIs are settling and breaking changes are likely.

## Installation

Not on Hex yet. Depend on it from Git:

```elixir
def deps do
  [
    {:linx, github: "oshlabs/linx"}
  ]
end
```

Linux only — the underlying kernel interfaces don't exist on macOS, BSD, or Windows.

## The headline example

Spawn a rootless namespaced bash, attach our terminal to it, run a few real commands inside, exit back to iex — verbatim transcript from an actual session:

```
[ldr@fry linx]$ iex -S mix
Erlang/OTP 28 [erts-16.3.1] [source] [64-bit] [smp:8:8] [ds:8:8:10] [async-threads:1] [jit:ns]

Interactive Elixir (1.19.5) - press Ctrl+C to exit (type h() ENTER for help)
iex(1)> {:ok, c} =
          Linx.Process.spawn(
            argv: ["/bin/bash"],
            namespaces: [:net, :mount, :pid, :uts, :ipc, :user],
            stdio: :pty
          )
{:ok, #PID<0.179.0>}
iex(2)> Linx.Process.proceed(c)
:ok
iex(3)> Linx.Tty.attach(:controlling, c)
[nobody@fry linx]$ whoami
nobody
[nobody@fry linx]$ env | head -n3
SHELL=/usr/bin/bash
SESSION_MANAGER=local/fry:@/tmp/.ICE-unix/2936,unix/fry:/tmp/.ICE-unix/2936
WINDOWID=94479143562352
[nobody@fry linx]$ ps | head -n3
    PID TTY          TIME CMD
      1 ?        00:00:13 systemd
      2 ?        00:00:00 kthreadd
[nobody@fry linx]$ w
 23:11:36 up 3 days,  9:22,  1 user,  load average: 0.51, 1.12, 1.70
USER     TTY       LOGIN@   IDLE   JCPU   PCPU  WHAT
ldr      tty1      Wed13    3days  0.04s  0.04s /usr/lib/sddm/sddm-helper ...
[nobody@fry linx]$ exit
exit
{:ok, {:exited, 0}}
iex(4)>
```

A few things worth noticing in that session:

- **Rootless.** No `sudo` to start iex. The `:user` namespace gives the BEAM ephemeral privilege inside the new user ns, which is what makes the other namespaces creatable — and inside, we're an unprivileged `nobody`.
- **`ps` shows host processes.** The `:mount` namespace is fresh, but `/proc` hasn't been remounted inside it, so `ps` reads the host's `/proc` and sees host PIDs. Fixable in one line with `Linx.Mount` — see "Going further: give the container its own `/proc`" below.
- **`exit` returns to iex with `{:ok, {:exited, 0}}`.** The session's exit code propagates back as a plain Elixir return value, after `attach/2` restores the local terminal.
- **No explicit `receive` for the lifecycle events.** The session emits `{:linx_process, :ready, _}` and `:running` into the iex evaluator's mailbox in the background; `attach/2`'s pump only matches on the messages it cares about, so the lifecycle events are just left there for a later `flush()` if you want to look. If you need the host pid (e.g. to configure the child's netns from the outside), `receive` for `:ready` before `proceed/1` — see the next example.

### Going further: give the container its own `/proc`

The caveat from the transcript above — `ps` showing host PIDs even though the child is in a fresh `:mount` namespace — is just the inherited mount table doing its job. Remount `/proc` inside the child's namespace at the checkpoint and `ps` sees only what lives inside:

```elixir
iex> alias Linx.Process, as: P
iex> alias Linx.Mount

iex> {:ok, c} =
...>   P.spawn(
...>     argv: ["/bin/bash"],
...>     namespaces: [:mount, :pid, :uts, :ipc, :user],
...>     stdio: :pty
...>   )
iex> host_pid = receive do {:linx_process, :ready, p} -> p end

# Mount a fresh /proc inside the child's mount namespace.
iex> :ok = Mount.mount("proc", "/proc", "proc", in: {:pid, host_pid})

iex> P.proceed(c)
iex> Linx.Tty.attach(:controlling, c)
```

Now `ps` inside the attached bash shows only the workload's own processes (PID 1 = bash, plus whatever it spawns). The `:in` option works the same way for `umount/2`, `bind/3`, `remount/2`, `move/2`, and `pivot_root/3` — they all operate on the target namespace via the kernel's setns mechanism.

### Going further: configure the container's network before bash starts

The transcript above doesn't touch `Linx.Netlink`. Adding it lets you configure the child's network from the host *while the child is parked at the checkpoint between `clone()` and `execve()`*:

```elixir
iex> alias Linx.Process, as: P
iex> alias Linx.Netlink.Rtnl
iex> alias Linx.Netlink.Rtnl.{Address, Link, Route}
iex> alias Linx.Tty

iex> {:ok, c} =
...>   P.spawn(
...>     argv: ["/bin/bash"],
...>     namespaces: [:net, :mount, :pid, :uts, :ipc],
...>     stdio: :pty
...>   )
iex> host_pid = receive do {:linx_process, :ready, p} -> p end

# Host-side: build a macvlan off eth0 and hand it to the child as ct0.
iex> {:ok, host} = Rtnl.open()
iex> :ok = Link.create_macvlan(host, "ct0", "eth0", :bridge)
iex> :ok = Link.move_to_netns(host, "ct0", host_pid)

# Inside the child's still-fresh netns: configure ct0 and a default route.
iex> {:ok, ns} = Rtnl.open({:pid, host_pid})
iex> :ok = Link.set_up(ns, "lo")
iex> :ok = Address.add(ns, "ct0", "10.0.0.5", 24)
iex> :ok = Link.set_up(ns, "ct0")
iex> :ok = Route.add_default(ns, "10.0.0.1")

# Release the child -- it execs bash now, with a fully configured network.
iex> P.proceed(c)
iex> Tty.attach(:controlling, c)
```

### Going further: cap resources before the workload runs

The same checkpoint window is where `Linx.Cgroup` slots in. Create a cgroup, set limits, place the child's host pid, then proceed:

```elixir
iex> alias Linx.Process, as: P
iex> alias Linx.Cgroup

iex> {:ok, c} = P.spawn(argv: ["/bin/bash"], namespaces: [:net, :pid])
iex> host_pid = receive do {:linx_process, :ready, p} -> p end

# Build the cgroup and apply limits while the workload is parked.
iex> {:ok, cg} = Cgroup.create("/sys/fs/cgroup/myorg/web-42")
iex> :ok = Cgroup.set_memory_max(cg, 256 * 1024 * 1024)   # 256 MiB
iex> :ok = Cgroup.set_pids_max(cg, 100)
iex> :ok = Cgroup.set_cpu_max(cg, {50_000, 100_000})       # half a CPU
iex> :ok = Cgroup.add_process(cg, host_pid)

# Release -- the workload execs already constrained.
iex> P.proceed(c)
:ok

# At any point you can read live counters as a struct:
iex> Cgroup.stats(cg)
{:ok, #Linx.Cgroup.Stats<cpu=0.4s mem=8MiB pids=3>}
```

`Linx.Process` itself has no awareness of cgroups; the checkpoint is the only coupling, exactly the way `Linx.Netlink` integration works. Limits are in force from the moment of `execve`.

The pieces are independent — you can spawn without namespaces, use netlink without spawning, attach to any `Linx.Process` with `stdio: :pty`, drop processes into cgroups whether or not they're Linx-spawned. They compose because they share clean primitives, not because there's a framework holding them together.

## Subsystems

### `Linx.Process` — clone, setns, signals, stdio

The Linux process-lifecycle surface: `clone(2)` with namespace flags, `setns(2)` to enter another process's namespaces, signal delivery, `waitpid(2)`, and stdio plumbing.

The actual syscalls run in a small external C agent — a Port, not a NIF — because `clone()` / `fork()` / `unshare()` inside the multithreaded BEAM corrupts the VM. A checkpoint protocol over fd 3/4 lets the orchestrator do host-side setup before the child execs.

```elixir
iex> alias Linx.Process, as: P

# Plain spawn (no namespaces) -- equivalent to fork+exec.
iex> {:ok, c} = P.spawn(argv: ["/bin/echo", "hello"])
iex> P.proceed(c)
iex> P.wait(c)
{:ok, {:exited, 0}}
```

Every `spawn` returns a session — a GenServer pid that owns the child. The session sends lifecycle events to its owner and ends with exactly one terminal event:

- `{:linx_process, :ready, host_pid}` — child reached the checkpoint
- `{:linx_process, :running}` — child has `execve`'d
- `{:linx_process, :exited, code}` — workload exited normally
- `{:linx_process, :signaled, signum}` — workload was killed by a signal
- `{:linx_process, :aborted}` — `abort/1` was called from the checkpoint; the workload never ran
- `{:linx_process, :error, errno, stage}` — pre-exec failure (e.g. `ENOENT` from `:execve`)

The **checkpoint** is what makes the host/child cooperation work: the child blocks between `clone()` and `execve()` so the host side can move netlink interfaces in, write cgroup state, mount things, whatever — *then* `proceed/1` lets the workload exec. (Or `abort/1` discards it without execve'ing, for setup-time rollback or test scenarios that just want to verify checkpoint-time setup.)

```elixir
iex> {:ok, c} = P.spawn(argv: ["/bin/sleep", "30"], namespaces: [:net])
iex> receive do {:linx_process, :ready, host_pid} -> host_pid end

# ... host-side setup happens here ...

iex> P.proceed(c)
```

Available namespace atoms: `:net`, `:mount`, `:pid`, `:uts`, `:ipc`, `:user`, `:cgroup`, `:time`. All but `:user` need `CAP_SYS_ADMIN`.

`enter/2` runs a new workload *inside* an existing target's namespaces — the equivalent of `nsenter --target <pid>` or `docker exec`:

```elixir
# probe lives inside ct's namespaces; sees only ct's interfaces
iex> {:ok, probe} = P.enter(ct_pid, argv: ["/bin/sh", "-c", "ip -o link | wc -l"])
```

**Stdio plumbing.** By default the workload inherits the BEAM's fds 0/1/2. The `:stdio` option chooses something else:

| Directive | Effect |
|---|---|
| `:inherit` (default) | child sees the BEAM's stdin/out/err |
| `:devnull` | `/dev/null` for all three |
| `{:connect_unix, path}` | per-fd: child connects to an AF_UNIX listener you opened |
| `:pty` | full PTY pair; bytes proxy through the control channel |

The per-fd keyword form lets each fd get its own treatment:

```elixir
iex> {:ok, c} = P.spawn(
...>   argv: ["/bin/echo", "captured"],
...>   stdio: [stdout: {:connect_unix, "/tmp/cap.sock"}, stderr: :devnull]
...> )
```

With `:pty`, reads arrive as `{:linx_process, :pty_out, bytes}` events in the owner's mailbox; writes go through `pty_write/2`:

```elixir
iex> {:ok, c} = P.spawn(argv: ["/bin/cat"], stdio: :pty)
iex> P.proceed(c)
iex> P.pty_write(c, "hello\n")
iex> receive do {:linx_process, :pty_out, b} -> b end
"hello\r\nhello\r\n"   # PTY echoes the input, then cat writes it back
```

`pty_set_winsize/2` configures the PTY's window size — either before `proceed/1` (so the workload sees the right size from the moment it `execve`s) or post-running (so a runtime update reaches the workload as `SIGWINCH`):

```elixir
iex> P.pty_set_winsize(c, {24, 80, 0, 0})  # rows, cols, xpix, ypix
:ok
```

More in [`docs/process/EXAMPLES.md`](docs/process/EXAMPLES.md).

### `Linx.Tty` — terminal, PTY, `/dev/tty`

The kernel's terminal surface: opening `/dev/tty`, manipulating `termios(3)` (raw / save / restore), tty ioctls for window size, plus an `attach/2` byte-pumping helper that composes with `Linx.Process`'s `:pty` stdio directive.

```elixir
iex> alias Linx.Tty
iex> {:ok, fd, saved} = Tty.open_controlling_raw()
iex> Tty.window_size(fd)
{:ok, #Linx.Tty.WindowSize<132x42>}
iex> :ok = Tty.restore_and_close(fd, saved)
```

The `Saved` blob is the original `termios` state, returned so the terminal can be restored exactly. `restore_and_close/2` is idempotent against already-closed fds, so wrapping callers with `try/after` is structurally safe — the user's terminal can never be left in raw mode.

The headliner is **`attach/2`**: given a `Linx.Process` session running under `stdio: :pty`, it hands the caller's controlling terminal over to the workload's PTY master and pumps bytes both ways until the workload exits, restoring the terminal unconditionally on return. Three quality-of-life pieces are baked in:

- **Coexistence with iex.** Erlang's `user_drv` / `prim_tty` driver reads `/dev/tty` to support type-ahead at the iex prompt. `attach/2` calls `:prim_tty.disable_reader/1` for its duration so keystrokes can't be split between the two readers.
- **Initial window size.** The workload's PTY is sized from the local terminal at entry, so `vim` and `less` open at the right dimensions.
- **Live resize.** Drag your terminal corner while inside the attached shell and the workload sees `SIGWINCH` with the new size in real time. A `:gen_event` handler registered on OTP's `:erl_signal_server` carries each resize through.

```elixir
iex> alias Linx.Process, as: P
iex> alias Linx.Tty

iex> {:ok, c} = P.spawn(argv: ["/bin/bash"], stdio: :pty)
iex> receive do {:linx_process, :ready, _} -> :ok end
iex> P.proceed(c)
iex> receive do {:linx_process, :running} -> :ok end

# iex blocks here. Your terminal IS the bash. Type, run vim, resize,
# exit. attach returns the workload's terminal event.
iex> Tty.attach(:controlling, c)
{:ok, {:exited, 0}}
```

More in [`docs/tty/EXAMPLES.md`](docs/tty/EXAMPLES.md).

### `Linx.Cgroup` — cgroup v2 primitives

The kernel's resource-control surface, talking to `/sys/fs/cgroup` directly. Pure Elixir file I/O — no NIF, no Port, no `:os.cmd` to `cgcreate`. cgroupfs *is* the API.

```elixir
iex> alias Linx.Cgroup
iex> Cgroup.supported?()
true

iex> {:ok, cg} = Cgroup.create("/sys/fs/cgroup/myorg/web-42")
iex> :ok = Cgroup.set_memory_max(cg, 256 * 1024 * 1024)
iex> :ok = Cgroup.add_process(cg, host_pid)
```

The path is the handle — `create/1` returns `{:ok, path}` and every other verb takes a path. There's no opaque struct or GenServer wrapping a cgroup; cgroupfs already provides the identity. `create/1` is **idempotent** against EEXIST; `destroy/1` succeeds only when the cgroup is empty (the kernel enforces this with `EBUSY`).

**Typed limit setters** for the common controllers:

| Setter | Interface file | Accepted values |
|---|---|---|
| `set_memory_max/2` | `memory.max` | int (bytes), `:max` |
| `set_pids_max/2` | `pids.max` | int (count), `:max` |
| `set_cpu_max/2` | `cpu.max` | `{quota_us, period_us}`, `:max` |

Plus `freeze/1` / `thaw/1` for `cgroup.freeze` (no controller delegation required — works on every cgroup), `enable_controllers/2` for setting up subtree delegation, and a raw `write/3` / `read/2` escape hatch for any interface file without a typed wrapper.

**Counters as a struct** — `stats/1` returns a `%Linx.Cgroup.Stats{}` with a compact `Inspect`:

```elixir
iex> Linx.Cgroup.stats(cg)
{:ok, #Linx.Cgroup.Stats<cpu=12.3s mem=42MiB pids=3>}
```

Each field is `nil` if its controller isn't delegated to the parent or the kernel is too old to expose it — so the struct works gracefully even on minimal setups.

**Errors as structs** — `%Linx.Cgroup.Error{path, operation, errno, code}` everywhere, never raw `{:error, :enoent}` tuples. Pattern-match on `:errno` and `:operation` for specific failures; the `Exception` impl makes `raise` and `Exception.message/1` work.

```elixir
iex> case Linx.Cgroup.destroy(cg) do
...>   :ok -> :destroyed
...>   {:error, %Linx.Cgroup.Error{errno: :ebusy}} -> :still_has_processes
...>   {:error, %Linx.Cgroup.Error{errno: :enoent}} -> :already_gone
...> end
```

**Composition with `Linx.Process`** happens at the existing checkpoint between `:ready` and `proceed/1`, as in the headline example above. `Linx.Process` has zero awareness of cgroups; cgroupfs is enough.

More in [`docs/cgroup/EXAMPLES.md`](docs/cgroup/EXAMPLES.md).

### `Linx.Mount` — filesystem mounts

`mount(2)`, `umount2(2)`, `pivot_root(2)`, and a pure-Elixir parser for `/proc/<pid>/mountinfo`. Plus convenience verbs for the most common shapes — `bind/3`, `remount/2`, `move/3` — and a cross-namespace `:in` option that operates on any process's mount namespace, not just the BEAM's.

```elixir
iex> alias Linx.Mount

# Read the mount table as %Linx.Mount.Entry{} structs.
iex> {:ok, mounts} = Mount.list()
iex> Enum.find(mounts, & &1.mount_point == "/")
#Linx.Mount.Entry<ext4 on / (rw,relatime)>

# Mount, bind, remount, move, umount -- all with optional flags.
iex> :ok = Mount.mount("none", "/mnt/scratch", "tmpfs", flags: [:nosuid, :nodev])
iex> :ok = Mount.bind("/data/cache", "/mnt/scratch/cache")
iex> :ok = Mount.remount("/mnt/scratch", flags: [:bind, :ro])
iex> :ok = Mount.umount("/mnt/scratch", flags: [:detach])
```

**Full flag catalog** — 21 mount flag atoms (`:ro`, `:nosuid`, `:nodev`, `:noexec`, `:bind`, `:rec`, propagation atoms `:private` / `:shared` / `:slave` / `:unbindable`, `:relatime` / `:strictatime` / `:lazytime`, …) and 4 umount flag atoms (`:force`, `:detach`, `:expire`, `:no_follow`), mapped to the kernel's `MS_*` / `MNT_*` / `UMOUNT_*` constants.

**Cross-namespace via `:in`.** Each mutating verb takes `:in :: :self | {:pid, n} | {:path, p}`. Works whether the target is parked at a `Linx.Process` checkpoint or a fully running container — the kernel's setns is lifecycle-agnostic.

```elixir
# Hot-mount a volume into a running container, no restart needed.
iex> :ok = Mount.bind("/data/cache", "/cache", in: {:pid, container_pid})

# Or pivot a rootfs at checkpoint, before the workload runs.
iex> :ok = Mount.bind(rootfs, rootfs, in: {:pid, host_pid})
iex> :ok = Mount.pivot_root(rootfs, Path.join(rootfs, "old_root"), in: {:pid, host_pid})
```

The NIF wraps each cross-namespace call with the standard `unshare(CLONE_FS)` + `setns(CLONE_NEWNS)` dance on a throwaway pthread — the BEAM's scheduler threads never enter the target namespace.

**Errors as structs** — `%Linx.Mount.Error{path, operation, errno, code}` with `:operation` distinguishing real-syscall failures (`:mount` / `:umount` / `:pivot_root`) from namespace-acquisition failures (`:open_ns` / `:unshare` / `:setns` / `:thread` / `:chdir`).

More in [`docs/mount/EXAMPLES.md`](docs/mount/EXAMPLES.md).

### `Linx.Netlink` — netlink sockets, rtnetlink

An `AF_NETLINK` client with the rtnetlink family fleshed out. Pure-Elixir encode/decode over a `:socket` socket; a small NIF handles the one thing the BEAM can't do safely on its own — entering another network namespace on a throwaway thread.

```elixir
iex> alias Linx.Netlink.Rtnl
iex> alias Linx.Netlink.Rtnl.Link

iex> {:ok, sock} = Rtnl.open()
iex> {:ok, links} = Link.list(sock)
[#Linx.Netlink.Rtnl.Link<"lo" (1) UP MTU=65536>,
 #Linx.Netlink.Rtnl.Link<"eth0" (2) UP MTU=1500>, ...]
```

**rtnetlink resources** with full CRUD across IPv4 and IPv6:

- **Links** — `list` / `get` / `delete` / `move_to_netns` / `set_{up,down,mtu,name,address,master}`, plus virtual-link constructors: `macvlan`, `ipvlan`, `veth`, `vlan`, `bridge`, `dummy`.
- **Addresses** — `list` (all / per-link), `add`, `delete`.
- **Routes** — `list`, `get` (destination lookup), `add` / `add_default`, `delete` / `delete_default`.
- **Neighbours** (ARP / NDP) — `list`, `add`, `delete`.
- **Rules** (policy routing) — `list`, `add`, `delete`.
- **Stats** — `get` / `list` for `rtnl_link_stats64` counters.

**Sockets in another netns.** `Rtnl.open({:pid, child_pid})` opens the socket from inside the target's network namespace; the socket then belongs to that netns for its whole life (the BEAM only ever briefly entered the namespace on an isolated thread). This is what makes the headline example work — configuring the child's network from the host while the child waits at the checkpoint.

```elixir
iex> {:ok, ns} = Rtnl.open({:pid, 41234})
iex> :ok = Link.set_up(ns, "lo")
iex> :ok = Address.add(ns, "eth0", "10.0.0.5", 24)
iex> :ok = Route.add_default(ns, "10.0.0.1")
```

**A codec DSL** (`use Linx.Netlink.Codec`) declares each message's wire format in one `codec do … end` block and generates the struct, `encode/1`, `decode/1`, and reflection.

**Rich errors.** `Linx.Netlink.Error` carries the errno as a POSIX atom plus the kernel's extended-ack message; verbs sharpen ambiguous "no such interface" into "no such *parent* interface" where they know better.

More in [`docs/netlink/EXAMPLES.md`](docs/netlink/EXAMPLES.md).

### Value types

- **`Linx.IP`** — IPv4 or IPv6 address. The `~IP` sigil parses at compile time; `Inspect` round-trips back to the sigil. `Linx.IP.Subnet` adds `contains?/2`, `network/1`, `broadcast/1`.

  ```elixir
  iex> ~IP"192.168.1.1"
  ~IP"192.168.1.1"
  iex> {:ok, net} = Linx.IP.Subnet.parse("10.0.0.0/8")
  iex> Linx.IP.Subnet.contains?(net, ~IP"10.5.3.1")
  true
  ```

- **`Linx.MAC`** — link-layer address. The `~MAC` sigil, same shape.

Decoded netlink fields carry these structs directly; verbs accept either the struct or the equivalent string.

## How Linx is organized

Three kinds of top-level module, named for what they organize:

| Kind | When | Examples |
|---|---|---|
| **Mechanism layer** | A coherent transport with shared infrastructure (codec, framing, error handling, …). | `Linx.Netlink` |
| **Subsystem concept** | A grouping of kernel operations that work together for one purpose. Mirrors how Linux man-page section 7 names things. | `Linx.Process`, `Linx.Tty`, `Linx.Cgroup`, `Linx.Mount` |
| **Value type** | A domain primitive that flows through the mechanisms. Top level. | `Linx.IP`, `Linx.MAC` |

Naming rule of thumb: name a module after a mechanism only when the mechanism has shared shape worth factoring out. Otherwise name it after the kernel subsystem or concept. `Namespace` isn't a subsystem — it's a cross-cutting flag on `clone(2)` — so it doesn't get its own module; the *operations* live where they belong.

Each subsystem owns its docs under `docs/<subsystem>/` — `EXAMPLES.md` (iex-style usage), `PLAN.md` (roadmap), `COVERAGE.md` (surface tracker), `REFERENCES.md` (external sources).

## What's next

- **Within `Linx.Netlink`** — a `Connection` GenServer for concurrent in-flight requests; a `Monitor` for multicast event subscription (the `ip monitor` equivalent); the `NETLINK_GENERIC` family and its subsystems (WireGuard, ethtool, …); more link kinds (`bond`, `vxlan`, `tun`/`tap`).
- **Within `Linx.Cgroup`** — typed setters for less-common controllers (`io.max`, `cpuset.cpus`, `memory.swap.max`), event monitoring (`memory.events`, OOM notifications), `cgroup.kill` for atomic teardown.
- **Within `Linx.Mount`** — the new mount API (`fsopen` / `fsmount` / `open_tree` / `move_mount` / `mount_setattr`); typed parsing of `mount_options` / `super_options`; `cgroup.kill`-style atomic-unmount-by-mount-id.
- **New subsystems on the horizon** — `Linx.Seccomp` (syscall filtering), `Linx.Capabilities` (`capset(2)` / file caps), a first hex release pulling the existing five subsystems together.

Roadmap details live in `docs/<subsystem>/PLAN.md`.

## Docs

`mix docs` generates HexDocs-style HTML under `_build/docs/`. The four living markdown docs per subsystem (EXAMPLES, PLAN, COVERAGE, REFERENCES) are surfaced there too. Once Linx has a first hex release, generated docs will be at [hexdocs.pm/linx](https://hexdocs.pm/linx).

## License

Linx is released under the [MIT License](LICENSE).
