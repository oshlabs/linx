# Linx

**Linux kernel interfaces for Elixir.**

A library of low-level Linux primitives — netlink sockets, process and namespace lifecycle, terminal/PTY control, cgroup v2 resource limits, filesystem mounts, user-namespace identity mappings, per-process capability sets, per-thread seccomp filters — exposed as idiomatic Elixir. The aim is to make these feel as natural to drive from the BEAM as anything in the standard library.

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

## The headline composition

Linx's value isn't any single subsystem — it's that they all hook into the same `Linx.Process` *checkpoint*, the window between `clone(2)` and `execve(2)` where the child is parked. Inside that window a workload's identity, resource ceiling, network, privileges, and syscall surface are all decided at once, before its first instruction.

```elixir
iex> alias Linx.{Process, User, Cgroup, Capabilities, Seccomp}
iex> alias Linx.Netlink.Rtnl

iex> {:ok, c} =
...>   Process.spawn(
...>     argv: ["/usr/sbin/nginx"],
...>     namespaces: [:net, :pid, :user],
...>     no_new_privs: true
...>   )
iex> receive do {:linx_process, :ready, _} -> :ok end
iex> {:ok, host_pid} = Process.host_pid(c)

# Identity:  root inside ↔ this uid outside.
iex> my_uid = System.cmd("id", ["-u"]) |> elem(0) |> String.trim() |> String.to_integer()
iex> my_gid = System.cmd("id", ["-g"]) |> elem(0) |> String.trim() |> String.to_integer()
iex> :ok = User.setup_maps(host_pid,
...>         uid: [{0, my_uid, 1}], gid: [{0, my_gid, 1}])

# Resources: 256 MiB / half a CPU.
iex> {:ok, cg} = Cgroup.create("/sys/fs/cgroup/myorg/nginx-42")
iex> :ok = Cgroup.set_memory_max(cg, 256 * 1024 * 1024)
iex> :ok = Cgroup.set_cpu_max(cg, {50_000, 100_000})
iex> :ok = Cgroup.add_process(cg, host_pid)

# Network:   a macvlan with an address and a default route.
iex> {:ok, host_sock} = Rtnl.open()
iex> :ok = Rtnl.Link.create_macvlan(host_sock, "ct0", "eth0", :bridge)
iex> :ok = Rtnl.Link.move_to_netns(host_sock, "ct0", host_pid)
iex> {:ok, ns} = Rtnl.open({:pid, host_pid})
iex> :ok = Rtnl.Link.set_up(ns, "ct0")
iex> :ok = Rtnl.Address.add(ns, "ct0", "10.0.0.5", 24)
iex> :ok = Rtnl.Route.add_default(ns, "10.0.0.1")

# Privilege: only cap_net_bind_service.
iex> all = Linx.Capabilities.Constants.all()
iex> :ok = Capabilities.drop_bounding(c,
...>         MapSet.difference(all, MapSet.new([:cap_net_bind_service])))

# Syscalls:  only what nginx actually needs.
iex> nginx_syscalls = ~w(read write openat close fstat brk mmap munmap mprotect
...>                     socket bind listen accept4 setsockopt getsockopt
...>                     rt_sigaction rt_sigprocmask rt_sigreturn exit_group
...>                     epoll_pwait epoll_ctl epoll_create1 clock_gettime futex)a
iex> {:ok, filter} = Seccomp.allow_list(nginx_syscalls, default: :kill_process)
iex> :ok = Seccomp.install(c, filter)

# Release the workload. Every constraint above is in force from
# the moment execve(2) runs.
iex> :ok = Process.proceed(c)
```

The subsystems are independent — you can spawn without namespaces, use netlink without spawning, drop caps without seccomp. They compose cleanly because they share one primitive (the checkpoint), not because there's a framework holding them together. The sections below walk through each subsystem in isolation; the "Going further" recipes that follow show progressively richer compositions, each layering one more subsystem onto a base spawn.

### Going further: become root inside

A workload spawned with `:user` in the namespaces list gets its own user namespace, but until uid/gid maps are written it sees itself as `nobody`/`nogroup` — the kernel's default. `Linx.User.setup_maps/2` writes the maps from the host while the child is parked at the checkpoint — picking the mapping that makes the workload think it's `root` while staying unprivileged outside:

```elixir
iex> alias Linx.Process, as: P
iex> alias Linx.User

iex> {:ok, c} =
...>   P.spawn(
...>     argv: ["/bin/bash"],
...>     namespaces: [:user, :mount, :pid, :uts, :ipc],
...>     stdio: :pty
...>   )

iex> receive do {:linx_process, :ready, _child_view} -> :ok end
iex> {:ok, host_pid} = P.host_pid(c)

# "root inside ↔ me outside" -- the canonical rootless mapping.
iex> my_uid = System.cmd("id", ["-u"]) |> elem(0) |> String.trim() |> String.to_integer()
iex> my_gid = System.cmd("id", ["-g"]) |> elem(0) |> String.trim() |> String.to_integer()
iex> :ok = User.setup_maps(host_pid, uid: [{0, my_uid, 1}], gid: [{0, my_gid, 1}])

iex> P.proceed(c)
iex> Linx.Tty.attach(:controlling, c)
```

Now `whoami` inside the attached bash reports `root`; `id` shows `uid=0(root) gid=0(root)`; the prompt renders as `[root@... /]#` (the `#` is bash's signal that EUID == 0). Outside, the BEAM is still uid 1000 — the kernel maps `uid 0 inside` ↔ `uid 1000 outside` per the `setup_maps` call.

`setup_maps/2` is the canonical "deny setgroups, then write uid_map, then write gid_map" sequence in one call. For finer control, the three primitives (`deny_setgroups/1`, `set_uid_map/2`, `set_gid_map/2`) are available individually.

> **`P.host_pid(c)` vs the `:ready` event.** When `:pid` is in the namespaces list, the `:ready` event delivers the child's *own* view of its pid (= 1 inside the fresh PID namespace). `Linx.Process.host_pid/1` returns the host's view, which is what every procfs path on the outside needs. Use `host_pid/1` whenever you want to address the workload from the host.

### Going further: give the container its own `/proc`

A workload spawned with `:pid` and `:mount` namespaces inherits the host's mount table — so `/proc` still reflects the host, and `ps` inside the container shows host PIDs rather than the namespace's. Remount `/proc` inside the child's namespace at the checkpoint and `ps` sees only what lives inside:

```elixir
iex> alias Linx.Process, as: P
iex> alias Linx.Mount

iex> {:ok, c} =
...>   P.spawn(
...>     argv: ["/bin/bash"],
...>     namespaces: [:mount, :pid, :uts, :ipc, :user],
...>     stdio: :pty
...>   )

iex> receive do {:linx_process, :ready, _} -> :ok end
iex> {:ok, host_pid} = P.host_pid(c)

# Mount a fresh /proc inside the child's mount namespace.
iex> :ok = Mount.mount("proc", "/proc", "proc", in: {:pid, host_pid})

iex> P.proceed(c)
iex> Linx.Tty.attach(:controlling, c)
```

Now `ps` inside the attached bash shows only the workload's own processes (PID 1 = bash, plus whatever it spawns). The `:in` option works the same way for `umount/2`, `bind/3`, `remount/2`, `move/2`, and `pivot_root/3` — they all operate on the target namespace via the kernel's setns mechanism.

> **Rootless caveat.** Mounting via `:in: {:pid, _}` requires the BEAM to have `CAP_SYS_ADMIN` in the child's user namespace. If the BEAM is itself root, that's automatic. If the BEAM is unprivileged *and* the child has its own `:user` namespace, the kernel returns `EPERM` — the workaround is to have the workload itself do the `/proc` remount after `execve` (where it has full caps in its own user ns). See `docs/mount/EXAMPLES.md`.

### Going further: configure the container's network before bash starts

`Linx.Netlink` lets you configure the child's network from the host *while the child is parked at the checkpoint between `clone()` and `execve()`* — build a virtual link, hand it to the child, add an address and route, then proceed:

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
iex> receive do {:linx_process, :ready, _} -> :ok end
iex> {:ok, host_pid} = P.host_pid(c)

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
iex> receive do {:linx_process, :ready, _} -> :ok end
iex> {:ok, host_pid} = P.host_pid(c)

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

### Going further: strip capabilities before the workload runs

The same checkpoint slot also accepts `Linx.Capabilities` write verbs. Drop everything the workload doesn't need from the kernel's perspective — bounding (one-way ceiling), the three thread sets, or the ambient set — before it ever starts:

```elixir
iex> alias Linx.Process, as: P
iex> alias Linx.Capabilities

iex> {:ok, c} = P.spawn(argv: ["/usr/sbin/nginx"])
iex> receive do {:linx_process, :ready, _} -> :ok end
iex> {:ok, host_pid} = P.host_pid(c)

# Strip everything except cap_net_bind_service from bounding.
iex> all = Linx.Capabilities.Constants.all()
iex> keep = MapSet.new([:cap_net_bind_service])
iex> :ok = Capabilities.drop_bounding(c, MapSet.difference(all, keep))

iex> P.proceed(c)
iex> receive do {:linx_process, :running} -> :ok end

iex> {:ok, state} = Capabilities.read(host_pid)
iex> state.bounding
#MapSet<[:cap_net_bind_service]>
```

After `proceed/1`, nginx runs with exactly the one capability it needs to bind a privileged port — even if its binary has file caps that would otherwise grant more, because bounding masks them too. `set_thread_sets/2` (`capset(2)` for effective/permitted/inheritable) and `set_ambient/2` (caps that survive `execve` without file caps) are the other two verbs.

> **Root only.** `PR_CAPBSET_DROP` and `capset(2)` require `CAP_SETPCAP` in the calling thread's effective set, which in practice means root. Uniquely among Linx subsystems, "rootless" doesn't help here.

### Going further: lock down the syscall surface

The same checkpoint slot also accepts `Linx.Seccomp.install/2`. Build a cBPF filter from atoms — allow-list (everything not listed gets `:kill_process` by default) or deny-list (everything not listed gets `:allow`, Docker-style) — and install it before the workload's first instruction:

```elixir
iex> alias Linx.Process, as: P
iex> alias Linx.Seccomp

iex> {:ok, c} = P.spawn(argv: ["/usr/sbin/nginx"], no_new_privs: true)
iex> receive do {:linx_process, :ready, _} -> :ok end

# An allow-list of the syscalls a workload actually uses. Anything
# else (an attacker pivoting to execve, ptrace, kexec_load, ...)
# fires :kill_process by default and dies with SIGSYS.
iex> {:ok, filter} = Seccomp.allow_list(
...>   ~w(read write openat close fstat brk mmap munmap mprotect
...>      accept4 bind listen socket connect setsockopt getsockopt
...>      rt_sigaction rt_sigprocmask rt_sigreturn exit_group)a,
...>   default: :kill_process
...> )

iex> :ok = Seccomp.install(c, filter)
iex> P.proceed(c)
iex> receive do {:linx_process, :running} -> :ok end
```

The filter is a `%Linx.Seccomp.Filter{}` value — composable, introspectable, the same shape regardless of whether you built it with `allow_list/2` / `deny_list/2`, the `Linx.Seccomp.Builder` DSL, or `Linx.Seccomp.from_rules/1` (the data-layer seam external policy adapters like Docker `seccomp.json` parsers will use). Kernel rejections of denied syscalls arrive as `{:linx_process, :signaled, 31}` (SIGSYS) for `:kill_process` actions, or just propagate as the appropriate errno to the workload for `{:errno, :eperm}`-style actions.

> **`no_new_privs: true`.** `seccomp(SECCOMP_SET_MODE_FILTER)` needs either `CAP_SYS_ADMIN` or `PR_SET_NO_NEW_PRIVS`. The `no_new_privs:` opt on `spawn/1` sets the latter early in the child; `install/2` also auto-sets it as a fallback if you forgot. So unprivileged callers Just Work.

`Linx.User` + `Linx.Capabilities` + `Linx.Seccomp` together are the security tripod: identity (who is the workload?), privilege bounds (what can it ask the kernel for?), and syscall surface (what can it call at all?). Three orthogonal envelopes, three independent verbs, all sharing the same `Linx.Process` checkpoint.

The pieces are independent — you can spawn without namespaces, use netlink without spawning, attach to any `Linx.Process` with `stdio: :pty`, drop processes into cgroups whether or not they're Linx-spawned, configure caps and seccomp filters on any session that's at the checkpoint. They compose because they share clean primitives, not because there's a framework holding them together.

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

- `{:linx_process, :ready, child_pid}` — child reached the checkpoint. **Note**: `child_pid` is the child's *own* view of itself — equals the host pid when `:pid` is *not* in the namespaces list, equals `1` when it is. Use `Linx.Process.host_pid/1` to get the host's view in either case.
- `{:linx_process, :running}` — child has `execve`'d
- `{:linx_process, :exited, code}` — workload exited normally
- `{:linx_process, :signaled, signum}` — workload was killed by a signal
- `{:linx_process, :aborted}` — `abort/1` was called from the checkpoint; the workload never ran
- `{:linx_process, :error, errno, stage}` — pre-exec failure (e.g. `ENOENT` from `:execve`)

The **checkpoint** is what makes the host/child cooperation work: the child blocks between `clone()` and `execve()` so the host side can move netlink interfaces in, write cgroup state, mount things, write uid/gid maps, whatever — *then* `proceed/1` lets the workload exec. (Or `abort/1` discards it without execve'ing, for setup-time rollback or test scenarios that just want to verify checkpoint-time setup.)

`host_pid/1` is the verb you'll reach for to address the workload from outside — every cross-namespace primitive in Linx (`Linx.Mount`'s `:in: {:pid, _}`, `Linx.User.setup_maps/2`, `Linx.Cgroup.add_process/2`) wants a host pid.

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

The end-to-end demo — spawn a rootless namespaced bash, attach our local terminal to it, run a few real commands inside, exit back to iex — verbatim transcript from an actual session:

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

- **Rootless.** No `sudo` to start iex. The `:user` namespace gives the BEAM ephemeral privilege inside the new user ns, which is what makes the other namespaces creatable. Inside the container, the workload reports itself as `nobody` — the kernel's default for a user namespace whose uid/gid maps haven't been written. Fixable with `Linx.User` (see "Going further: become root inside" earlier in this doc).
- **`ps` shows host processes.** The `:mount` namespace is fresh, but `/proc` hasn't been remounted inside it, so `ps` reads the host's `/proc` and sees host PIDs. Fixable with `Linx.Mount` (see "Going further: give the container its own `/proc`").
- **`exit` returns to iex with `{:ok, {:exited, 0}}`.** The session's exit code propagates back as a plain Elixir return value, after `attach/2` restores the local terminal.
- **No explicit `receive` for the lifecycle events.** The session emits `{:linx_process, :ready, _}` and `:running` into the iex evaluator's mailbox in the background; `attach/2`'s pump only matches on the messages it cares about, so the lifecycle events are just left there for a later `flush()` if you want to look. If you need the host pid (e.g. to configure the child's mount/user/cgroup state from the outside), `receive` for `:ready` and then call `Linx.Process.host_pid/1` — every other Linx subsystem does that.

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

**Composition with `Linx.Process`** happens at the existing checkpoint between `:ready` and `proceed/1`, as in the headline composition at the top of this doc. `Linx.Process` has zero awareness of cgroups; cgroupfs is enough.

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

### `Linx.User` — user-namespace identity mapping

The procfs surface that turns a workload spawned with `:user` from a kernel-default `nobody` into a properly-mapped identity — typically the rootless trick where the workload thinks it's `root` while staying unprivileged outside.

```elixir
iex> alias Linx.User

iex> User.supported?()
true

# Write uid/gid maps from the host while the child is parked.
iex> :ok = User.setup_maps(host_pid,
...>   uid: [{0, my_host_uid, 1}],
...>   gid: [{0, my_host_gid, 1}]
...> )
```

Pure Elixir file I/O on `/proc/<pid>/{uid_map,gid_map,setgroups}` — no NIF, no Port, no `:in` option (uid/gid maps are written via the host's view of procfs). Smallest subsystem in the library by a wide margin.

**Three primitives + one convenience:**

```elixir
:ok = User.deny_setgroups(host_pid)       # required before set_gid_map/2 for unprivileged callers
:ok = User.set_uid_map(host_pid, mappings)
:ok = User.set_gid_map(host_pid, mappings)

# Or the canonical sequence in one call:
:ok = User.setup_maps(host_pid, uid: [...], gid: [...])
```

**Read side** for inspection:

```elixir
iex> User.read_uid_map(host_pid)
{:ok, [#Linx.User.Map<0 -> 1000>]}

iex> User.read_uid_map(other_pid)  # multi-range identity (runc-style)
{:ok, [
  #Linx.User.Map<0 -> 0>,
  #Linx.User.Map<1..65535 -> 100000..165535>
]}
```

**Each mapping** is a `{inside_id, outside_id, length}` triple. The kernel writes are **write-once** per user namespace — plan the mapping fully before calling. `%Linx.User.Map{}` round-trips cleanly back to the input tuple shape.

**Errors as structs** — `%Linx.User.Error{path, operation, errno, code}` for kernel rejections (`:eperm` if the map is too broad for an unprivileged caller, `:enoent` if the target pid is gone), and `{:error, {:bad_map, _}}` / `{:bad_setup, _}` / `{:bad_setgroups, _}` for caller-side input mistakes — distinct shapes so consumers can pattern-match cleanly.

**Composition with `Linx.Process`** happens at the checkpoint, as in the "Going further: become root inside" example above. `Linx.Process` has zero awareness of user-namespace mappings; the checkpoint is the only coupling.

More in [`docs/user/EXAMPLES.md`](docs/user/EXAMPLES.md).

### `Linx.Capabilities` — per-process Linux capabilities

The kernel's five per-thread capability sets (effective, permitted, inheritable, bounding, ambient) and the syscalls that read and manipulate them. Pure-Elixir read side from `/proc/<pid>/status`; agent-side write side through new checkpoint-window commands in the `Linx.Process` C agent.

```elixir
iex> alias Linx.Capabilities

iex> Capabilities.supported?()
true

iex> {:ok, state} = Capabilities.read(:self)
{:ok, #Linx.Capabilities.State<eff=0 prm=0 inh=0 bnd=41 amb=0>}

iex> MapSet.member?(state.bounding, :cap_net_admin)
true
```

**MapSets of `:cap_*` atoms.** Cap sets are 64-bit kernel bitmasks; in Elixir they're `MapSet`s of `:cap_*` atoms (`:cap_net_admin`, `:cap_sys_admin`, …). Set operations (`MapSet.union/2`, `MapSet.difference/2`) come for free; the bitmask conversion is isolated to `Linx.Capabilities.Constants`.

**Read side** — `read/1` parses `/proc/<pid>/status` into a `%Linx.Capabilities.State{}`:

```elixir
iex> {:ok, state} = Capabilities.read(host_pid)
iex> state.effective
#MapSet<[]>
iex> state.bounding
#MapSet<[:cap_chown, :cap_dac_override, ...]>
```

Errors are structured: `%Linx.Capabilities.Error{path, operation, errno, code}` for procfs failures (`:enoent` if the pid is gone, `:eacces` for the rare permission case, `:bad_status` for a malformed file).

**Forward compatibility** — if the kernel reports cap bits past Linx's table (a newer kernel with caps Linx hasn't catalogued yet), they're silently dropped from the returned MapSets and a single `Logger.warning/1` is emitted per read. The returned `%State{}` is still valid for every cap Linx *does* know about.

**Write side — three checkpoint-window verbs**, all only valid in the `:ready` (parked) state, same shape as `Linx.Process.proceed/1`:

```elixir
# One-way drops from the bounding set (prctl(PR_CAPBSET_DROP)).
:ok = Capabilities.drop_bounding(session, [:cap_sys_admin, :cap_sys_module])

# Set all three thread sets at once (capset(2)). All three keys required.
:ok = Capabilities.set_thread_sets(session,
  effective: [:cap_net_bind_service],
  permitted: [:cap_net_bind_service],
  inheritable: []
)

# Replace the ambient set (prctl(PR_CAP_AMBIENT_CLEAR_ALL) + RAISE per cap).
:ok = Capabilities.set_ambient(session, [:cap_net_bind_service])
```

The verbs are agent-side (the child applies them just before `execve`) — they can't be implemented as a NIF because `capset(2)` and `prctl(PR_CAP*)` are per-thread syscalls and the kernel rejects cross-thread calls. See "Going further: strip capabilities before the workload runs" above for the end-to-end recipe.

**State-machine errors** mirror `Linx.Process.abort/1`: `{:error, :not_ready}` / `{:error, :running}` / `{:error, :already_terminated}`. Caller-side input errors: `{:error, {:bad_capability, atom}}` for unknown cap atoms, `{:error, {:bad_thread_sets, {:missing, key}}}` for `set_thread_sets/2` opts missing one of the three required keys. Kernel-level failures (the workload couldn't drop the cap, capset's subset rule was violated, etc.) arrive asynchronously as `{:linx_process, :error, errno, :cap_drop_bounding | :cap_set_thread | :cap_set_ambient}` on the owner's mailbox.

**Root only for writes.** `PR_CAPBSET_DROP` and `capset(2)` require `CAP_SETPCAP` in the calling thread's effective set, which in practice means the BEAM runs as root.

**File capabilities** (xattrs on binaries, the `setcap(8)` / `getcap(8)` surface) are out of scope for now — a future `Linx.Capabilities.File` is the natural home.

More in [`docs/capabilities/EXAMPLES.md`](docs/capabilities/EXAMPLES.md).

### `Linx.Seccomp` — Linux syscall filtering

The kernel's `seccomp(2)` surface: per-thread cBPF programs that gate every syscall the workload makes. Pure-Elixir cBPF compiler (no `libseccomp` linkage); agent-side install via the same `Linx.Process` checkpoint that `Linx.Capabilities` uses.

```elixir
iex> alias Linx.Seccomp

iex> Seccomp.supported?()
true
iex> Seccomp.arch()
:x86_64
```

**Two-layer API.** The sugar layer is `allow_list/2`, `deny_list/2`, and the `Linx.Seccomp.Builder` DSL — for filters constructed in code. The data layer is `from_rules/1` / `to_rules/1` — the seam external consumers like Silo will use to translate JSON profiles (or any other external policy representation) into Linx filters. Linx itself never sees JSON.

```elixir
# Sugar -- allow-list with kill_process default (the secure shape).
iex> {:ok, filter} = Seccomp.allow_list(
...>   ~w(read write openat close exit_group)a,
...>   default: :kill_process
...> )
#Linx.Seccomp.Filter<x86_64 5 syscalls, 11 BPF insns>

# Sugar -- deny-list with EPERM default (the Docker shape).
iex> {:ok, filter} = Seccomp.deny_list(
...>   ~w(kexec_load init_module delete_module ptrace mount)a
...> )

# Data layer -- consumers translate from external policy and call this.
iex> rules = [
...>   {:allow, :read}, {:allow, :write},
...>   {{:errno, :eperm}, :ptrace},
...>   {:kill_process, :kexec_load}
...> ]
iex> {:ok, filter} = Seccomp.from_rules({rules, :allow})

# DSL.
iex> {:ok, filter} =
...>   Seccomp.builder()
...>   |> Linx.Seccomp.Builder.allow(:read)
...>   |> Linx.Seccomp.Builder.deny(:ptrace, errno: :eperm)
...>   |> Linx.Seccomp.Builder.build(default: :kill_process)
```

**Actions.** Each rule (and the default) is one of: `:allow`, `:kill_process`, `:kill_thread`, `:trap`, `:log`, or `{:errno, atom_or_int}`. Mix freely — most realistic filters allow the common syscalls, return EPERM for graceful-degradation cases (ptrace, process_vm_readv), and kill outright for the dangerous ones (kexec_load, init_module).

**Hand-curated syscall table.** `Linx.Seccomp.Syscalls` ships per-arch atom ↔ number maps for `:x86_64` (239 entries) and `:aarch64` (214 entries) — the common workload subset, the Docker deny-list, and the namespace / capability / seccomp / bpf syscalls Linx itself uses. The module-doc-false comment block documents the extension procedure for future contributors.

**Install at the checkpoint** (the headline composition with `Linx.Process`):

```elixir
iex> {:ok, c} = P.spawn(argv: ["/usr/sbin/nginx"], no_new_privs: true)
iex> receive do {:linx_process, :ready, _} -> :ok end

iex> {:ok, filter} = Seccomp.allow_list(syscalls_nginx_needs)
iex> :ok = Seccomp.install(c, filter)
iex> P.proceed(c)
```

The filter is installed by the child agent (`apply_seccomp` in `c_src/linx_process.c`) right before `execve(2)` — so even `execve` itself is gated by the filter, which is what makes the contract airtight. `seccomp(SECCOMP_SET_MODE_FILTER)` needs `PR_SET_NO_NEW_PRIVS` (or `CAP_SYS_ADMIN`); pass `no_new_privs: true` to `spawn/1` for the principled posture, or let `install/2` auto-set it for you.

**State-machine errors** mirror `Linx.Capabilities`'s write verbs: `{:error, :not_ready}` / `{:error, :running}` / `{:error, :already_terminated}`. Caller-side build errors are tagged tuples: `{:error, {:unknown_syscall, atom}}`, `{:error, {:bad_action, _}}`, `{:error, {:duplicate_rule, atom}}`, `{:error, {:unsupported_arch, atom}}`. Kernel-level install failures arrive asynchronously as `{:linx_process, :error, errno, :seccomp_install | :seccomp_no_new_privs}` on the owner mailbox.

**`%Linx.Seccomp.Error{operation, errno, code}`** is the struct shape for non-tuple build failures (today just the `:e2big` case for filters that would overflow the 8-bit jump distance — the hand-curated tables are well under the limit, but the check is there for when the table grows).

**Deferred** — per-argument matching (`allow_if(:open, &(...))`), multi-arch filters, `SECCOMP_USER_NOTIF` (userspace decision handlers), and Docker `seccomp.json` parsing (the last belongs in consumers, not Linx).

More in [`docs/seccomp/EXAMPLES.md`](docs/seccomp/EXAMPLES.md).

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

**Sockets in another netns.** `Rtnl.open({:pid, child_pid})` opens the socket from inside the target's network namespace; the socket then belongs to that netns for its whole life (the BEAM only ever briefly entered the namespace on an isolated thread). This is what makes the headline composition work — configuring the child's network from the host while the child waits at the checkpoint.

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
| **Subsystem concept** | A grouping of kernel operations that work together for one purpose. Mirrors how Linux man-page section 7 names things. | `Linx.Process`, `Linx.Tty`, `Linx.Cgroup`, `Linx.Mount`, `Linx.User`, `Linx.Capabilities`, `Linx.Seccomp` |
| **Value type** | A domain primitive that flows through the mechanisms. Top level. | `Linx.IP`, `Linx.MAC` |

Naming rule of thumb: name a module after a mechanism only when the mechanism has shared shape worth factoring out. Otherwise name it after the kernel subsystem or concept. `Namespace` isn't a subsystem — it's a cross-cutting flag on `clone(2)` — so it doesn't get its own module; the *operations* live where they belong.

Each subsystem owns its docs under `docs/<subsystem>/` — `EXAMPLES.md` (iex-style usage), `PLAN.md` (roadmap), `COVERAGE.md` (surface tracker), `REFERENCES.md` (external sources).

## What's next

- **Within `Linx.Netlink`** — a `Connection` GenServer for concurrent in-flight requests; a `Monitor` for multicast event subscription (the `ip monitor` equivalent); the `NETLINK_GENERIC` family and its subsystems (WireGuard, ethtool, …); more link kinds (`bond`, `vxlan`, `tun`/`tap`).
- **Within `Linx.Cgroup`** — typed setters for less-common controllers (`io.max`, `cpuset.cpus`, `memory.swap.max`), event monitoring (`memory.events`, OOM notifications), `cgroup.kill` for atomic teardown.
- **Within `Linx.Mount`** — the new mount API (`fsopen` / `fsmount` / `open_tree` / `move_mount` / `mount_setattr`); typed parsing of `mount_options` / `super_options`; `cgroup.kill`-style atomic-unmount-by-mount-id.
- **Within `Linx.User`** — `newuidmap(1)` / `newgidmap(1)` integration for unprivileged multi-range maps via `/etc/subuid` / `/etc/subgid` (required for true `runc rootless`-parity).
- **Within `Linx.Capabilities`** — file capabilities (`security.capability` xattrs on binaries; the `setcap(8)` / `getcap(8)` surface), `SECBIT_*` securebits, per-thread cap reads via `/proc/<pid>/task/<tid>/status`.
- **Within `Linx.Seccomp`** — per-argument matching (`allow_if(:openat, &(&1.flags == :rdonly))` — the S1.5 surface), multi-arch routing for cross-arch workloads, `SECCOMP_USER_NOTIF` for userspace decision handlers, and richer filter introspection.
- **First hex release** — pulling the existing eight subsystems together; HexDocs hosting; a CHANGELOG settling onto semantic versioning.

Roadmap details live in `docs/<subsystem>/PLAN.md`.

## Docs

`mix docs` generates HexDocs-style HTML under `_build/docs/`. The four living markdown docs per subsystem (EXAMPLES, PLAN, COVERAGE, REFERENCES) are surfaced there too. Once Linx has a first hex release, generated docs will be at [hexdocs.pm/linx](https://hexdocs.pm/linx).

## License

Linx is released under the [MIT License](LICENSE).
