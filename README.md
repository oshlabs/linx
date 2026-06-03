# Linx

[![CI](https://github.com/oshlabs/linx/actions/workflows/ci.yml/badge.svg)](https://github.com/oshlabs/linx/actions/workflows/ci.yml)

**Linux kernel interfaces for Elixir.**

A library of low-level Linux primitives — netlink sockets, process and namespace lifecycle, terminal/PTY control, cgroup v2 resource limits, filesystem mounts, user-namespace identity mappings, per-process capability sets, per-thread seccomp filters, kernel-tunable parameters, modern firewalling via nf_tables — exposed as idiomatic Elixir. The aim is to make these feel as natural to drive from the BEAM as anything in the standard library.

Linx is a library of **primitives**, not a runtime. A container engine, a network orchestrator, or an observability tool is a *consumer* of Linx; the runtime concepts (images, supervision policies, request routing) live in those projects.

> ⚠️ **0.x.** The API is still settling; minor releases may include breaking changes until 1.0.

## Installation

Add `linx` to your dependencies:

```elixir
def deps do
  [
    {:linx, "~> 0.1"}
  ]
end
```

**Requirements.** Linux only — the underlying kernel interfaces don't exist on macOS, BSD, or Windows. Elixir **1.15+** on Erlang/**OTP 26+** (the `Linx.Tty` group-leader attach mode depends on the OTP-26 `prim_tty` driver). Kernel **6.6 LTS** or newer; the nf_tables paths target 6.12 LTS.

**Build prerequisites.** The kernel-interface NIFs and the process Port are compiled from C (`c_src/`) at install time, so a C compiler and the relevant headers must be present:

- **Debian / Ubuntu:** `sudo apt install build-essential` *(add `erlang-dev` if you installed Erlang from apt rather than asdf/precompiled)*
- **Arch:** `sudo pacman -S base-devel` *(the `erlang` / `erlang-nox` package already ships the Erlang headers)*

`build-essential` / `base-devel` also pull in the libc and Linux UAPI headers the sources include.

## The headline composition

Linx's value isn't any single subsystem — it's that they all hook into the same `Linx.Process` *checkpoint*, the window between `clone(2)` and `execve(2)` where the child is parked. Inside that window a workload's identity, resource ceiling, network, privileges, and syscall surface are all decided at once, before its first instruction.

```elixir
alias Linx.{Process, User, Cgroup, Capabilities, Seccomp}
alias Linx.Netlink.Rtnl

{:ok, c} =
  Process.spawn(
    argv: ["/usr/sbin/nginx"],
    namespaces: [:net, :pid, :user],
    no_new_privs: true
  )
receive do {:linx_process, :ready, _} -> :ok end
{:ok, host_pid} = Process.host_pid(c)

# Identity:  root inside ↔ this uid outside.
my_uid = System.cmd("id", ["-u"]) |> elem(0) |> String.trim() |> String.to_integer()
my_gid = System.cmd("id", ["-g"]) |> elem(0) |> String.trim() |> String.to_integer()
:ok = User.setup_maps(host_pid,
        uid: [{0, my_uid, 1}], gid: [{0, my_gid, 1}])

# Resources: 256 MiB / half a CPU.
{:ok, cg} = Cgroup.create("/sys/fs/cgroup/myorg/nginx-42")
:ok = Cgroup.set_memory_max(cg, 256 * 1024 * 1024)
:ok = Cgroup.set_cpu_max(cg, {50_000, 100_000})
:ok = Cgroup.add_process(cg, host_pid)

# Network:   a macvlan with an address and a default route.
{:ok, host_sock} = Rtnl.open()
:ok = Rtnl.Link.create_macvlan(host_sock, "ct0", "eth0", :bridge)
:ok = Rtnl.Link.move_to_netns(host_sock, "ct0", host_pid)
{:ok, ns} = Rtnl.open({:pid, host_pid})
:ok = Rtnl.Link.set_up(ns, "ct0")
:ok = Rtnl.Address.add(ns, "ct0", "10.0.0.5", 24)
:ok = Rtnl.Route.add_default(ns, "10.0.0.1")

# Firewall:  default drop, allow established + ssh; rules vanish when we do.
{:ok, ct_nfnl} = Linx.Netlink.Nfnl.open({:pid, host_pid})
:ok = Linx.Netfilter.push(ct_nfnl, ~NFT"""
  table inet guard {
    chain input {
      type filter hook input priority 0
      policy drop
      ct state established accept
      tcp dport 22 accept
    }
  }
""")

# Privilege: only cap_net_bind_service.
all = Linx.Capabilities.Constants.all()
:ok = Capabilities.drop_bounding(c,
        MapSet.difference(all, MapSet.new([:cap_net_bind_service])))

# Syscalls:  only what nginx actually needs.
nginx_syscalls = ~w(read write openat close fstat brk mmap munmap mprotect
                    socket bind listen accept4 setsockopt getsockopt
                    rt_sigaction rt_sigprocmask rt_sigreturn exit_group
                    epoll_pwait epoll_ctl epoll_create1 clock_gettime futex)a
{:ok, filter} = Seccomp.allow_list(nginx_syscalls, default: :kill_process)
:ok = Seccomp.install(c, filter)

# Release the workload. Every constraint above is in force from
# the moment execve(2) runs.
:ok = Process.proceed(c)
```

The subsystems are independent — you can spawn without namespaces, use netlink without spawning, drop caps without seccomp. They compose cleanly because they share one primitive (the checkpoint), not because there's a framework holding them together. Each subsystem's module doc carries the standalone walkthroughs and the progressively-richer composition recipes; `docs/<subsystem>/EXAMPLES.md` has runnable, copy-paste transcripts.

## Subsystems

- **`Linx.Process`** — `clone(2)` with namespace flags, `setns(2)`, signal delivery, `waitpid(2)`, and stdio plumbing (inherit / `/dev/null` / AF_UNIX / PTY). The syscalls run in a small external C *agent* — a Port, not a NIF — because `clone()`/`fork()`/`unshare()` inside the multithreaded BEAM corrupts the VM. The **checkpoint** (the parked window between `clone()` and `execve()`) is the seam every other subsystem hooks into. See [`docs/process/EXAMPLES.md`](docs/process/EXAMPLES.md).

- **`Linx.Tty`** — the terminal surface: `/dev/tty`, `termios(3)` (raw / save / restore), window-size ioctls, and `attach/2`, which pumps bytes between a `:pty` workload and the caller's terminal — `:controlling` for a local terminal, `:group_leader` for SSH / `:remsh` — restoring all transient terminal state unconditionally on return. See [`docs/tty/EXAMPLES.md`](docs/tty/EXAMPLES.md).

- **`Linx.Cgroup`** — cgroup v2 resource control via direct `/sys/fs/cgroup` file I/O (no NIF, no `cgcreate`). The path is the handle; typed setters for memory / pids / cpu; live counters as `%Linx.Cgroup.Stats{}`; errors as `%Linx.Cgroup.Error{}`. See [`docs/cgroup/EXAMPLES.md`](docs/cgroup/EXAMPLES.md).

- **`Linx.Mount`** — `mount(2)`, `umount2(2)`, `pivot_root(2)`, convenience verbs (`bind` / `remount` / `move`), a pure-Elixir `/proc/<pid>/mountinfo` parser, and a cross-namespace `:in` option that targets any process's mount namespace, not just the BEAM's. See [`docs/mount/EXAMPLES.md`](docs/mount/EXAMPLES.md).

- **`Linx.User`** — user-namespace identity mapping. Writes `/proc/<pid>/{uid_map,gid_map,setgroups}` to turn a `:user`-namespaced workload from a kernel-default `nobody` into a mapped identity — typically the rootless "root inside ↔ me outside" trick. Pure Elixir; maps are write-once per namespace. See [`docs/user/EXAMPLES.md`](docs/user/EXAMPLES.md).

- **`Linx.Capabilities`** — the five per-thread capability sets (effective / permitted / inheritable / bounding / ambient) as `MapSet`s of `:cap_*` atoms. Pure-Elixir read from `/proc/<pid>/status`; checkpoint-window write verbs (`drop_bounding` / `set_thread_sets` / `set_ambient`). Root-only for writes. See [`docs/capabilities/EXAMPLES.md`](docs/capabilities/EXAMPLES.md).

- **`Linx.Seccomp`** — per-thread cBPF syscall filters compiled in pure Elixir (no `libseccomp`). `allow_list/2`, `deny_list/2`, and the `Linx.Seccomp.Builder` DSL produce a `%Linx.Seccomp.Filter{}`, installed at the checkpoint just before `execve`; `from_rules/1` / `to_rules/1` is the data seam external policy adapters (e.g. a Docker `seccomp.json` parser in a consumer) plug into. See [`docs/seccomp/EXAMPLES.md`](docs/seccomp/EXAMPLES.md).

- **`Linx.Sysctl`** — the `/proc/sys/` knobs `sysctl(8)` reads and writes, with dot-form keys, per-namespace routing, and the same `:in` option as `Linx.Mount`. Pure-Elixir host path; a small NIF handles the cross-namespace case. See [`docs/sysctl/EXAMPLES.md`](docs/sysctl/EXAMPLES.md).

- **`Linx.Netlink`** — an `AF_NETLINK` client with rtnetlink (links / addresses / routes / neighbours / rules / stats — full CRUD across IPv4 and IPv6) and nfnetlink (surfaced separately as `Linx.Netfilter`). Pure-Elixir encode/decode; a NIF only for entering another netns on a throwaway thread. `Rtnl.open({:pid, n})` binds a socket to a child's network namespace for its whole life. See [`docs/netlink/EXAMPLES.md`](docs/netlink/EXAMPLES.md).

- **`Linx.Netfilter`** — nf_tables (the iptables / ip6tables / ebtables successor) over `NETLINK_NETFILTER`. A `%Linx.Netfilter.Ruleset{}` is plain data; build it with the pipeline DSL or the compile-time `~NFT` sigil (real nft syntax), then `push` / `pull` / `diff`. Tables are **socket-owned by default** — when the supervisor that opened the socket dies, the kernel atomically destroys the rules. Live `subscribe/1` monitor + NFLOG `log_listen/2`, plus a `mix format` plugin for `~NFT` bodies and `.nft` files. See [`docs/netfilter/EXAMPLES.md`](docs/netfilter/EXAMPLES.md); [`docs/netfilter/DESIGN.md`](docs/netfilter/DESIGN.md) covers the road to `nft` feature-parity.

- **Value types** — `Linx.IP` (with `Linx.IP.Subnet`) and `Linx.MAC`. Each has a compile-time sigil (`~IP`, `~MAC`) that `Inspect` round-trips. Decoded netlink fields carry these structs directly; verbs accept either the struct or the equivalent string.

## How Linx is organized

Three kinds of top-level module, named for what they organize:

| Kind | When | Examples |
|---|---|---|
| **Mechanism layer** | A coherent transport with shared infrastructure (codec, framing, error handling, …). | `Linx.Netlink` |
| **Subsystem concept** | A grouping of kernel operations that work together for one purpose. Mirrors how Linux man-page section 7 names things. | `Linx.Process`, `Linx.Tty`, `Linx.Cgroup`, `Linx.Mount`, `Linx.User`, `Linx.Capabilities`, `Linx.Seccomp`, `Linx.Sysctl`, `Linx.Netfilter` |
| **Value type** | A domain primitive that flows through the mechanisms. Top level. | `Linx.IP`, `Linx.MAC` |

Name a module after a mechanism only when the mechanism has shared shape worth factoring out; otherwise name it after the kernel subsystem or concept. `Namespace` isn't a subsystem — it's a cross-cutting flag on `clone(2)` — so it doesn't get its own module; the *operations* live where they belong.

Each subsystem owns its living docs under `docs/<subsystem>/`: `EXAMPLES.md` (iex-style usage) and `REFERENCES.md` (external sources). Roadmap and forward-compatibility notes live in each subsystem's module doc.

## Errors

Kernel-level failures are structured exceptions — `%Linx.Cgroup.Error{}`, `%Linx.Mount.Error{}`, `%Linx.Netlink.Error{}`, and so on — never raw `{:error, :enoent}` tuples. Each carries a uniform `operation` / `errno` / `code` core (so you can pattern-match a specific failure) and implements `Exception`, so `raise` and `Exception.message/1` work. Caller-side input mistakes are tagged tuples (`{:error, {:bad_key, _}}`, `{:error, {:unknown_syscall, _}}`, …), distinct from kernel rejections; context-free lifecycle conditions stay bare atoms (`{:error, :not_ready}`, `{:error, :no_process}`).

## Docs

Generated docs are hosted at [hexdocs.pm/linx](https://hexdocs.pm/linx). Locally, `mix docs` builds HexDocs-style HTML under `_build/docs/`; the per-subsystem `EXAMPLES.md` and `REFERENCES.md` are surfaced there alongside the module docs.

## License

Linx is released under the [MIT License](LICENSE).
