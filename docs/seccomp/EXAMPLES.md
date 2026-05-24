# Linx.Seccomp examples

Hands-on examples of `Linx.Seccomp` — Linux syscall-filter
primitives.

Detection (`supported?/0`, `arch/0`) and the constants /
syscall-table queries work in a plain `iex -S mix` session
against any kernel ≥ 3.5. Filter construction
(`allow_list/2`, `deny_list/2`, `Builder`, `from_rules/1`) is
also plain — no installation, no root. Installation
(`install/2`) is agent-side at the `Linx.Process` checkpoint —
needs a parked session and (typically) `no_new_privs: true` or
root.

> 🚧 **Skeleton.** Primitives are still in flight; sections
> fill in as milestones ship. See `PLAN.md` for the roadmap
> and `COVERAGE.md` for what's in / out.

## Detecting seccomp support

```elixir
iex> Linx.Seccomp.supported?()
true
```

`supported?/0` returns `true` iff `/proc/self/status` contains a
`Seccomp:` line — true on any Linux ≥ 3.5, which is every
kernel Linx targets.

## Inspecting the running architecture

```elixir
iex> Linx.Seccomp.arch()
:x86_64

# On aarch64:
iex> Linx.Seccomp.arch()
:aarch64
```

The arch atom drives which syscall table is used when building
filters. Linx v1 supports `:x86_64` and `:aarch64`; other
arches return `:unsupported`.

## (Will land with S0 — table queries)

## (Will land with S1 — filter construction)

```elixir
# Allow-list -- the most secure shape. Anything not listed gets
# the default action, which for allow_list is :kill_process.
{:ok, filter} = Linx.Seccomp.allow_list(
  ~w(read write openat close fstat brk mmap munmap mprotect
     exit exit_group rt_sigreturn)a,
  default: :kill_process
)

# Deny-list -- the Docker default shape. Listed syscalls get the
# deny action (EPERM by default); everything else is allowed.
{:ok, filter} = Linx.Seccomp.deny_list(
  ~w(kexec_load init_module delete_module ptrace swapon swapoff
     mount umount2 pivot_root iopl ioperm)a
)
```

## (Will land with S1 — Builder DSL)

```elixir
{:ok, filter} =
  Linx.Seccomp.builder()
  |> Linx.Seccomp.Builder.allow(:read)
  |> Linx.Seccomp.Builder.allow(:write)
  |> Linx.Seccomp.Builder.deny(:ptrace, errno: :eperm)
  |> Linx.Seccomp.Builder.deny(:kexec_load, action: :kill_process)
  |> Linx.Seccomp.Builder.build(default: :allow)
```

## (Will land with S1 — from_rules/1 data-layer API)

The data-layer API for consumers like Silo that build filters
from external sources:

```elixir
# A rules list -- the shape Silo would build from a parsed
# Docker seccomp.json.
rules = [
  {:allow, :read},
  {:allow, :write},
  {:allow, :openat},
  {:allow, :close},
  {:allow, :exit_group},
  {{:errno, :eperm}, :ptrace},
  {:kill_process, :kexec_load}
]

{:ok, filter} = Linx.Seccomp.from_rules({rules, _default = :allow})
```

## (Will land with S2 — install at the checkpoint)

The headline composition — spawn a workload, install a filter
before it `execve`s, observe it run with a constrained syscall
envelope:

```elixir
{:ok, c} =
  Linx.Process.spawn(
    argv: ["/usr/sbin/nginx"],
    no_new_privs: true,
    stdio: :pty
  )

receive do {:linx_process, :ready, _} -> :ok end

{:ok, filter} = Linx.Seccomp.allow_list(
  ~w(read write openat close fstat brk mmap munmap mprotect
     accept4 bind listen socket connect setsockopt getsockopt
     rt_sigaction rt_sigprocmask rt_sigreturn exit_group)a,
  default: :kill_process
)

:ok = Linx.Seccomp.install(c, filter)
:ok = Linx.Process.proceed(c)

receive do {:linx_process, :running} -> :ok end
```

## Composition with `Linx.Capabilities`

Both subsystems hook into the same checkpoint window. The order
matters in principle but not for correctness — caps and
seccomp are orthogonal envelopes:

```elixir
{:ok, c} = Linx.Process.spawn(argv: ["/usr/sbin/nginx"],
                              no_new_privs: true)
receive do {:linx_process, :ready, _} -> :ok end

# Drop capabilities first -- this is the "what privileged
# operations can the workload attempt?" question.
all_caps = Linx.Capabilities.Constants.all()
keep_caps = MapSet.new([:cap_net_bind_service])
:ok = Linx.Capabilities.drop_bounding(c,
        MapSet.difference(all_caps, keep_caps))

# Then install seccomp -- this is the "which syscalls can the
# workload call at all?" question.
{:ok, filter} = Linx.Seccomp.allow_list(...)
:ok = Linx.Seccomp.install(c, filter)

:ok = Linx.Process.proceed(c)
```

Together: nginx runs as a (mapped) user, with
`cap_net_bind_service` only, calling only the syscalls in the
allow-list. Three orthogonal envelopes, three independent verbs.

## (Will land with S2 — observing kernel rejection)

If the workload tries a syscall its filter denies with
`:kill_process`, the kernel sends `SIGSYS` and the process
dies. The session emits a `:signaled` terminal:

```elixir
{:ok, c} = Linx.Process.spawn(argv: ["/bin/bash"],
                              no_new_privs: true,
                              stdio: :pty)
receive do {:linx_process, :ready, _} -> :ok end

# Pathologically tight filter: don't allow `read`. The shell
# can't even read its stdin before crashing.
{:ok, filter} = Linx.Seccomp.allow_list(
  ~w(write openat close exit_group)a,
  default: :kill_process
)

:ok = Linx.Seccomp.install(c, filter)
:ok = Linx.Process.proceed(c)

# The shell will die on its first read() with SIGSYS (31).
receive do {:linx_process, :signaled, 31} -> :ok end
```

## (Will land with S2 — graceful failure with errno)

For workloads where you want graceful degradation rather than
hard kill, use `{:errno, _}` actions:

```elixir
{:ok, filter} = Linx.Seccomp.deny_list(
  [:ptrace, :process_vm_readv, :process_vm_writev],
  deny_action: {:errno, :eperm}
)

:ok = Linx.Seccomp.install(c, filter)
:ok = Linx.Process.proceed(c)

# The workload runs normally. If it tries to ptrace, the syscall
# returns -1 with errno EPERM -- which userspace code typically
# handles as "you don't have permission" rather than crashing.
```
