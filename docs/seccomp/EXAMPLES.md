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

> **Status: live.** S0–S2 are shipped — detection, syscall table,
> filter construction, BPF compiler, and kernel-side install at the
> `Linx.Process` checkpoint. See `PLAN.md` for the design notes and
> `COVERAGE.md` for the feature matrix. Per-arg matching (`allow_if/3`)
> is the deferred S1.5 surface.

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

## Querying the syscall table

```elixir
iex> Linx.Seccomp.Syscalls.to_number(:read, :x86_64)
0
iex> Linx.Seccomp.Syscalls.to_number(:read, :aarch64)
63
iex> Linx.Seccomp.Syscalls.from_number(317, :x86_64)
:seccomp
iex> Linx.Seccomp.Syscalls.from_number(99999, :x86_64)
:unknown
iex> MapSet.size(Linx.Seccomp.Syscalls.all(:x86_64))
239
```

`Linx.Seccomp.Syscalls` is `@moduledoc false` and the inverse is
intended for use by `Linx.Seccomp` itself, but it's accessible for
introspection. See `docs/seccomp/PLAN.md` "Extending the syscall
table" for how to add an entry the table doesn't ship yet.

## Building filters — `allow_list/2` and `deny_list/2`

```elixir
# Allow-list — the most secure shape. Anything not listed gets the
# default action, which for allow_list is :kill_process (per D1).
{:ok, filter} = Linx.Seccomp.allow_list(
  ~w(read write openat close fstat brk mmap munmap mprotect
     exit_group rt_sigreturn)a,
  default: :kill_process
)
filter
#=> #Linx.Seccomp.Filter<x86_64 11 syscalls, 17 BPF insns>

# Deny-list — the Docker default shape. Listed syscalls get the
# deny action (EPERM by default); everything else is allowed.
{:ok, filter} = Linx.Seccomp.deny_list(
  ~w(kexec_load init_module delete_module ptrace swapon swapoff
     mount umount2 pivot_root)a
)
filter
#=> #Linx.Seccomp.Filter<x86_64 9 syscalls, 15 BPF insns>
```

The `Filter` struct's compact Inspect shows the arch, the rule
count, and the cBPF instruction count — the raw BPF binary lives
in `filter.bpf` if you ever need to look at the bytes.

## Building filters — `Linx.Seccomp.Builder`

The fluent DSL for filters constructed in code (rather than
translated from external policy):

```elixir
{:ok, filter} =
  Linx.Seccomp.builder()
  |> Linx.Seccomp.Builder.allow(:read)
  |> Linx.Seccomp.Builder.allow(:write)
  |> Linx.Seccomp.Builder.allow(:exit_group)
  |> Linx.Seccomp.Builder.deny(:ptrace, errno: :eperm)
  |> Linx.Seccomp.Builder.deny(:kexec_load, action: :kill_process)
  |> Linx.Seccomp.Builder.build(default: :allow)
```

`deny/3` takes either `errno: :eacces` (shorthand for `{:errno,
:eacces}`) or `action: :kill_process` for an explicit verdict; if
both are given, `:action` wins.

## Building filters — `from_rules/1` (data-layer API)

The seam consumers like Silo use when they translate external
policy (Docker `seccomp.json`, custom DSLs, runtime config) into
a fully-resolved Linx filter:

```elixir
# A rules list — the shape Silo would build from a parsed
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

# And back again — for filters Linx itself built.
{:ok, {^rules, :allow}} = Linx.Seccomp.to_rules(filter)
```

## Error shapes

Build errors are caller-actionable atoms — what the failing
expression returned, and what to fix:

```elixir
iex> Linx.Seccomp.allow_list([:not_a_real_syscall])
{:error, {:unknown_syscall, :not_a_real_syscall}}

iex> Linx.Seccomp.allow_list([:read], default: :not_an_action)
{:error, {:bad_action, :not_an_action}}

iex> Linx.Seccomp.allow_list([:read, :read])
{:error, {:duplicate_rule, :read}}

iex> Linx.Seccomp.from_rules({[:not_a_rule], :allow})
{:error, {:bad_rule, :not_a_rule}}
```

The `%Linx.Seccomp.Error{}` struct is reserved for kernel-side
failures (S2's `:install` / `:set_no_new_privs` operations) and
the rare `:build` failure that doesn't fit a tagged tuple — today
just `:e2big` for filters that overflow the 255-instruction jump
limit.

## Installing a filter at the checkpoint

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

## Observing kernel rejection — `SIGSYS` on `:kill_process`

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

## Graceful degradation — `{:errno, _}` actions

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
