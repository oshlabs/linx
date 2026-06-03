# Linx.Cgroup examples

Hands-on examples of `Linx.Cgroup` — the cgroup v2 primitives.

Read-only operations work in a plain `iex -S mix` session. Anything
that *changes* the cgroup hierarchy — `create/1`, `add_process/2`,
`write/3`, `destroy/1` — needs root. Start with `./sudorun.sh iex
-S mix`.

## Detecting cgroup v2

```elixir
Linx.Cgroup.supported?()
# => true
```

`supported?/0` returns true iff `/sys/fs/cgroup/cgroup.controllers`
is readable — the canonical "unified hierarchy is mounted" check.
Returns false on cgroup-v1-only hosts (Linx targets v2 only).

## Lifecycle: create, destroy, add_process

```elixir
alias Linx.Cgroup
{:ok, cg} = Cgroup.create("/sys/fs/cgroup/myorg/web-42")
# => {:ok, "/sys/fs/cgroup/myorg/web-42"}

:ok = Cgroup.add_process(cg, 41234)   # move a pid in
:ok = Cgroup.destroy(cg)              # remove the cgroup
```

The path *is* the handle — `create/1` returns `{:ok, path}`, and
every other verb takes that path. There's no opaque struct or
GenServer wrapping a cgroup; cgroupfs already provides the identity.

`create/1` is **idempotent against `EEXIST`**:

```elixir
Cgroup.create("/sys/fs/cgroup/myorg/web-42")
# => {:ok, "/sys/fs/cgroup/myorg/web-42"}
Cgroup.create("/sys/fs/cgroup/myorg/web-42")
# => {:ok, "/sys/fs/cgroup/myorg/web-42"}
```

`destroy/1` only succeeds when the cgroup is **empty** — the kernel
returns `EBUSY` while any process is still in it:

```elixir
Cgroup.add_process(cg, 41234)
# => :ok
Cgroup.destroy(cg)
# => {:error,
#  %Linx.Cgroup.Error{
#    path: "/sys/fs/cgroup/myorg/web-42",
#    operation: :destroy,
#    errno: :ebusy,
#    code: 16
#  }}
```

Wait for the workload to exit (or move it out) before destroying.

## Raw read and write

For any cgroup interface file that doesn't have a typed setter yet,
fall back to `read/2` and `write/3`:

```elixir
Cgroup.write(cg, "memory.max", 256 * 1024 * 1024)
# => :ok
Cgroup.read(cg, "memory.max")
# => {:ok, "268435456"}

Cgroup.write(cg, "memory.max", :max)         # special value
# => :ok
Cgroup.read(cg, "memory.max")
# => {:ok, "max"}
```

`read/2` trims the trailing newline cgroupfs interface files always
ship with — callers almost never want it. Atoms, integers, and
binaries all work as `write/3` values (anything `to_string/1`
handles).

## Composing with `Linx.Process`

The motivating use case: place a workload into a cgroup at the
`Linx.Process` checkpoint, *before* `proceed/1`, so the workload
execs already constrained.

```elixir
alias Linx.Process, as: P
alias Linx.Cgroup

{:ok, c} = P.spawn(argv: ["/bin/sleep", "30"])
host_pid = receive do {:linx_process, :ready, p} -> p end
# => 41234

# Set up the cgroup while the workload is parked.
{:ok, cg} = Cgroup.create("/sys/fs/cgroup/myorg/web-42")
:ok = Cgroup.write(cg, "memory.max", 256 * 1024 * 1024)
:ok = Cgroup.add_process(cg, host_pid)

# Release the workload -- it execs constrained.
P.proceed(c)
# => :ok
```

`Linx.Process` itself knows nothing about cgroups; the checkpoint is
the integration surface. The same pattern works for `enter/2`-style
exec sessions: place the new host_pid into the parent container's
cgroup before `proceed/1`.

## Errors

Every failure surfaces as `%Linx.Cgroup.Error{}` — a struct, not a
raw `{:error, :enoent}` tuple. Pattern-match on `:errno` and
`:operation` for specific cases:

```elixir
case Linx.Cgroup.destroy(cg) do
  :ok ->
    :destroyed

  {:error, %Linx.Cgroup.Error{errno: :ebusy}} ->
    :still_has_processes

  {:error, %Linx.Cgroup.Error{errno: :enoent}} ->
    :already_gone
end
```

The `Exception` impl makes `raise` and `Exception.message/1` work:

```elixir
err = Linx.Cgroup.Error.from_posix(:eexist, "/sys/fs/cgroup/x", :create)
Exception.message(err)
# => "cgroup create failed on /sys/fs/cgroup/x: eexist (errno 17)"
```

The integer `:code` is looked up from a small POSIX table; an
unmapped errno (an exotic kernel-specific one) keeps `:code` at
`nil` but the atom is still pattern-matchable.

## Freezing and thawing

`freeze/1` suspends every process in the cgroup (and its
descendants) by writing `"1"` to `cgroup.freeze`. Processes stop
scheduling but stay resident — memory, open fds, network
connections, everything is preserved.

```elixir
{:ok, cg} = Linx.Cgroup.create("/sys/fs/cgroup/myorg/web-42")
:ok = Linx.Cgroup.freeze(cg)
{:ok, "1"} = Linx.Cgroup.read(cg, "cgroup.freeze")

:ok = Linx.Cgroup.thaw(cg)
{:ok, "0"} = Linx.Cgroup.read(cg, "cgroup.freeze")
```

Always available on cgroup v2 — no controller needs to be enabled,
so freeze/thaw works on every cgroup you create.

`thaw/1` is idempotent against an already-thawed cgroup.

## Resource limits

Each setter takes either a typed value (an integer for byte/count
limits, a `{quota, period}` tuple for CPU bandwidth) or the atom
`:max` to clear the limit. The kernel's `<file>` ↔ `<setter>`
mapping:

| Setter | Interface file | Accepted values |
|---|---|---|
| `set_memory_max/2` | `memory.max` | int (bytes), `:max` |
| `set_pids_max/2` | `pids.max` | int (count), `:max` |
| `set_cpu_max/2` | `cpu.max` | `{quota_us, period_us}`, `:max` |

```elixir
# 256 MiB memory limit
Linx.Cgroup.set_memory_max(cg, 256 * 1024 * 1024)
# => :ok
Linx.Cgroup.read(cg, "memory.max")
# => {:ok, "268435456"}

# Cap process count at 100
Linx.Cgroup.set_pids_max(cg, 100)
# => :ok

# Half a CPU: 50 ms of compute per 100 ms wall time
Linx.Cgroup.set_cpu_max(cg, {50_000, 100_000})
# => :ok
Linx.Cgroup.read(cg, "cpu.max")
# => {:ok, "50000 100000"}

# Clear any limit
Linx.Cgroup.set_memory_max(cg, :max)
# => :ok
Linx.Cgroup.read(cg, "memory.max")
# => {:ok, "max"}
```

The typed setters are thin wrappers over `write/3` with input
validation and the kernel's special-value rendering — `:max` →
`"max"`, `{q, p}` → `"<q> <p>"`. For interface files without a
typed setter (e.g. `memory.swap.max`, `io.max`, `cpu.weight`), use
`write/3` directly.

### Requires controller delegation

The memory, pids, and cpu controllers must be enabled in the
*parent* cgroup's `cgroup.subtree_control` for `memory.max` /
`pids.max` / `cpu.max` to even exist in the child. On a systemd
host this is the default at the root. When it isn't, the kernel
surfaces `ENOENT` on the write — the interface file isn't there.
`enable_controllers/2` is the helper that flips a
parent's subtree control on.

## End-to-end: limit a workload before it execs

Combining placement at the checkpoint and limits:

```elixir
alias Linx.Process, as: P
alias Linx.Cgroup

{:ok, c} = P.spawn(argv: ["/bin/sleep", "60"])
host_pid = receive do {:linx_process, :ready, p} -> p end

# Build the cgroup and apply limits while the workload is parked.
{:ok, cg} = Cgroup.create("/sys/fs/cgroup/myorg/web-42")
:ok = Cgroup.set_memory_max(cg, 256 * 1024 * 1024)
:ok = Cgroup.set_pids_max(cg, 100)
:ok = Cgroup.set_cpu_max(cg, {50_000, 100_000})
:ok = Cgroup.add_process(cg, host_pid)

# Release -- the workload execs with the limits already in place.
P.proceed(c)
# => :ok
```

If the workload tries to allocate past `memory.max`, the kernel
OOM-kills it inside the cgroup; `Linx.Process` then delivers the
`{:linx_process, :signaled, 9}` you'd expect.

## Reconciling limits declaratively

The setters above are imperative. To describe the limits you *want* and have
them converged — and re-converged after manual drift — use
`Linx.Cgroup.Reconcile`. It is "sysctl-with-hierarchy": a flat map from
interface-file name to desired value, against one already-existing cgroup.

```elixir
alias Linx.Cgroup.Reconcile

desired = %{
  "memory.max" => 256 * 1024 * 1024,   # bytes, or :max to clear
  "pids.max" => 100,                    # count, or :max
  "cpu.max" => {50_000, 100_000}        # {quota_us, period_us}, or :max
}

{:ok, r} = Reconcile.reconcile("/sys/fs/cgroup/myorg/web-42", desired)
r.converged?            #=> true once the kernel matches

# Thread last_applied into the next pass; idempotent.
{:ok, r2} = Reconcile.reconcile("/sys/fs/cgroup/myorg/web-42", desired, r.last_applied)
```

It reconciles **limits only** — it never creates or destroys the cgroup,
enables controllers, or moves processes. Those are lifecycle the consumer owns
(create the cgroup and delegate controllers first, as above); a write to a knob
whose controller isn't delegated simply lands in `r.failed`, best-effort, and
the next pass retries. Three-way `last_applied` ownership and
`revert_on_release:` work exactly as in `Linx.Sysctl.Reconcile`.

For continuous convergence, drive it from the opt-in `Linx.Reconcile` loop via
the cgroup `Source` adapter (the `scope` is the cgroup path):

```elixir
{Linx.Reconcile,
 source: Linx.Cgroup.Reconcile.Source,
 scope: "/sys/fs/cgroup/myorg/web-42",
 desired: %{"memory.max" => 256 * 1024 * 1024, "pids.max" => 100}}
```

cgroupfs has no change multicast, so the loop is timer-only — right for limit
knobs that only move when something writes them.

## Reading counters

`stats/1` returns a snapshot of a cgroup's resource counters as a
`Linx.Cgroup.Stats` struct:

```elixir
{:ok, s} = Linx.Cgroup.stats(cg)
# => {:ok, #Linx.Cgroup.Stats<cpu=12.3s mem=42MiB pids=3>}

s.cpu_usec
# => 12_345_678
s.memory_current
# => 44_040_192
s.pids_current
# => 3
```

The struct's `Inspect` impl renders compactly, omitting any field
that's `nil`. Pattern-match on individual fields for programmatic
access:

```elixir
case Linx.Cgroup.stats(cg) do
  {:ok, %Stats{memory_current: m}} when is_integer(m) and m > 256 * 1024 * 1024 ->
    :over_quarter_gig
  _ ->
    :under
end
```

### What's populated

Each field is `nil` if its source isn't available — either
because the controller isn't delegated to the parent (interface
file missing) or the kernel is too old to expose it.

| Field | Source | Notes |
|---|---|---|
| `cpu_usec` / `cpu_user_usec` / `cpu_system_usec` | `cpu.stat` | always present on v2 |
| `cpu_nr_throttled` / `cpu_throttled_usec` | `cpu.stat` | 0 unless `cpu.max` is set |
| `memory_current` | `memory.current` | needs memory controller |
| `memory_peak` | `memory.peak` | Linux ≥ 5.19 + memory controller |
| `pids_current` | `pids.current` | needs pids controller |

```elixir
# A cgroup without the pids controller delegated:
{:ok, s} = Linx.Cgroup.stats(cg)
s.pids_current
# => nil
```

The `Inspect` rendering reflects what's actually populated:

```elixir
%Linx.Cgroup.Stats{cpu_usec: 100, pids_current: 3}
#Linx.Cgroup.Stats<cpu=100µs pids=3>
```

`stats/1` only errors when the cgroup directory itself doesn't
exist or isn't readable — otherwise it returns `{:ok, %Stats{}}`
with every field best-effort filled:

```elixir
Linx.Cgroup.stats("/sys/fs/cgroup/nope")
# => {:error,
#  %Linx.Cgroup.Error{
#    path: "/sys/fs/cgroup/nope",
#    operation: :stats,
#    errno: :enoent,
#    code: 2
#  }}
```

## Enabling controllers (delegation)

The `memory`, `pids`, and `cpu` controllers (and the rest of cgroup
v2's catalog) only become available on a *child* cgroup when the
parent has them in its `cgroup.subtree_control`. `enable_controllers/2`
is the shorthand for setting that up.

```elixir
alias Linx.Cgroup
{:ok, parent} = Cgroup.create("/sys/fs/cgroup/myorg")
:ok = Cgroup.enable_controllers(parent, [:memory, :pids, :cpu])

{:ok, child} = Cgroup.create("/sys/fs/cgroup/myorg/web-42")
:ok = Cgroup.set_memory_max(child, 256 * 1024 * 1024)
```

Each controller is written individually as `"+<name>"` so a
rejected entry doesn't lose the ones that already landed:

```elixir
Cgroup.enable_controllers(parent, [:memory, :nosuch_controller])
# => {:partial,
#  [
#    {:nosuch_controller,
#     %Linx.Cgroup.Error{
#       operation: :write,
#       path: "/sys/fs/cgroup/myorg/cgroup.subtree_control",
#       errno: :einval,
#       code: 22
#     }}
#  ]}

# :memory still landed:
Cgroup.read(parent, "cgroup.subtree_control")
# => {:ok, "memory"}
```

The partial-failure shape — `{:partial, [{name, %Error{}}, …]}` —
is always returned as a *non-empty* list of the ones that failed.
The complement (succeeded) is implicit: anything in the input list
not named in `failures` was accepted. Pattern-match on it:

```elixir
case Cgroup.enable_controllers(parent, requested) do
  :ok ->
    :all_enabled

  {:partial, failures} ->
    Logger.warning("cgroup: failed to enable #{inspect(failures)}")
    :degraded
end
```

`enable_controllers(cg, [])` is a no-op returning `:ok` — useful
when the controllers list comes from configuration that might be
empty.

### What controllers are even available?

A controller can only be enabled in `cgroup.subtree_control` if
it's listed in `cgroup.controllers` (which inherits from
the parent's `subtree_control` recursively). Read it to find out:

```elixir
Cgroup.read(parent, "cgroup.controllers")
# => {:ok, "cpuset cpu io memory hugetlb pids rdma misc dmem"}
```

If a controller you want isn't there, the kernel doesn't have it
delegated this far down the tree — chase it up to the root.
