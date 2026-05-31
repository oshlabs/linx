# Linx.Cgroup examples

Hands-on examples of `Linx.Cgroup` — the cgroup v2 primitives.

Read-only operations work in a plain `iex -S mix` session. Anything
that *changes* the cgroup hierarchy — `create/1`, `add_process/2`,
`write/3`, `destroy/1` — needs root. Start with `./sudorun.sh iex
-S mix`.

> ✅ **All foundation milestones shipped (C0–C4).** Lifecycle, raw
> I/O, errors, freeze/thaw, typed limits, stats, and controller
> delegation are all in.

## Detecting cgroup v2

```elixir
iex> Linx.Cgroup.supported?()
true
```

`supported?/0` returns true iff `/sys/fs/cgroup/cgroup.controllers`
is readable — the canonical "unified hierarchy is mounted" check.
Returns false on cgroup-v1-only hosts (Linx targets v2 only).

## Lifecycle: create, destroy, add_process

```elixir
iex> alias Linx.Cgroup
iex> {:ok, cg} = Cgroup.create("/sys/fs/cgroup/myorg/web-42")
{:ok, "/sys/fs/cgroup/myorg/web-42"}

iex> :ok = Cgroup.add_process(cg, 41234)   # move a pid in
iex> :ok = Cgroup.destroy(cg)              # remove the cgroup
```

The path *is* the handle — `create/1` returns `{:ok, path}`, and
every other verb takes that path. There's no opaque struct or
GenServer wrapping a cgroup; cgroupfs already provides the identity.

`create/1` is **idempotent against `EEXIST`**:

```elixir
iex> Cgroup.create("/sys/fs/cgroup/myorg/web-42")
{:ok, "/sys/fs/cgroup/myorg/web-42"}
iex> Cgroup.create("/sys/fs/cgroup/myorg/web-42")
{:ok, "/sys/fs/cgroup/myorg/web-42"}
```

`destroy/1` only succeeds when the cgroup is **empty** — the kernel
returns `EBUSY` while any process is still in it:

```elixir
iex> Cgroup.add_process(cg, 41234)
:ok
iex> Cgroup.destroy(cg)
{:error,
 %Linx.Cgroup.Error{
   path: "/sys/fs/cgroup/myorg/web-42",
   operation: :destroy,
   errno: :ebusy,
   code: 16
 }}
```

Wait for the workload to exit (or move it out) before destroying.

## Raw read and write

For any cgroup interface file that doesn't have a typed setter yet,
fall back to `read/2` and `write/3`:

```elixir
iex> Cgroup.write(cg, "memory.max", 256 * 1024 * 1024)
:ok
iex> Cgroup.read(cg, "memory.max")
{:ok, "268435456"}

iex> Cgroup.write(cg, "memory.max", :max)         # special value
:ok
iex> Cgroup.read(cg, "memory.max")
{:ok, "max"}
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
iex> alias Linx.Process, as: P
iex> alias Linx.Cgroup

iex> {:ok, c} = P.spawn(argv: ["/bin/sleep", "30"])
iex> host_pid = receive do {:linx_process, :ready, p} -> p end
41234

# Set up the cgroup while the workload is parked.
iex> {:ok, cg} = Cgroup.create("/sys/fs/cgroup/myorg/web-42")
iex> :ok = Cgroup.write(cg, "memory.max", 256 * 1024 * 1024)
iex> :ok = Cgroup.add_process(cg, host_pid)

# Release the workload -- it execs constrained.
iex> P.proceed(c)
:ok
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
iex> case Linx.Cgroup.destroy(cg) do
...>   :ok ->
...>     :destroyed
...>
...>   {:error, %Linx.Cgroup.Error{errno: :ebusy}} ->
...>     :still_has_processes
...>
...>   {:error, %Linx.Cgroup.Error{errno: :enoent}} ->
...>     :already_gone
...> end
```

The `Exception` impl makes `raise` and `Exception.message/1` work:

```elixir
iex> err = Linx.Cgroup.Error.from_posix(:eexist, "/sys/fs/cgroup/x", :create)
iex> Exception.message(err)
"cgroup create failed on /sys/fs/cgroup/x: eexist (errno 17)"
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
iex> {:ok, cg} = Linx.Cgroup.create("/sys/fs/cgroup/myorg/web-42")
iex> :ok = Linx.Cgroup.freeze(cg)
iex> {:ok, "1"} = Linx.Cgroup.read(cg, "cgroup.freeze")

iex> :ok = Linx.Cgroup.thaw(cg)
iex> {:ok, "0"} = Linx.Cgroup.read(cg, "cgroup.freeze")
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
iex> Linx.Cgroup.set_memory_max(cg, 256 * 1024 * 1024)
:ok
iex> Linx.Cgroup.read(cg, "memory.max")
{:ok, "268435456"}

# Cap process count at 100
iex> Linx.Cgroup.set_pids_max(cg, 100)
:ok

# Half a CPU: 50 ms of compute per 100 ms wall time
iex> Linx.Cgroup.set_cpu_max(cg, {50_000, 100_000})
:ok
iex> Linx.Cgroup.read(cg, "cpu.max")
{:ok, "50000 100000"}

# Clear any limit
iex> Linx.Cgroup.set_memory_max(cg, :max)
:ok
iex> Linx.Cgroup.read(cg, "memory.max")
{:ok, "max"}
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
`enable_controllers/2` (landing in C4) is the helper that flips a
parent's subtree control on.

## End-to-end: limit a workload before it execs

Combining C1 (placement at the checkpoint) and C2 (limits):

```elixir
iex> alias Linx.Process, as: P
iex> alias Linx.Cgroup

iex> {:ok, c} = P.spawn(argv: ["/bin/sleep", "60"])
iex> host_pid = receive do {:linx_process, :ready, p} -> p end

# Build the cgroup and apply limits while the workload is parked.
iex> {:ok, cg} = Cgroup.create("/sys/fs/cgroup/myorg/web-42")
iex> :ok = Cgroup.set_memory_max(cg, 256 * 1024 * 1024)
iex> :ok = Cgroup.set_pids_max(cg, 100)
iex> :ok = Cgroup.set_cpu_max(cg, {50_000, 100_000})
iex> :ok = Cgroup.add_process(cg, host_pid)

# Release -- the workload execs with the limits already in place.
iex> P.proceed(c)
:ok
```

If the workload tries to allocate past `memory.max`, the kernel
OOM-kills it inside the cgroup; `Linx.Process` then delivers the
`{:linx_process, :signaled, 9}` you'd expect.

## Reading counters

`stats/1` returns a snapshot of a cgroup's resource counters as a
`Linx.Cgroup.Stats` struct:

```elixir
iex> {:ok, s} = Linx.Cgroup.stats(cg)
{:ok, #Linx.Cgroup.Stats<cpu=12.3s mem=42MiB pids=3>}

iex> s.cpu_usec
12_345_678
iex> s.memory_current
44_040_192
iex> s.pids_current
3
```

The struct's `Inspect` impl renders compactly, omitting any field
that's `nil`. Pattern-match on individual fields for programmatic
access:

```elixir
iex> case Linx.Cgroup.stats(cg) do
...>   {:ok, %Stats{memory_current: m}} when is_integer(m) and m > 256 * 1024 * 1024 ->
...>     :over_quarter_gig
...>   _ ->
...>     :under
...> end
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
iex> {:ok, s} = Linx.Cgroup.stats(cg)
iex> s.pids_current
nil
```

The `Inspect` rendering reflects what's actually populated:

```elixir
iex> %Linx.Cgroup.Stats{cpu_usec: 100, pids_current: 3}
#Linx.Cgroup.Stats<cpu=100µs pids=3>
```

`stats/1` only errors when the cgroup directory itself doesn't
exist or isn't readable — otherwise it returns `{:ok, %Stats{}}`
with every field best-effort filled:

```elixir
iex> Linx.Cgroup.stats("/sys/fs/cgroup/nope")
{:error,
 %Linx.Cgroup.Error{
   path: "/sys/fs/cgroup/nope",
   operation: :stats,
   errno: :enoent,
   code: 2
 }}
```

## Enabling controllers (delegation)

The `memory`, `pids`, and `cpu` controllers (and the rest of cgroup
v2's catalog) only become available on a *child* cgroup when the
parent has them in its `cgroup.subtree_control`. `enable_controllers/2`
is the shorthand for setting that up.

```elixir
iex> alias Linx.Cgroup
iex> {:ok, parent} = Cgroup.create("/sys/fs/cgroup/myorg")
iex> :ok = Cgroup.enable_controllers(parent, [:memory, :pids, :cpu])

iex> {:ok, child} = Cgroup.create("/sys/fs/cgroup/myorg/web-42")
iex> :ok = Cgroup.set_memory_max(child, 256 * 1024 * 1024)
```

Each controller is written individually as `"+<name>"` so a
rejected entry doesn't lose the ones that already landed:

```elixir
iex> Cgroup.enable_controllers(parent, [:memory, :nosuch_controller])
{:partial,
 [
   {:nosuch_controller,
    %Linx.Cgroup.Error{
      operation: :write,
      path: "/sys/fs/cgroup/myorg/cgroup.subtree_control",
      errno: :einval,
      code: 22
    }}
 ]}

# :memory still landed:
iex> Cgroup.read(parent, "cgroup.subtree_control")
{:ok, "memory"}
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
iex> Cgroup.read(parent, "cgroup.controllers")
{:ok, "cpuset cpu io memory hugetlb pids rdma misc dmem"}
```

If a controller you want isn't there, the kernel doesn't have it
delegated this far down the tree — chase it up to the root.
