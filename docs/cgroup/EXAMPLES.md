# Linx.Cgroup examples

Hands-on examples of `Linx.Cgroup` — the cgroup v2 primitives.

Read-only operations work in a plain `iex -S mix` session. Anything
that *changes* the cgroup hierarchy — `create/1`, `add_process/2`,
`write/3`, `destroy/1` — needs root. Start with `./sudorun.sh iex
-S mix`.

> 🚧 **Partial.** C1 (lifecycle, raw I/O, errors) and C2 (freeze /
> thaw + typed limits) ship now. Stats (C3) and controller
> delegation (C4) land in follow-ups. See `PLAN.md` for the
> roadmap.

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

## (more examples will land with C3–C4)
