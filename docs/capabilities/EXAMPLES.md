# Linx.Capabilities examples

Hands-on examples of `Linx.Capabilities` — Linux capability
primitives.

Read-only operations (`read/1`, `supported?/0`) work in a plain
`iex -S mix` session against any process's
`/proc/<pid>/status`. Write operations are agent-side at the
`Linx.Process` checkpoint — they need a parked session and
typically root (or capabilities in the right user namespace) to
actually apply.

> 🚧 **K0 + K1 shipped, K2 still in flight.** Detection, the
> constants table, and the read side (`read/1`) are real; the
> write verbs (`drop_bounding/2`, `set_thread_sets/2`,
> `set_ambient/2`) are stubs that return
> `{:error, :not_yet_implemented}`. See `PLAN.md` for the roadmap
> and `COVERAGE.md` for what's in / out.

## Detecting capability support

```elixir
iex> Linx.Capabilities.supported?()
true
```

`supported?/0` returns true iff `/proc/self/status` contains a
`CapBnd:` line — true on any Linux ≥ 2.6.25, which is every
kernel Linx targets.

## Inspecting the constants table

The 41-entry atom ↔ bit table lives in
`Linx.Capabilities.Constants` (internal — `@moduledoc false`, but
usable from `iex` for ad-hoc inspection):

```elixir
iex> Linx.Capabilities.Constants.all() |> MapSet.size()
41

iex> Linx.Capabilities.Constants.to_bit(:cap_net_admin)
12

iex> Linx.Capabilities.Constants.from_bit(40)
:cap_checkpoint_restore

iex> Linx.Capabilities.Constants.from_bit(50)
:unknown
```

`:unknown` is the forward-compat marker for bits past the table —
a future kernel could add a cap Linx doesn't know yet, and
`from_bits/1` will silently drop it from the read result rather
than crash.

## Building cap sets with MapSet

The canonical representation everywhere in this subsystem is a
`MapSet` of `:cap_*` atoms — so the standard `MapSet` API is the
toolbox:

```elixir
iex> all = Linx.Capabilities.Constants.all()
iex> keep = MapSet.new([:cap_net_bind_service, :cap_setuid])
iex> drop = MapSet.difference(all, keep)
iex> MapSet.size(drop)
39
```

That `drop` set is exactly what gets passed to `drop_bounding/2`
in K2.

## Reading a process's capability sets

`read/1` parses `/proc/<pid>/status` into a `%Linx.Capabilities.State{}`.
Accepts a pid integer or `:self`:

```elixir
iex> {:ok, state} = Linx.Capabilities.read(:self)
{:ok, #Linx.Capabilities.State<eff=0 prm=0 inh=0 bnd=41 amb=0>}

iex> state.bounding
#MapSet<[:cap_chown, :cap_dac_override, :cap_dac_read_search, ...]>

iex> MapSet.member?(state.bounding, :cap_net_admin)
true
```

Reading any live process:

```elixir
iex> {:ok, init_state} = Linx.Capabilities.read(1)
{:ok, #Linx.Capabilities.State<eff=41 prm=41 inh=0 bnd=41 amb=0>}
```

`/proc/<pid>/status` is world-readable on every Linux distro, so
no special privileges are needed for read access.

## Handling read errors

`read/1` returns a structured `%Linx.Capabilities.Error{}` on
failure — pattern-match on `:errno` to handle specific cases:

```elixir
iex> Linx.Capabilities.read(1_234_567_890)
{:error,
 %Linx.Capabilities.Error{
   path: "/proc/1234567890/status",
   operation: :read,
   errno: :enoent,
   code: 2
 }}
```

The common errnos:

| `:errno` | Meaning |
|---|---|
| `:enoent` | The target pid doesn't exist (gone, or never existed) |
| `:eacces` | No permission to read this process's status — rare for `status`, since it's almost always world-readable |
| `:bad_status` | The file existed but didn't contain the five `Cap*:` lines we expected; should never happen on a real Linux kernel |

## Forward compatibility

If you read a `/proc/<pid>/status` from a newer kernel that
reports capability bits past Linx's table (e.g. a `CAP_` constant
Linx hasn't catalogued yet), `read/1` silently drops those bits
from the returned `MapSet`s and emits a single `Logger.warning/1`
per read.

The returned `%State{}` is still valid for every cap Linx *does*
know about — consumers don't need to handle "partial" states
specially.

## Composing read with other Linx verbs

Common pattern — read caps right after `Linx.Process.spawn/1` (at
the checkpoint), to confirm the kernel-default cap posture before
proceeding:

```elixir
{:ok, c} = Linx.Process.spawn(argv: ["/bin/bash"], stdio: :pty)
{:ok, host_pid} = Linx.Process.host_pid(c)

{:ok, state} = Linx.Capabilities.read(host_pid)
IO.inspect(state, label: "child's caps at checkpoint")
# => #Linx.Capabilities.State<eff=0 prm=0 inh=0 bnd=41 amb=0>

# (K2 will land here: drop_bounding, set_thread_sets, set_ambient)

:ok = Linx.Process.proceed(c)
```

## (Will land with K2 — write via agent)
