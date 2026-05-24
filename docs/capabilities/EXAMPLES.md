# Linx.Capabilities examples

Hands-on examples of `Linx.Capabilities` — Linux capability
primitives.

Read-only operations (`read/1`, `supported?/0`) work in a plain
`iex -S mix` session against any process's
`/proc/<pid>/status`. Write operations are agent-side at the
`Linx.Process` checkpoint — they need a parked session and
typically root (or capabilities in the right user namespace) to
actually apply.

> 🚧 **K0 shipped, K1/K2 still in flight.** The detection and
> constants surfaces are real; read and write verbs are stubs that
> return `{:error, :not_yet_implemented}`. See `PLAN.md` for the
> roadmap and `COVERAGE.md` for what's in / out.

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

## (Will land with K1 — read side)

## (Will land with K2 — write via agent)
