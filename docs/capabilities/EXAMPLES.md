# Linx.Capabilities examples

Hands-on examples of `Linx.Capabilities` — Linux capability
primitives.

Read-only operations (`read/1`, `supported?/0`) work in a plain
`iex -S mix` session against any process's
`/proc/<pid>/status`. Write operations are agent-side at the
`Linx.Process` checkpoint — they need a parked session and
typically root (or capabilities in the right user namespace) to
actually apply.

> 🚧 **Skeleton.** Primitives are still in flight; sections
> fill in as milestones ship. See `PLAN.md` for the roadmap
> and `COVERAGE.md` for what's in / out.

## Detecting capability support

```elixir
iex> Linx.Capabilities.supported?()
true
```

`supported?/0` returns true iff `/proc/self/status` contains a
`CapBnd:` line — true on any Linux ≥ 2.6.25, which is every
kernel Linx targets.

## (Will land with K1 — read side)

## (Will land with K2 — write via agent)
