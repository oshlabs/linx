# Linx.Cgroup examples

Hands-on examples of `Linx.Cgroup` — the cgroup v2 primitives.

All cgroup operations need root (or a delegated cgroup subtree).
Start with `./sudorun.sh iex -S mix` to demo interactively.

> 🚧 **Skeleton.** Most primitives are still in flight; sections fill
> in as milestones ship. See `PLAN.md` for the roadmap and
> `COVERAGE.md` for what's in / out.

## Detecting cgroup v2

```elixir
iex> Linx.Cgroup.supported?()
true
```

`supported?/0` returns true iff `/sys/fs/cgroup/cgroup.controllers`
is readable — the canonical "unified hierarchy is mounted" check.
Returns false on cgroup-v1-only hosts (Linx targets v2 only).

## (more examples will land with C1–C4)
