# Linx.User examples

Hands-on examples of `Linx.User` — the user-namespace configuration
primitives.

Read-only operations (`read_uid_map/1`, `read_gid_map/1`,
`supported?/0`) work in a plain `iex -S mix` session against any
process's `/proc/<pid>/...`. **Write** operations need either
`CAP_SETUID` / `CAP_SETGID` in the parent user ns (typically root)
*or* a single-line identity map that the kernel allows for
unprivileged callers.

> 🚧 **Skeleton.** Primitives are still in flight; sections fill
> in as milestones ship. See `PLAN.md` for the roadmap and
> `COVERAGE.md` for what's in / out.

## Detecting user-namespace support

```elixir
iex> Linx.User.supported?()
true
```

`supported?/0` returns true iff `/proc/self/uid_map` exists — true
on any kernel ≥ 3.8. Linx targets modern Linux; on a supported
system this should always be `true`.

## (Will land with U1 — write side)

## (Will land with U2 — read side + setup_maps/2)
