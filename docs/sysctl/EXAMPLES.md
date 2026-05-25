# Linx.Sysctl examples

Hands-on examples of `Linx.Sysctl` — the kernel-tunable-parameter
surface, the `/proc/sys/` knobs that `sysctl(8)` reads and writes.

Most read operations work in a plain `iex -S mix` session against
the host's namespace. Writes to global knobs (`vm.*`, `fs.*`, most
`kernel.*`) need root. Per-namespace knobs (`net.*`,
`kernel.hostname`, IPC limits) may be writable as an unprivileged
user *inside* their own namespace — e.g. as `root` inside a
container's user ns — but writes from the BEAM to the host's
namespace still need real root.

> 🚧 **Skeleton.** Primitives are still in flight; sections fill
> in as milestones ship. See `PLAN.md` for the roadmap and
> `COVERAGE.md` for what's in / out.

## Detecting sysctl support

```elixir
iex> Linx.Sysctl.supported?()
true
```

`supported?/0` returns true iff `/proc/sys/kernel/ostype` exists.
The knob predates namespaces; on any Linux system with procfs
mounted, this is always `true`. Returning `false` would mean
procfs isn't mounted at all (which would also break most of the
rest of Linx).

## (Will land with S1 — host read/write + Error)

## (Will land with S2 — subtree walking + Entry)

## (Will land with S3 — cross-namespace via `:in`)
