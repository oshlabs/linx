# Linx.Mount examples

Hands-on examples of `Linx.Mount` — the filesystem-mount primitives.

Read-side operations (`list/0`, `list/1`) work in a plain `iex -S
mix` session. Anything that *changes* the mount table — `mount/4`,
`umount/2`, `bind/3`, `remount/2`, `move/2`, `pivot_root/3` — needs
the calling thread to have `CAP_SYS_ADMIN` in the target user
namespace (root in the simple case). Start with `./sudorun.sh iex
-S mix`.

> 🚧 **Skeleton.** Primitives are still in flight; sections fill
> in as milestones ship. See `PLAN.md` for the roadmap and
> `COVERAGE.md` for what's in / out.

## (Will land with M0 — reading mountinfo)

## (Will land with M1 — basic mount + umount)

## (Will land with M2 — bind / remount / move)

## (Will land with M3 — mounting into another namespace via `:in`)

## (Will land with M4 — pivot_root)
