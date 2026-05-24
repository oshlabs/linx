# Linx.User references

The kernel docs and man pages this subsystem encodes. Cite specific
sections in the source when interpretation is non-obvious.

## Man pages

- **`user_namespaces(7)`** — the canonical reference. Especially the
  sections "User and group ID mappings: uid_map and gid_map" and
  "Interaction of user namespaces and setgroups(2)". Source of
  truth for:
  - The `inside_id outside_id length` format.
  - The write-once semantics.
  - The setgroups-must-be-deny-first rule for unprivileged gid_map
    writes.
  - The capability requirements (CAP_SETUID / CAP_SETGID in the
    parent user ns) for "out-of-range" mappings.
- **`namespaces(7)`** — overview; the relationship between
  `CLONE_NEWUSER` and the other namespaces.
- **`clone(2)`** — `CLONE_NEWUSER` semantics, including the
  requirement that it must be the first namespace created when
  combined with others.
- **`setgroups(2)`** — the syscall whose use is what
  `/proc/<pid>/setgroups` controls.
- **`capabilities(7)`** — background for understanding what "root
  inside a user ns" actually means.

## Kernel documentation

- **`Documentation/admin-guide/namespaces/resource-control.rst`** —
  brief; namespace-related resource control.
- **`Documentation/userspace-api/...`** — various per-feature
  pieces; less directly relevant than the man pages above.

## In-repo cross-references

- `docs/process/PLAN.md` — `Linx.Process` namespace machinery; the
  `:user` namespace and how it's selected at `spawn/1`.
- `lib/linx/mount/error.ex` — pattern for `Linx.User.Error`'s shape
  and `Exception` impl. (`Linx.Cgroup.Error` is equivalent.)

## Adjacent userspace tooling (for context, not implementation)

- **`newuidmap(1)` / `newgidmap(1)`** — setuid helpers shipped with
  the `shadow` / `uidmap` package; let unprivileged callers write
  multi-range maps using `/etc/subuid` and `/etc/subgid`. **Out of
  scope for U0–U2**; potential follow-up.
- **`unshare(1)`** — userspace tool that does essentially what
  `Linx.Process.spawn(namespaces: [:user, ...])` plus
  `Linx.User.setup_maps/2` will do together.
- **`bwrap(1)`** (bubblewrap) — well-known consumer of the same
  procfs surface this subsystem wraps. Reading its source is
  instructive for edge cases.
