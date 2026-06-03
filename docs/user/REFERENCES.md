# Linx.User references

The kernel docs and man pages this subsystem encodes. Cite specific
sections in the source when interpretation is non-obvious.

## Man pages

- **[`user_namespaces(7)`](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)** — the canonical reference. Especially the
  sections "User and group ID mappings: uid_map and gid_map" and
  "Interaction of user namespaces and setgroups(2)". Source of
  truth for:
  - The `inside_id outside_id length` format.
  - The write-once semantics.
  - The setgroups-must-be-deny-first rule for unprivileged gid_map
    writes.
  - The capability requirements (CAP_SETUID / CAP_SETGID in the
    parent user ns) for "out-of-range" mappings.
- **[`namespaces(7)`](https://man7.org/linux/man-pages/man7/namespaces.7.html)** — overview; the relationship between
  `CLONE_NEWUSER` and the other namespaces.
- **[`clone(2)`](https://man7.org/linux/man-pages/man2/clone.2.html)** — `CLONE_NEWUSER` semantics, including the
  requirement that it must be the first namespace created when
  combined with others.
- **[`setgroups(2)`](https://man7.org/linux/man-pages/man2/setgroups.2.html)** — the syscall whose use is what
  `/proc/<pid>/setgroups` controls.
- **[`capabilities(7)`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** — background for understanding what "root
  inside a user ns" actually means.

## Kernel documentation

- **[`Documentation/admin-guide/namespaces/resource-control.rst`](https://docs.kernel.org/admin-guide/namespaces/resource-control.html)** —
  brief; namespace-related resource control.
- **`Documentation/userspace-api/...`** — various per-feature
  pieces; less directly relevant than the man pages above.

## In-repo cross-references

- `Linx.Process` — `Linx.Process` namespace machinery; the
  `:user` namespace and how it's selected at `spawn/1`.
- `lib/linx/mount/error.ex` — pattern for `Linx.User.Error`'s shape
  and `Exception` impl. (`Linx.Cgroup.Error` is equivalent.)

## Adjacent userspace tooling (for context, not implementation)

- **[`newuidmap(1)`](https://man7.org/linux/man-pages/man1/newuidmap.1.html) / [`newgidmap(1)`](https://man7.org/linux/man-pages/man1/newgidmap.1.html)** — setuid helpers distributed with
  the `shadow` / `uidmap` package; let unprivileged callers write
  multi-range maps using `/etc/subuid` and `/etc/subgid`. **Out of
  scope**; potential follow-up.
- **[`unshare(1)`](https://man7.org/linux/man-pages/man1/unshare.1.html)** — userspace tool that does essentially what
  `Linx.Process.spawn(namespaces: [:user, ...])` plus
  `Linx.User.setup_maps/2` will do together.
- **[`bwrap(1)`](https://manpages.debian.org/bwrap.1.en.html)** (bubblewrap) — well-known consumer of the same
  procfs surface this subsystem wraps. Reading its source is
  instructive for edge cases.
