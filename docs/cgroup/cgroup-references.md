# Linx.Cgroup references

The kernel docs and man pages this subsystem encodes. Cite specific
sections in the source when interpretation is non-obvious.

## Kernel documentation

- **[`Documentation/admin-guide/cgroup-v2.rst`](https://docs.kernel.org/admin-guide/cgroup-v2.html)** — the canonical cgroup
  v2 reference. Source of truth for interface-file semantics, special
  values (`"max"`, the `"<quota> <period>"` form of `cpu.max`),
  delegation rules, controller availability.
- **[`Documentation/admin-guide/cgroup-v1/`](https://docs.kernel.org/admin-guide/cgroup-v1/index.html)** — v1's docs, for context.
  We don't implement v1; reading this clarifies what v2 changed and
  why.

## Man pages

- **[`cgroups(7)`](https://man7.org/linux/man-pages/man7/cgroups.7.html)** — overview; the v1 vs. v2 differences in
  particular.
- **[`cgroup_namespaces(7)`](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)** — the `CLONE_NEWCGROUP` namespace, which
  is `Linx.Process`'s concern, not `Linx.Cgroup`'s. Useful when
  reasoning about which cgroup view a process sees inside a
  namespace.

## Other touched-but-not-implemented surface

- **[`mount(2)`](https://man7.org/linux/man-pages/man2/mount.2.html)** — the cgroup2 filesystem is typically mounted by the
  init system at `/sys/fs/cgroup`; we don't mount it ourselves.
  `Linx.Cgroup.supported?/0` just checks whether it's already there.
- **[`inotify(7)`](https://man7.org/linux/man-pages/man7/inotify.7.html)** / **[`fanotify(7)`](https://man7.org/linux/man-pages/man7/fanotify.7.html)** — would underpin a future
  event-monitoring API for files like `memory.events`. Deferred.

## In-repo cross-references

- `Linx.Process` — the checkpoint protocol that
  `Linx.Cgroup.add_process/2` composes with.
- `lib/linx/netlink/error.ex` — pattern for `Linx.Cgroup.Error`'s
  shape and `Exception` impl.
