# Linx.Mount references

The kernel docs and man pages this subsystem encodes. Cite specific
sections in the source when interpretation is non-obvious.

## Man pages

- **[`mount(2)`](https://man7.org/linux/man-pages/man2/mount.2.html)** — the canonical reference for the mount syscall.
  Flag semantics, valid combinations, the `data` argument format.
- **[`umount(2)`](https://man7.org/linux/man-pages/man2/umount.2.html) / [`umount2(2)`](https://man7.org/linux/man-pages/man2/umount2.2.html)** — the two-flavor unmount API;
  we wrap `umount2`. `MNT_FORCE` / `MNT_DETACH` / `MNT_EXPIRE` /
  `UMOUNT_NOFOLLOW` semantics.
- **[`pivot_root(2)`](https://man7.org/linux/man-pages/man2/pivot_root.2.html)** — the rootfs-swap syscall. Critically: lists
  the four constraints `new_root` and `put_old` must satisfy
  (mount points, no shared propagation, etc.).
- **[`proc(5)`](https://man7.org/linux/man-pages/man5/proc.5.html)** — the mountinfo format. Section "/proc/[pid]/mountinfo"
  documents the 11-field shape plus the optional-fields section
  terminated by `-`.
- **[`mount_namespaces(7)`](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html)** — how mounts behave across the `:mount`
  namespace. Propagation types, what "shared" / "slave" /
  "private" / "unbindable" mean.

## Kernel documentation

- **[`Documentation/filesystems/sharedsubtree.rst`](https://docs.kernel.org/filesystems/sharedsubtree.html)** — the canonical
  reference for mount propagation. Read before adding any of
  `:shared` / `:slave` / `:private` / `:unbindable`.
- **[`Documentation/filesystems/proc.rst`](https://docs.kernel.org/filesystems/proc.html)** — supplementary detail
  on `/proc/<pid>/mountinfo` and `/proc/<pid>/mounts`.

## Adjacent man pages (background)

- **[`namespaces(7)`](https://man7.org/linux/man-pages/man7/namespaces.7.html)** — overview. The relationship between
  `clone(CLONE_NEWNS)`, `setns(CLONE_NEWNS)`, and the mount
  namespace.
- **[`nsenter(1)`](https://man7.org/linux/man-pages/man1/nsenter.1.html)** — the userspace tool that does, essentially,
  what our `:in` option does. The semantics our cross-namespace
  mounts match.

## In-repo cross-references

- `Linx.Process` — `Linx.Process` namespace machinery; the
  `:mount` namespace and where it comes from.
- `lib/linx/netlink/socket/native.ex` — the netlink-in-netns NIF
  whose throwaway-thread setns pattern `Linx.Mount.Native` reuses.
- `lib/linx/cgroup/error.ex` — pattern for `Linx.Mount.Error`'s
  shape and `Exception` impl.

## Out of scope — pointers for future work

- **The new mount API** — see man pages for [`open_tree(2)`](https://man7.org/linux/man-pages/man2/open_tree.2.html),
  [`move_mount(2)`](https://man7.org/linux/man-pages/man2/move_mount.2.html), [`fsopen(2)`](https://man7.org/linux/man-pages/man2/fsopen.2.html), [`fsmount(2)`](https://man7.org/linux/man-pages/man2/fsmount.2.html), [`fsconfig(2)`](https://man7.org/linux/man-pages/man2/fsconfig.2.html),
  [`mount_setattr(2)`](https://man7.org/linux/man-pages/man2/mount_setattr.2.html). When a consumer needs this, a sibling
  `Linx.Mount.New` module would be the natural home.
