# Linx.Mount references

The kernel docs and man pages this subsystem encodes. Cite specific
sections in the source when interpretation is non-obvious.

## Man pages

- **`mount(2)`** — the canonical reference for the mount syscall.
  Flag semantics, valid combinations, the `data` argument format.
- **`umount(2)`** / **`umount2(2)`** — the two-flavor unmount API;
  we wrap `umount2`. `MNT_FORCE` / `MNT_DETACH` / `MNT_EXPIRE` /
  `UMOUNT_NOFOLLOW` semantics.
- **`pivot_root(2)`** — the rootfs-swap syscall. Critically: lists
  the four constraints `new_root` and `put_old` must satisfy
  (mount points, no shared propagation, etc.).
- **`proc(5)`** — the mountinfo format. Section "/proc/[pid]/mountinfo"
  documents the 11-field shape plus the optional-fields section
  terminated by `-`.
- **`mount_namespaces(7)`** — how mounts behave across the `:mount`
  namespace. Propagation types, what "shared" / "slave" /
  "private" / "unbindable" mean.

## Kernel documentation

- **`Documentation/filesystems/sharedsubtree.rst`** — the canonical
  reference for mount propagation. Read before adding any of
  `:shared` / `:slave` / `:private` / `:unbindable`.
- **`Documentation/filesystems/proc.rst`** — supplementary detail
  on `/proc/<pid>/mountinfo` and `/proc/<pid>/mounts`.

## Adjacent man pages (background)

- **`namespaces(7)`** — overview. The relationship between
  `clone(CLONE_NEWNS)`, `setns(CLONE_NEWNS)`, and the mount
  namespace.
- **`nsenter(1)`** — the userspace tool that does, essentially,
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

- **The new mount API** — see man pages for `open_tree(2)`,
  `move_mount(2)`, `fsopen(2)`, `fsmount(2)`, `fsconfig(2)`,
  `mount_setattr(2)`. When a consumer needs this, a sibling
  `Linx.Mount.New` module would be the natural home.
