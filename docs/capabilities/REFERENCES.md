# Linx.Capabilities references

The kernel docs and man pages this subsystem encodes. Cite
specific sections in the source when interpretation is
non-obvious.

## Man pages

- **[`capabilities(7)`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** — the canonical reference. Especially:
  - "Thread capability sets" — the three thread sets (E, P, I)
    and their relationships.
  - "Capability bounding set" — semantics and the one-way
    drop rule.
  - "Ambient capabilities" — Linux 4.3+; the
    survives-execve-without-file-caps mechanism.
  - "Transformation of capabilities during execve()" — the
    full rule for how caps move across exec, including file-cap
    interaction.
- **[`capget(2)`](https://man7.org/linux/man-pages/man2/capget.2.html) / [`capset(2)`](https://man7.org/linux/man-pages/man2/capset.2.html)** — the per-thread cap manipulation
  syscalls.
- **[`prctl(2)`](https://man7.org/linux/man-pages/man2/prctl.2.html)** — specifically:
  - `PR_CAPBSET_READ` / `PR_CAPBSET_DROP` — bounding set
  - `PR_CAP_AMBIENT` (the `_IS_SET`, `_RAISE`, `_LOWER`,
    `_CLEAR_ALL` operations) — ambient set
- **[`proc(5)`](https://man7.org/linux/man-pages/man5/proc.5.html)** — `/proc/<pid>/status` documentation, in
  particular the `Cap*:` lines.
- **[`user_namespaces(7)`](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)** — covers how cap sets interact with
  user namespaces. Relevant for understanding "full caps in a
  fresh user ns" semantics that come up with `Linx.User`.

## Kernel documentation

- **`Documentation/admin-guide/...`** — various; less directly
  relevant than the man pages.
- **[`include/uapi/linux/capability.h`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/capability.h)** — the UAPI header with
  the `CAP_*` constants and the capability data structures used
  by `capget/capset`. The 41-entry constants table in
  `Linx.Capabilities.Constants` mirrors this.

## Adjacent userspace tooling (background, not implementation)

- **`libcap`** — the canonical userspace library for cap
  manipulation. The conceptual model
  (`cap_t` / `cap_set_flag` / `cap_set_proc`) shaped this
  subsystem's design but we don't link against it. Pure Elixir
  + the underlying syscalls are enough.
- **[`capsh(1)`](https://man7.org/linux/man-pages/man1/capsh.1.html)** — interactive shell for inspecting and
  modifying caps. Useful for cross-checking the read side.
- **[`setpriv(1)`](https://man7.org/linux/man-pages/man1/setpriv.1.html)** — `util-linux` tool that does
  drop-before-exec, much like what the agent commands
  implement.

## In-repo cross-references

- `Linx.Process` — the checkpoint protocol that the
  write side hooks into, adding three new commands to that
  protocol.
- `lib/linx/user/error.ex` — pattern for
  `Linx.Capabilities.Error`'s shape and Exception impl.
- `lib/linx/process.ex` `await_proceed` and the existing
  checkpoint-window command set (`:proceed`, `:abort`,
  `:pty_winsize`) — the write side adds to this.

## Out of scope — pointers for future work

- **File caps** — see [`setcap(8)`](https://man7.org/linux/man-pages/man8/setcap.8.html), [`getcap(8)`](https://man7.org/linux/man-pages/man8/getcap.8.html),
  [`cap_from_text(3)`](https://man7.org/linux/man-pages/man3/cap_from_text.3.html), and the `security.capability` xattr in
  [`xattr(7)`](https://man7.org/linux/man-pages/man7/xattr.7.html). A future `Linx.Capabilities.File` module would be
  the natural home.
- **No-new-privs** — `prctl(PR_SET_NO_NEW_PRIVS)`. Conceptually
  adjacent; probably belongs in `Linx.Process` rather than
  here, since it's about the spawn-time security posture more
  than caps per se.
