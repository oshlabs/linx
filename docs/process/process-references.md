# References

External sources `Linx.Process` draws on — kernel docs, prior art, and
the Erlang/Elixir conventions that shape the API.

A living doc — add to it as new sources inform a decision.

## Kernel side

The syscalls and namespace concepts `Linx.Process` exposes:

- [`clone(2)`](https://man7.org/linux/man-pages/man2/clone.2.html) — the
  syscall that creates the child; `CLONE_NEW*` flags pick which
  namespaces are fresh.
- [`setns(2)`](https://man7.org/linux/man-pages/man2/setns.2.html) — what
  `enter/2` uses to join an existing process's namespaces.
- [`execve(2)`](https://man7.org/linux/man-pages/man2/execve.2.html) —
  the child's final act after the checkpoint.
- [`unshare(2)`](https://man7.org/linux/man-pages/man2/unshare.2.html) —
  in-place namespace creation. Documented for context; not exposed (the
  BEAM can't safely unshare its own scheduler thread, and the Port helper
  has no use case `spawn/1` doesn't cover).
- [`namespaces(7)`](https://man7.org/linux/man-pages/man7/namespaces.7.html)
  — the overview page. The per-type pages document the specifics:
  [`pid_namespaces(7)`](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html),
  [`network_namespaces(7)`](https://man7.org/linux/man-pages/man7/network_namespaces.7.html),
  [`mount_namespaces(7)`](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html),
  [`user_namespaces(7)`](https://man7.org/linux/man-pages/man7/user_namespaces.7.html),
  [`uts_namespaces(7)`](https://man7.org/linux/man-pages/man7/uts_namespaces.7.html),
  [`ipc_namespaces(7)`](https://man7.org/linux/man-pages/man7/ipc_namespaces.7.html),
  [`cgroup_namespaces(7)`](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html),
  [`time_namespaces(7)`](https://man7.org/linux/man-pages/man7/time_namespaces.7.html).

## The Port boundary

The agent talks ETF to the BEAM over fd 3/4:

- [Erlang External Term Format
  spec](https://www.erlang.org/doc/apps/erts/erl_ext_dist.html) — the
  wire format on fd 3/4.
- [`erl_interface` / `ei` man
  page](https://www.erlang.org/doc/apps/erl_interface/ei.html) — the C
  library the agent uses to encode and decode ETF. Statically linked
  (`libei.a`); the path is resolved by the Mix compiler via
  `:code.root_dir/0`.
- [`Port.open/2` /
  `:erlang.open_port/2`](https://www.erlang.org/doc/apps/erts/erlang.html#open_port/2)
  — the `:nouse_stdio` + `{:packet, 4}` options that route control over
  fd 3/4 and leave fd 0/1/2 free for the workload.

## Prior art

- [tini](https://github.com/krallin/tini),
  [dumb-init](https://github.com/Yelp/dumb-init),
  [catatonit](https://github.com/openSUSE/catatonit) — established
  upstream `mini_init` binaries.
- [runc's `libcontainer`](https://github.com/opencontainers/runc) — the
  reference container-runtime implementation in Go; `nsenter`,
  `setns_init`, and the checkpoint relay design parallel `linx_process`.
- [conmon](https://github.com/containers/conmon) — the per-container
  agent in the podman/CRI-O world. The "clone parent = conmon" framing
  carries through here: the Port-spawned agent
  IS conmon, sized down to its essentials.

## Build

- The `:linx_process` Mix compiler
  (`lib/mix/tasks/compile.linx_process.ex`) — mirrors the
  `:netlink_nif` one but builds an executable, statically linking
  `libei` from the OTP install.
