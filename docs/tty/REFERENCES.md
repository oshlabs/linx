# References

External sources `Linx.Tty` draws on — kernel docs, prior-art tooling,
and the Erlang/Elixir conventions that shape the API.

A living doc — add to it as new sources inform a decision.

## Kernel side

The syscalls and concepts `Linx.Tty` exposes:

- [`termios(3)`](https://man7.org/linux/man-pages/man3/termios.3.html) —
  the structure and functions (`tcgetattr`, `tcsetattr`, `cfmakeraw`,
  …) for terminal attribute control.
- [`tty(4)`](https://man7.org/linux/man-pages/man4/tty.4.html) — the
  controlling terminal abstraction; `/dev/tty` semantics.
- [`tty_ioctl(4)`](https://man7.org/linux/man-pages/man4/tty_ioctl.4.html)
  — the `TIOC*` ioctls (`TIOCGWINSZ`, `TIOCSWINSZ`, `TIOCSCTTY`, …)
  exposed for terminal control.
- [`pty(7)`](https://man7.org/linux/man-pages/man7/pty.7.html) —
  pseudoterminal overview. Pair to `Linx.Process`'s `stdio: :pty`.
- [`ptmx(4)`](https://man7.org/linux/man-pages/man4/ptmx.4.html) —
  `/dev/ptmx` and the multiplexor PTY creation path. (Used by
  `Linx.Process` in T0 era; a future standalone `Linx.Tty.openpt/0`
  would land here.)

## Prior art

- [conmon](https://github.com/containers/conmon) — the per-container
  agent in podman/CRI-O. Its PTY relay (master fd in the agent,
  byte-pumping over a control channel) is the same architectural shape
  `Linx.Process` + `Linx.Tty` compose into.
- [Go's `creack/pty`](https://github.com/creack/pty) — a widely used
  PTY library; useful reference for the Linux PTY allocation
  sequence and the `TIOCSCTTY` / `setsid` ordering.
- [Rust's `nix::pty`](https://docs.rs/nix/latest/nix/pty/index.html) —
  another reference implementation; useful for cross-checking
  termios constant interpretations.
- [Python's `pty` module](https://docs.python.org/3/library/pty.html)
  and the venerable `tty` module — minimal Python wrappers around
  the same syscalls; instructive for what the *minimum* useful PTY
  surface looks like.
- `docker attach` / `kubectl exec -it` — the user-experience target.
  Their implementations are the canonical "TTY-aware byte relay";
  `Linx.Tty.attach/2` (T2) follows the same shape: open local raw,
  pump bytes both ways, restore on exit.

## NIF mechanics

- [erl_nif manual](https://www.erlang.org/doc/man/erl_nif.html) — the
  C API for ERL_NIF_INIT, term construction (`enif_make_atom`,
  `enif_alloc_binary`, …), and the integer-conversion helpers.

## Erlang TTY (the other one)

- [Erlang's `tty` driver in ERTS](https://github.com/erlang/otp/tree/master/erts/emulator/drivers/unix)
  — what the BEAM's group-leader process uses behind the scenes for
  shell IO. `Linx.Tty` deliberately bypasses this by opening
  `/dev/tty` directly; the reference is included so future readers
  understand the layering choice.
- [`:prim_tty`](https://www.erlang.org/doc/man/prim_tty.html) — the
  modern Erlang TTY primitives. Different abstraction, different
  goals (Erlang's interactive shell, not `docker attach`); included
  for completeness.

## I/O protocol and group leaders (T6 / `attach(:group_leader, _)`)

The SSH-compatible attach mode pumps bytes through the caller's
group leader instead of `/dev/tty`. The references that shape that
design:

- [The Erlang I/O Protocol](https://www.erlang.org/doc/apps/stdlib/io_protocol.html)
  — `{io_request, From, ReplyAs, Request}` /
  `{io_reply, ReplyAs, Reply}`, the get_chars / put_chars / setopts
  request shapes, and the contract every group leader implements.
- [`:io`](https://www.erlang.org/doc/man/io.html) — public-API
  wrappers (`get_chars/3`, `setopts/2`, `columns/1`, `rows/1`)
  the pump uses.
- [Erlang `ssh` user's guide — `ssh_cli`](https://www.erlang.org/doc/man/ssh_cli.html)
  — the IO server / shell channel handler that fronts an SSH iex
  session. The class of group leader we have to interoperate with
  when an iex session is reached over SSH.
- [`nerves_ssh`](https://github.com/nerves-project/nerves_ssh) —
  the Nerves wrapper around `:ssh.daemon` that ships in the
  default Nerves config. Composes `ssh_subsystem_fwup` (firmware
  updates), an iex subsystem (the shell we attach into), and
  authorized-key handling. Useful for understanding what process
  hierarchy a Nerves SSH iex actually lives in.

## Why `/dev/tty` and not fd 0

The reasoning lives in `docs/tty/PLAN.md` under "Guiding principles."
The short version: BEAM's stdio is mediated by an Erlang group leader;
going through fd 0 would race the group leader and depend on its
buffering behaviour. `/dev/tty` is the *controlling terminal*
abstraction — every C program that wants direct terminal access (`vi`,
`less`, `ssh`, `passwd`, …) opens it for exactly this reason.

The trade-off shows up when `/dev/tty` is **not** the user's terminal —
SSH, `:remsh`, embedded device consoles where the BEAM is wired to
a serial port the user can't reach. T6's `attach(:group_leader, _)`
is the deliberate "fall back to the group leader anyway" mode for
those environments, with the corresponding loss of raw-mode fidelity
(see PLAN.md § T6).
