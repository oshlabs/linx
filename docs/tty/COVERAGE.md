# Linx.Tty coverage

What of the kernel's terminal/PTY surface `Linx.Tty` exposes today,
what is planned, and what is deferred.

A living doc — update as primitives ship. Status legend:

| | |
|---|---|
| ✅ | done — shipped and tested |
| 🟡 | partial — some sub-features in, others not |
| ⬜ | todo — not yet |
| ⏳ | architected-for — design accommodates it, no code yet |

## Primitives

| Feature | Status | Notes |
|---|---|---|
| `version/0` | ✅ | T0 — NIF round-trip marker |
| `open_controlling_raw/0` | ✅ | T1 — opens `/dev/tty`, saves termios, `cfmakeraw` |
| `restore_and_close/2` | ✅ | T1 — idempotent against already-closed |
| `window_size/1` (`TIOCGWINSZ`) | ✅ | T1 |
| `set_window_size/2` (`TIOCSWINSZ`) | ✅ | T1 |
| `attach(:controlling, _)` | ✅ | T2 — byte pump; T4 — brackets pump with `:prim_tty.disable_reader/1` so iex's tty driver stops competing |
| Initial winsize seed in `attach(:controlling, _)` | ✅ | T3 |
| SIGWINCH-driven runtime propagation | ✅ | T5 — `Linx.Tty.SigwinchHandler` gen_event on `:erl_signal_server`; OTP 28 made the NIF unnecessary |
| `:no_local_tty` precondition guard on `:controlling` | ✅ | T6.0 — `Linx.Tty.Env.classify_caller_terminal/0` sniffs the GL's `"$ancestors"` for `:ssh_sup` / `:sshd_sup`; `attach(:controlling, _)` refuses with `{:error, :no_local_tty}` over SSH. `Linx.Tty.format_error/1` describes the atom. |
| `attach(:group_leader, _)` | ✅ | T6.1 — pumps via Erlang I/O protocol through `Process.group_leader/0`; works over SSH, `:remsh`, and locally (universal mode). `:io.setopts(echo: false)` routes input through `:group`'s `:dumb` state for byte-oriented delivery |
| Initial winsize seed in `attach(:group_leader, _)` | ✅ | T6.1 — sourced from `:io.columns/0` / `:io.rows/0` |
| Polling resize in `attach(:group_leader, _)` | ✅ | T6.1 — default 1s poll, memoised so no work when geometry is stable |
| Driver `:prim_tty` raw-output bracket | ✅ | T6.1.1 — `:sys.replace_state/2` on `ssh_cli` (or `user_drv` locally) flips `:prim_tty`'s `options.output` map field to `:raw` (direct put_elem, not `:prim_tty.reinit/2` which crashes on SSH's `tty=undefined` state). Workload bytes (`\b`, ANSI, etc.) pass through verbatim instead of being caret-rendered |
| Ctrl-C forwarding to workload | ✅ | T6.1.2 — `ssh_cli` swallows `\x03` and turns it into `exit(group, interrupt)`; the reader's `{:error, :interrupted}` and the pump's `{:EXIT, ^gl, :interrupt}` paths both translate back to a literal `<<3>>` byte to the workload's PTY, which the line discipline turns into SIGINT |

## Cross-subsystem (new verbs on `Linx.Process`)

| Feature | Status | Notes |
|---|---|---|
| `Linx.Process.pty_set_winsize/2` | ✅ | T3 — agent gains `{:pty_winsize, _}` (both pre-proceed and post-running) |

## Value types

| Module | Status | Notes |
|---|---|---|
| `Linx.Tty.Saved` | ✅ | T0 — opaque termios blob wrapper |
| `Linx.Tty.WindowSize` | ✅ | T0 — `struct winsize` mirror |

## Error reporting

| Mechanism | Status | Notes |
|---|---|---|
| errno → POSIX atom (`:enxio`, `:enotty`, …) | ✅ | T1 — C-side mapping |
| Unknown errno falls back to integer | ✅ | T1 |

## Deferred — not in `Linx.Tty` itself

See `PLAN.md`'s "Deferred — architected-for, not built here" for the
full list with reasoning:

- Detach key combinations (`Ctrl-P Ctrl-Q`-style escape sequences in
  the attach loop).
- Cooked / cbreak / per-attribute termios manipulation beyond raw +
  restore.
- Standalone `Linx.Tty.openpt/0` (PTY pair creation from BEAM —
  `Linx.Process` already does this for `stdio: :pty`).
- Job control / `tcsetpgrp(3)`.
- terminfo / `tput`-style escape-sequence database.
