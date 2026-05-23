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
| `attach/2` | ✅ | T2 — byte pump between local tty and `Linx.Process` PTY |
| SIGWINCH propagation in `attach/2` | ⬜ | T3 |

## Cross-subsystem (new verbs on `Linx.Process`)

| Feature | Status | Notes |
|---|---|---|
| `Linx.Process.pty_set_winsize/2` | ⬜ | T3 — agent gains `{:pty_winsize, _}` command |

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
