# Linx.Tty examples

Hands-on examples of `Linx.Tty` — the terminal/PTY primitives.

These run unprivileged. Most need an `iex -S mix` session attached to
a real terminal (the BEAM's controlling tty). `mix test` covers the
error paths; the success paths live here because they mutate your
actual terminal state and are best demonstrated interactively.

## NIF identifier

```elixir
Linx.Tty.version()
```

Returns `"linx_tty"` — a cheap round-trip that confirms the native
library you built is the one actually loaded.

## Reading the terminal's window size

```elixir
{:ok, fd, saved} = Linx.Tty.open_controlling_raw()
Linx.Tty.window_size(fd)
:ok = Linx.Tty.restore_and_close(fd, saved)
```

`open_controlling_raw/0` returns `{:ok, fd, %Linx.Tty.Saved{...}}`;
`window_size/1` returns `{:ok, %Linx.Tty.WindowSize<132x42>}` (the
struct's `Inspect` renders `cols x rows`, so `132x42` means "132
columns, 42 rows").

`window_size/1` works on any tty fd, not just the controlling one.
On a non-tty fd it returns `{:error, {:ioctl, :enotty}}`; on an
invalid fd, `{:error, {:ioctl, :ebadf}}`.

## The save / restore contract

`open_controlling_raw/0` always pairs with `restore_and_close/2` — the
saved blob exists so the user's terminal can be returned to exactly the
state it was in before:

```elixir
defp with_raw_controlling(fun) do
  with {:ok, fd, saved} <- Linx.Tty.open_controlling_raw() do
    try do
      fun.(fd)
    after
      Linx.Tty.restore_and_close(fd, saved)
    end
  end
end
```

`try/after` runs the restore on *every* path — normal return, raised
exception, throw, exit signal — so the terminal can never be left
stuck in raw mode. `restore_and_close/2` is idempotent against an
already-closed fd, so wrapping callers that themselves run `after`
blocks is safe.

## When the BEAM has no controlling terminal

`open_controlling_raw/0` returns a typed error rather than crashing:

```elixir
Linx.Tty.open_controlling_raw()
```

Returns `{:error, {:open, :enxio}}` in some CI runners, or after
`setsid` detached the BEAM from its tty. Always pattern-match —
the atom is what makes `with` chains pleasant:

```elixir
with {:ok, fd, saved} <- Linx.Tty.open_controlling_raw(),
     {:ok, ws} <- Linx.Tty.window_size(fd) do
  IO.inspect(ws, label: "current terminal")
  Linx.Tty.restore_and_close(fd, saved)
end
```

## Setting a window size

`set_window_size/2` is the rare direct-on-an-fd path. Most callers
won't reach for it — the typical use case is propagating the *local*
tty's size onto a `Linx.Process` PTY workload, and that goes through
`Linx.Process.pty_set_winsize/2` so the agent performs the ioctl on
the master fd.

The function exists for the case where you do hold a tty fd directly:

```elixir
{:ok, fd, saved} = Linx.Tty.open_controlling_raw()
Linx.Tty.set_window_size(fd, %Linx.Tty.WindowSize{rows: 40, cols: 100, xpixel: 0, ypixel: 0})
Linx.Tty.window_size(fd)
Linx.Tty.restore_and_close(fd, saved)
```

Setting a tty's size sends `SIGWINCH` to the foreground process group,
so attached programs see the new size immediately.

## Attaching to a workload's PTY

`attach/2` is the composition that makes the whole subsystem
worthwhile. Pair it with `Linx.Process` running a workload under
`stdio: :pty` and the caller's terminal *becomes* the workload's
terminal until it exits.

Two modes pick how the caller's terminal is reached:

- `:controlling` — `open("/dev/tty", ...)` directly. Works wherever
  the BEAM's controlling tty is the user's terminal (local iex on
  a terminal emulator, Nerves HDMI / UART console). Has real
  event-driven `SIGWINCH` resize and the snappiest behaviour.
- `:group_leader` — pump bytes through `Process.group_leader/0` via
  Erlang's I/O protocol. Works over SSH, `:remsh`, and locally as
  a universal mode. Polls `:io.columns/0` + `:io.rows/0` for
  resize on a ~250 ms cadence (no SIGWINCH equivalent over SSH).

`:controlling` actively refuses over SSH — see below.
`:group_leader` works everywhere.

## `:controlling` mode — local terminal

Run from `iex -S mix` in a terminal emulator on your laptop, or from
iex on a Nerves device's HDMI / UART console.

```elixir
alias Linx.Process, as: P
alias Linx.Tty

{:ok, c} = P.spawn(argv: ["/bin/sh"], stdio: :pty)
P.proceed(c)
Tty.attach(:controlling, c)
```

Drops your iex into the workload's `/bin/sh`. Type whatever; `^D`
or `exit` ends the shell; attach restores your terminal and
returns `{:ok, {:exited, 0}}` (or a `:signaled` / `:error` shape
on abnormal termination).

Internals:

  1. `open_controlling_raw/0` grabs `/dev/tty` in raw mode and
     saves the original termios.
  2. The fd is wrapped as an Erlang port — keystrokes arrive as
     `{port, {:data, bytes}}` messages.
  3. The pump alternately forwards keystrokes to
     `Linx.Process.pty_write/2` and writes `{:linx_process, :pty_out,
     _}` events back to the port via `Port.command/2`.
  4. `try/after` runs `restore_and_close/2` unconditionally on the
     way out — terminal can't be left in raw mode even if the pump
     raises.

### Coexisting with iex's tty driver

When `attach(:controlling, _)` runs from `iex -S mix`, the BEAM
already has Erlang's `user_drv` / `prim_tty` driver reading
`/dev/tty` to support type-ahead at the iex prompt. Two readers
on the same kernel tty buffer alternate-steal each other's bytes
— without mitigation you'd lose roughly every other keystroke.

`attach/2` handles this internally: grabs the `prim_tty` state out
of `user_drv` via `:sys.get_state(:user_drv)`, calls
`:prim_tty.disable_reader/1` before the pump, and
`:prim_tty.enable_reader/1` in the `try/after` so iex's reader
resumes cleanly on return. No caller action required.

### What `:controlling` does over SSH / `:remsh`

`/dev/tty` resolves to the BEAM process's controlling terminal,
which has nothing to do with how *you* got into the iex session.

- **Local terminal emulator**: `/dev/tty` is your terminal. Attach
  works.
- **SSH iex on Nerves** (`ssh my-pi.local` → iex): `/dev/tty` is
  the BEAM's controlling tty — the HDMI / UART console — *not*
  your SSH session.
- **`:remsh`**: the local-iex side's GL points at a remote IO
  server; `/dev/tty` is wherever the remote BEAM was launched.

This closes the silent-attach-to-the-wrong-terminal trap:
`attach(:controlling, _)` returns `{:error, :no_local_tty}` in
the SSH (and likely `:remsh`) case. `Linx.Tty.format_error/1`
on the atom renders a human-readable hint that names
`attach(:group_leader, _)` as the alternative.

## `:group_leader` mode — universal

```elixir
alias Linx.Process, as: P
alias Linx.Tty

{:ok, c} =
  P.spawn(
    argv: ["/bin/sh"],
    namespaces: [:net, :mount, :pid, :uts, :ipc, :user],
    stdio: :pty
  )

P.proceed(c)
Tty.attach(:group_leader, c)
```

Your iex blocks; the SSH session *is* the workload's `/bin/sh` until
you `exit`.

### Observed end-to-end behaviour over SSH (nerves_ssh, rpi5)

What the iex session looks like in practice:

```
Linx.Tty.attach(:group_leader, c)
$ ls
releases   lib        erts-16.4
$ sleep 30
^C
$ exit
{:ok, {:exited, 130}}
```

  - `$ ` is busybox `sh`'s prompt. Characters echo as you type.
    Backspace erases them on screen.
  - `Ctrl-C` during `sleep 30` interrupts the running command and
    returns control to the prompt — attach does *not* exit.
  - `exit` ends `/bin/sh` and attach returns. Exit code `130` is
    `128 + SIGINT(2)` — `sh` reports the last command's status,
    and the last command (`sleep`) was killed by your earlier
    Ctrl-C. A clean session that ends with a successful command
    returns `{:ok, {:exited, 0}}`.

### Side effects of `:group_leader` mode, transient

For the duration of the attach call:

- The caller's `:io.setopts(:echo)` is flipped to `false`. This
  routes `:group`'s input requests through its `:dumb` state
  (byte-oriented; no line editor), and disables iex's own
  line-editing features (↑/↓ history, tab completion at the iex
  prompt) until attach returns. Restored unconditionally on the
  way out — even if the pump raises.
- The SSH driver's `:prim_tty` output mode is flipped from
  `:cooked` to `:raw` (via `:sys.replace_state/2` on the driver
  pid, directly mutating the `prim_tty` state's `options` map).
  Without this, `\b`, ANSI escapes, and other non-printable
  bytes from the workload get caret-rendered (`\b` → `^(`, etc.)
  by `prim_tty`'s cooked-mode line editor. Restored to `:cooked`
  on the way out.
- `trap_exit` is set on the iex shell process so the linked
  reader sub-process's exit doesn't take the pump down with it,
  and so `ssh_cli`'s race-case `^C` interrupt to the shell pid
  can be caught and translated to a `<<3>>` byte for the
  workload. Restored to the prior value on the way out.

### `Ctrl-C` handling

`ssh_cli` intercepts byte `\x03` from the SSH stream and turns it
into `exit(group, interrupt)` rather than passing the byte through.
The pump translates that back into a literal `<<3>>` byte to the
workload's PTY in both shapes it can arrive:

- As `{:error, :interrupted}` on the reader's pending
  `:io.get_chars` — the common case (reader is blocked on a
  read when `^C` arrives).
- As `{:EXIT, ^gl, :interrupt}` to the pump's mailbox — the
  rare race case where `^C` arrives in the tiny window between
  two reader round-trips.

The workload's PTY line discipline then turns `<<3>>` into SIGINT
for the foreground process group — the "Ctrl-C interrupts the
running command" behaviour users expect.

### Window resize: ~250 ms polling

`:group_leader` mode polls `:io.columns/0` and `:io.rows/0` on a
250 ms cadence (the `@winsize_poll_ms` module attribute in
`lib/linx/tty.ex`) and forwards the new geometry via
`Linx.Process.pty_set_winsize/2` when it changes. Dragging your
SSH client's terminal corner produces a clean redraw within a
quarter second — well under the threshold of perceptible lag for
interactive use. CPU cost is ~60 µs/s (~0.006 % of one core on
the rpi5) — invisible in any practical sense.

There is no SSH-side `SIGWINCH` equivalent surfaced through `:io`,
so polling is the practical answer. The trade-offs against an
event-driven `:erlang.trace/3` hook on `ssh_cli` are discussed in
the inline comment on `@winsize_poll_ms` in `lib/linx/tty.ex`.

## `:controlling` vs `:group_leader` — when to pick which

| Environment | Pick |
|---|---|
| Local terminal (`iex -S mix`) | `:controlling` |
| Nerves HDMI / UART console (a keyboard plugged into the device) | `:controlling` |
| SSH iex on Nerves (the headline use case) | `:group_leader` |
| `:remsh` to a remote BEAM | `:group_leader` |

In short: `:controlling` is the more-direct path that gives event-
driven SIGWINCH and bypasses one OTP-internals dance (no need to
flip `prim_tty` output mode); `:group_leader` is the universal
path that works regardless of how the user reached the iex shell.

You can always start with `:controlling`, watch for
`{:error, :no_local_tty}`, and fall back to `:group_leader`:

```elixir
case Linx.Tty.attach(:controlling, c) do
  {:error, :no_local_tty} -> Linx.Tty.attach(:group_leader, c)
  other -> other
end
```

## The owner requirement

The pump waits for `{:linx_process, :pty_out, _}` in the caller's
mailbox. The owner of those events defaults to the process that
called `P.spawn/1` (you can override with the `:owner` option).
**Call `attach/2` from the session's owner**, or the pump will block
forever waiting on events that go to another process.

In iex this is automatic — `spawn`, `proceed`, `attach` are all just
sequential calls from the iex evaluator. In an OTP application you
typically structure the calling process so it owns the session for
the duration of the attach.

## Composing with `Linx.Process` namespaces

Putting it all together — the headline `docker attach` /
`kubectl exec -it` workflow on Nerves over SSH:

```elixir
{:ok, c} =
  Linx.Process.spawn(
    argv: ["/bin/sh"],
    namespaces: [:net, :mount, :pid, :uts, :ipc, :user],
    stdio: :pty
  )

# Optional host-side setup before proceed/1:
# move a netlink interface into the new netns, write cgroup
# state, etc., while the child waits at the checkpoint.

Linx.Process.proceed(c)
Linx.Tty.attach(:group_leader, c)
# -> your iex prompt becomes the container's sh until you exit
```

That's `docker attach` / `kubectl exec -it`, end-to-end inside the
BEAM, from a few hundred lines of clean Elixir and a few thin NIFs.

## Window size: initial seed

`attach/2` seeds the workload's PTY window size from the caller's
terminal at entry, so a fresh `sh` inside the container sees the
right `$LINES`/`$COLUMNS` from the moment it starts — `vi` and
`less` open at the correct size, prompts wrap correctly.

- `:controlling` reads `TIOCGWINSZ` on the local tty fd directly.
- `:group_leader` calls `:io.columns/0` and `:io.rows/0` against
  the GL.

You can also set the workload's size manually at any point —
before `proceed/1` for "start the workload at this size", or
post-running to push an update:

```elixir
alias Linx.Process, as: P

{:ok, c} = P.spawn(argv: ["/bin/sh"], stdio: :pty)
P.pty_set_winsize(c, %{rows: 50, cols: 200, xpixel: 0, ypixel: 0})
P.proceed(c)
# sh starts thinking the terminal is 200x50.
```

## Live resize with `:controlling` mode (SIGWINCH)

While `attach(:controlling, _)` is running, dragging the corner of
your terminal emulator sends `SIGWINCH` to the BEAM. `attach/2`
registers a `Linx.Tty.SigwinchHandler` on OTP's `:erl_signal_server`
for the lifetime of the call, so each resize becomes a
`{:linx_tty, :sigwinch}` message in the pump's mailbox — the pump
re-reads `TIOCGWINSZ` on the local tty and forwards the new size
through `Linx.Process.pty_set_winsize/2`. Inside the container,
`sh` / `vi` / `top` then see their own (slave-side) `SIGWINCH` and
redraw at the new size.

The trick — and the reason this required OTP 28 — is that OTP 26
hadn't yet added `:sigwinch` to `:os.set_signal/2`. `prim_tty` got
SIGWINCH support partway through the OTP 27/28 series; we now ride
on the same plumbing iex itself uses for its line-editor geometry
refresh. No NIF needed.

`:gen_event` broadcasts each signal to every registered handler.
`prim_tty_sighandler` (iex's handler, which refreshes its line
editor's idea of width) stays armed throughout — we register
*alongside* it, not in place of it. Handler IDs (`{Module, ref}`)
keep multiple concurrent attaches independent: each one removes
only its own handler on teardown.
