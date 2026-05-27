# Linx.Tty examples

Hands-on examples of `Linx.Tty` — the terminal/PTY primitives.

These run unprivileged. Most need an `iex -S mix` session attached to
a real terminal (the BEAM's controlling tty). `mix test` covers the
error paths; the success paths live here because they mutate your
actual terminal state and are best demonstrated interactively.

## Versions

```elixir
iex> Linx.Tty.version()
"linx_tty 0.1.0 (T1)"
```

The trailing `(Tn)` matches the shipped milestone — sanity that the
NIF you're talking to is the one you built.

## Reading the terminal's window size

```elixir
iex> {:ok, fd, saved} = Linx.Tty.open_controlling_raw()
{:ok, 14, #Linx.Tty.Saved<…>}

iex> Linx.Tty.window_size(fd)
{:ok, #Linx.Tty.WindowSize<132x42>}

iex> :ok = Linx.Tty.restore_and_close(fd, saved)
```

`window_size/1` works on any tty fd, not just the controlling one. On
a non-tty fd it returns `{:error, {:ioctl, :enotty}}`; on an invalid
fd, `{:error, {:ioctl, :ebadf}}`. The struct's `Inspect` renders
`cols x rows` so `132x42` means "132 columns, 42 rows."

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
# In some CI runners, or after `setsid` detached the BEAM from its tty
iex> Linx.Tty.open_controlling_raw()
{:error, {:open, :enxio}}
```

Always pattern-match. The atom is what makes `with` chains pleasant:

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
`Linx.Process.pty_set_winsize/2` (T3, not shipped yet) so the agent
performs the ioctl on the master fd.

The function exists for the case where you do hold a tty fd directly:

```elixir
iex> {:ok, fd, saved} = Linx.Tty.open_controlling_raw()
iex> Linx.Tty.set_window_size(fd, %Linx.Tty.WindowSize{rows: 40, cols: 100, xpixel: 0, ypixel: 0})
:ok
iex> Linx.Tty.window_size(fd)
{:ok, #Linx.Tty.WindowSize<100x40>}
iex> Linx.Tty.restore_and_close(fd, saved)
```

Setting a tty's size sends `SIGWINCH` to the foreground process group,
so attached programs see the new size immediately.

## Attaching to a workload's PTY

`attach/2` is the composition that makes the whole subsystem
worthwhile. Pair it with `Linx.Process` running a workload under
`stdio: :pty` and the caller's controlling terminal *becomes* the
workload's terminal until it exits.

```elixir
# In iex -- this requires a real controlling tty under the BEAM.
iex> alias Linx.Process, as: P
iex> alias Linx.Tty

iex> {:ok, c} = P.spawn(argv: ["/bin/bash"], stdio: :pty)
iex> receive do {:linx_process, :ready, _} -> :ok end
iex> P.proceed(c)
iex> receive do {:linx_process, :running} -> :ok end

# iex blocks here. Your terminal IS the bash inside the cloned
# child. Type whatever; ^D or `exit` ends bash; attach restores your
# terminal and returns the exit event.
iex> Tty.attach(:controlling, c)
{:ok, {:exited, 0}}
```

The mechanics:

  1. `attach/2` calls `open_controlling_raw/0` to grab `/dev/tty` in
     raw mode, saving the original termios.
  2. The fd is wrapped as an Erlang port — keystrokes arrive as
     `{port, {:data, bytes}}` messages.
  3. The pump alternately reads from the port (forwarding to
     `Linx.Process.pty_write/2`) and reads `{:linx_process, :pty_out, _}`
     events (writing them back to the port via `Port.command/2`).
  4. When the session terminates (`:exited` / `:signaled` / pre-exec
     `:error`), the pump returns. A `try/after` runs
     `restore_and_close/2` unconditionally — so your terminal can
     never be left in raw mode, even if the pump raises mid-flight.

### Coexisting with iex's tty driver

When `attach/2` runs from `iex -S mix`, the BEAM already has
Erlang's `user_drv` / `prim_tty` driver reading `/dev/tty` to
support type-ahead at the iex prompt. Two readers on the same
kernel tty buffer alternate-steal each other's bytes — without
mitigation you'd lose roughly every other keystroke.

`attach/2` handles this internally: it grabs the `prim_tty` state
out of `user_drv` (via `:sys.get_state(:user_drv)`) and calls
`:prim_tty.disable_reader/1` before the pump, then
`:prim_tty.enable_reader/1` in the `try/after` so iex's reader
resumes cleanly on return. No caller action required — type into
the attached shell as you would any normal terminal.

When the BEAM is not running under `user_drv` (escripts,
non-shell apps, ssh-shell driver variants), the suspend is a
no-op — there's no competing reader to worry about.

### What `attach(:controlling, _)` does over SSH / `:remsh`

`:controlling` targets the BEAM's *kernel-level* controlling
terminal — `open("/dev/tty", ...)`. That fd is whatever tty the
BEAM was launched against; it has nothing to do with how *you*
got into the iex session. Two important corollaries:

- **Local terminal emulator** (`iex -S mix` in your laptop's
  terminal): `/dev/tty` is your terminal. Attach works as
  expected. This is the happy path the rest of this document
  assumes.
- **SSH iex on Nerves** (`ssh my-pi.local` → iex): `/dev/tty` is
  the **BEAM's controlling tty**, which on Nerves is the HDMI /
  UART console — *not* your SSH session. Erlang's SSH daemon
  (`ssh_cli`) is a pure I/O-protocol bridge with no kernel tty
  behind it, so attach can't reach your remote terminal via
  `:controlling`. The attempt opens the HDMI fd, runs the pump
  against *it*, and your SSH iex blocks waiting for a workload
  exit event the keyboard at the SSH end can never produce.

T6 (in progress, branch `tty-group-leader-attach`) closes both
loose ends:

1. A precondition guard so `attach(:controlling, _)` over SSH
   returns `{:error, :no_local_tty}` instead of silently grabbing
   the HDMI console.
2. A new mode `attach(:group_leader, session)` that pumps via
   Erlang's I/O protocol through the caller's group leader — works
   over SSH, `:remsh`, and anywhere the user's terminal is an
   Erlang process rather than a kernel tty fd.

Until T6 lands, the workarounds for attaching from a Nerves device
are: plug a monitor + USB keyboard into the Pi and use the HDMI
console (which *is* the BEAM's controlling tty), or wait for T6.1.
See `docs/tty/PLAN.md` § T6 for the design.

### The owner requirement

The pump waits for `{:linx_process, :pty_out, _}` in the caller's
mailbox. The owner of those events defaults to the process that
called `P.spawn/1` (you can override with the `:owner` option).
**Call `attach/2` from the session's owner**, or the pump will block
forever waiting on events that go to another process.

In iex this is automatic — `spawn`, `proceed`, `attach` are all just
sequential calls from the iex evaluator. In an OTP application you
typically structure the calling process so it owns the session for
the duration of the attach.

### Composing with `Linx.Process` namespaces

Putting it all together — the motivating use case from
`PLAN.md`:

```elixir
{:ok, c} =
  Linx.Process.spawn(
    argv: ["/bin/bash"],
    namespaces: [:net, :mount, :pid, :uts, :ipc, :user],
    stdio: :pty
  )

# Host-side setup: move a netlink interface into the new netns,
# write cgroup state, etc., while the child waits at the checkpoint.

Linx.Process.proceed(c)
Linx.Tty.attach(:controlling, c)
# -> your iex prompt becomes the container's bash until you exit
```

That's `docker attach` / `kubectl exec -it`, end-to-end inside the
BEAM, from a few hundred lines of clean Elixir and a few thin NIFs.

## Window size: initial seed

`attach/2` reads the local terminal's `TIOCGWINSZ` at entry and forwards
it to the workload's PTY via `Linx.Process.pty_set_winsize/2`. So a
fresh `bash` inside the container sees the right `$LINES`/`$COLUMNS`
from the moment it starts — `vim` and `less` open at the correct
size, prompts wrap correctly.

```elixir
# Manually inspect what attach/2 will seed:
iex> {:ok, fd, saved} = Linx.Tty.open_controlling_raw()
iex> Linx.Tty.window_size(fd)
{:ok, #Linx.Tty.WindowSize<132x42>}
iex> Linx.Tty.restore_and_close(fd, saved)
```

You can also set the workload's size manually at any point — before
`proceed/1` for "start the workload at this size", or post-running
(once the session is `:running`) to push an update:

```elixir
iex> alias Linx.Process, as: P
iex> {:ok, c} = P.spawn(argv: ["/bin/bash"], stdio: :pty)
iex> receive do {:linx_process, :ready, _} -> :ok end
iex> P.pty_set_winsize(c, %{rows: 50, cols: 200, xpixel: 0, ypixel: 0})
:ok
iex> P.proceed(c)
# bash starts thinking the terminal is 200x50.
```

## Live resize (`SIGWINCH`)

While `attach/2` is running, dragging the corner of your terminal
emulator sends `SIGWINCH` to the BEAM. `attach/2` registers a
`Linx.Tty.SigwinchHandler` on OTP's `:erl_signal_server` for the
lifetime of the call, so each resize becomes a `{:linx_tty, :sigwinch}`
message in the pump's mailbox — the pump re-reads `TIOCGWINSZ` on the
local tty and forwards the new size through
`Linx.Process.pty_set_winsize/2`. Inside the container, `bash` / `vim`
/ `top` then see their own (slave-side) `SIGWINCH` and redraw at the
new size.

### Manual acceptance test

```elixir
# In iex -S mix
iex> alias Linx.Process, as: P
iex> alias Linx.Tty
iex> {:ok, c} = P.spawn(argv: ["/bin/bash"], stdio: :pty)
iex> receive do {:linx_process, :ready, _} -> :ok end
iex> P.proceed(c)
iex> receive do {:linx_process, :running} -> :ok end
iex> Tty.attach(:controlling, c)
# Inside the attached bash:
#   $ vim
#   <drag the terminal emulator's corner while vim is open>
#   <vim redraws cleanly at the new dimensions>
#   :q
#   $ exit
{:ok, {:exited, 0}}
```

The trick — and the reason this required OTP 28 — is that OTP 26
hadn't yet added `:sigwinch` to `:os.set_signal/2`. `prim_tty` got
SIGWINCH support partway through the OTP 27/28 series; we now ride on
the same plumbing iex itself uses for its line-editor geometry
refresh. No NIF needed.

### Why this composes safely with iex

`:gen_event` broadcasts each signal to every registered handler.
`prim_tty_sighandler` (iex's handler, which refreshes its line
editor's idea of width) stays armed throughout — we register
*alongside* it, not in place of it. Handler IDs (`{Module, ref}`)
keep multiple concurrent attaches independent: each one removes only
its own handler on teardown.
