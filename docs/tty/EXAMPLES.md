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

## Not yet implemented

`attach/2` is still a stub returning `{:error, :not_yet_implemented}`.
T2 wires the byte pump; T3 adds window-size propagation across the
`Linx.Process` boundary. See `PLAN.md` for the roadmap.
