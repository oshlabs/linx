defmodule Linx.Tty do
  @moduledoc """
  Linux terminal / PTY primitives — `/dev/tty` access, `termios(3)`
  save and restore, tty `ioctl(2)` (window size), and the byte-pumping
  `attach/2` that composes with `Linx.Process`'s `stdio: :pty` to give
  the BEAM a `docker attach` experience.

  ## Why a separate subsystem

  Terminals are a coherent kernel-subsystem concept with their own
  primitives — line discipline, controlling-terminal rules, the
  `termios` struct, the tty `ioctl(2)` surface. `Linx.Process` knows
  enough about PTYs to set one up for a workload (`stdio: :pty`); the
  *interactive* layer that wires the workload's PTY to the *caller's*
  controlling terminal lives here.

  ## What this module is *not*

  Not an interactive-shell library. Not a terminfo / `tput` layer. Not
  a line editor. The point of `Linx.Tty` is to expose the kernel
  primitives so a consumer can build those things on top — or compose
  them with `Linx.Process` in the one way this subsystem builds in:
  `attach/2`.

  ## `/dev/tty`, not fd 0

  The BEAM's stdio is mediated by an Erlang group-leader process; the
  underlying fds are not generally usable from Elixir code, and even
  if they were, going through them would race the group leader.
  `Linx.Tty` opens `/dev/tty` directly — the *controlling terminal* of
  the BEAM process, independent of the group leader. That is what C
  programs like `vim` and `less` do, and it works the same way from
  the BEAM whether iex is running in a terminal emulator, over SSH,
  inside tmux, or as a Nerves device console.

  When the BEAM has no controlling terminal at all (redirected stdio,
  some CI environments), opening `/dev/tty` fails cleanly with
  `{:error, %Linx.Tty.Error{operation: :open, errno: :enxio}}` — a typed
  error a caller can pattern-match on, not a crash.

  ## `/dev/tty` is the BEAM's terminal, not necessarily yours

  `:controlling` targets `/dev/tty` — the BEAM *process's* controlling
  terminal. That is not always the terminal the *caller* is typing
  into. The distinction matters in three environments:

    * **SSH iex** (e.g. `ssh nerves-foo.local` → iex on a Nerves
      device). Erlang's SSH daemon (`ssh_cli`) is a pure
      I/O-protocol bridge; there is no kernel tty behind the SSH
      session. `/dev/tty` inside the BEAM resolves to the BEAM's
      actual controlling tty (on Nerves: the HDMI / UART console),
      not the SSH session.
    * **`:remsh`** (`iex --sname foo --remsh bar@host`). The iex
      shell's group leader is an IO server living in the local
      node; the remote BEAM has its own `/dev/tty` somewhere else.
    * **Headless deployments where the BEAM's controlling tty is a
      serial port the user can't physically reach.**

  Two pieces close those gaps:

    * `attach(:controlling, _)` refuses with
      `{:error, :no_local_tty}` when the caller's group leader is
      fronted by Erlang's SSH daemon (detected by `:ssh_sup` /
      `:sshd_sup` in the GL's `"$ancestors"` chain). Call
      `Linx.Tty.format_error/1` on the atom for the hint.

    * `attach(:group_leader, session)` (T6.1) pumps through the
      caller's group leader instead of `/dev/tty`, working over
      SSH, `:remsh`, and locally as a universal alternative to
      `:controlling`. See `attach/2`'s docstring for the
      mechanism (`:io.setopts(echo: false)` + a linked reader
      sub-process + `:io.put_chars/2` for output + polled winsize).

  Both modes also refuse `{:error, :no_process}` when called against
  a session whose workload has already exited (or whose GenServer is
  gone) — without this the
  pump would set itself up waiting for `:pty_out` events that
  can never arrive, and Ctrl-C wouldn't help (`ssh_cli`
  intercepts it and the pump's reaction is to write `<<3>>` to a
  dead session). `Linx.Process.info/1` is the cheap stage query
  behind the guard.

  ## Save and restore is mandatory

  Any operation that mutates the local terminal's state hands the
  caller back a `t:Linx.Tty.Saved.t/0` blob with which to restore it
  exactly. If the caller forgets to restore and the terminal stays in
  raw mode, the user has to type `reset(1)` blind to recover. The API
  shape (`open_controlling_raw/0` returning the saved state, paired
  with `restore_and_close/2`) and the `attach/2` `try/after` finalisation
  exist so this can't happen accidentally.

  ## Coexisting with iex's tty driver

  When `attach/2` is called from `iex -S mix`, the BEAM already has
  Erlang's `user_drv` / `prim_tty` driver reading `/dev/tty` to support
  type-ahead at the iex prompt. Two readers on the same kernel tty
  buffer alternate-steal each other's bytes — the user sees roughly
  every other keystroke vanish.

  `attach/2` handles this by bracketing its pump with
  `:prim_tty.disable_reader/1` / `:prim_tty.enable_reader/1`, reaching
  into `user_drv`'s state via `:sys.get_state/1` to find the
  `prim_tty` state record. The competing reader process parks in an
  inner `receive` until attach returns and re-enables it. When the
  BEAM isn't running under `user_drv` (escripts, non-shell apps,
  ssh-shell driver variants), the bracket is a no-op.

  ## Runtime SIGWINCH propagation

  `attach/2` also forwards live terminal resizes (drag the corner of
  your emulator while inside the attached shell) to the workload's
  PTY. It does this by registering a `Linx.Tty.SigwinchHandler`
  instance on OTP's `:erl_signal_server` for the lifetime of the
  attach; each `SIGWINCH` becomes a `{:linx_tty, :sigwinch}` message
  in the pump's mailbox, which re-reads `TIOCGWINSZ` on the local tty
  and pushes the new size through `Linx.Process.pty_set_winsize/2`.
  Inside the container, `bash` / `vim` / `top` then see `SIGWINCH`
  through their *own* (slave-side) tty and redraw at the new size.

  Coexists with `prim_tty_sighandler` (iex's own SIGWINCH consumer):
  `:gen_event` broadcasts to every registered handler.

  ## Status

  T0–T5 shipped: scaffolding, termios + ioctl primitives, `attach/2`,
  window-size propagation, coexistence with `iex`'s tty driver, and
  runtime SIGWINCH-driven resize updates. T6.0 + T6.1 shipped on
  branch `tty-group-leader-attach`: the SSH-aware refusal guard on
  `attach(:controlling, _)`, the `Linx.Tty.format_error/1` helper,
  and the `attach(:group_leader, _)` mode that pumps via the
  Erlang I/O protocol — works over SSH, `:remsh`, and locally as
  a universal alternative to `:controlling`. See
  `docs/tty/PLAN.md` for the roadmap.
  """

  alias Linx.Tty.Native
  alias Linx.Tty.{Env, Saved, WindowSize}

  @typedoc """
  An open file descriptor referring to a tty device. Integer — the
  caller hands it back to `restore_and_close/2`, `window_size/1`, etc.
  """
  @type fd :: non_neg_integer()

  @typedoc """
  A `Linx.Process` session pid (running with `stdio: :pty`). The
  attaching side never touches the workload's master fd directly; it
  goes through `Linx.Process.pty_write/2` and the `:pty_out` event
  stream.
  """
  @type session :: pid()

  # Error stages the C agent can name. The Port-decoded ETF for any
  # error from `Linx.Tty.Native` already lives in this BEAM as an
  # atom; referencing them here is belt-and-braces against `:safe`
  # decode and against ever-typo'd stage names in the C side.
  @error_stages [:open, :tcgetattr, :tcsetattr, :ioctl, :close]
  @doc false
  def __error_stages__, do: @error_stages

  @doc """
  Returns the linx_tty NIF version string — sanity that the native
  library loaded and its ABI is reachable.
  """
  @spec version() :: binary()
  def version, do: Native.version()

  @doc """
  Opens `/dev/tty` and switches it to raw mode (`cfmakeraw(3)`), saving
  the current `termios` so it can be restored later.

  Returns `{:ok, fd, saved}` on success — `fd` for wrapping with
  `:erlang.open_port({:fd, fd, fd}, [...])`, `saved` for
  `restore_and_close/2`. `{:error, %Linx.Tty.Error{}}` covers the
  failure paths (`operation` is one of `:open`, `:tcgetattr`,
  `:tcsetattr`); the most common case — BEAM without a controlling
  terminal — surfaces as
  `{:error, %Linx.Tty.Error{operation: :open, errno: :enxio}}`.

  Pair every successful call with `restore_and_close/2` (idiomatically
  in a `try/after`) so the user's terminal can never be left stuck in
  raw mode.
  """
  @spec open_controlling_raw() :: {:ok, fd(), Saved.t()} | {:error, term()}
  def open_controlling_raw do
    case Native.open_controlling_raw() do
      {:ok, fd, saved_bin} -> {:ok, fd, %Saved{termios: saved_bin}}
      {:error, _} = err -> wrap_tty_error(err)
    end
  end

  @doc """
  Restores the saved `termios` on `fd` and closes the fd.

  Symmetric finaliser for `open_controlling_raw/0`. Idempotent against
  already-closed fds — calling it twice (e.g. once explicitly, then
  again from an outer `try/after`) is safe.
  """
  @spec restore_and_close(fd(), Saved.t()) :: :ok | {:error, term()}
  def restore_and_close(fd, %Saved{termios: saved_bin}) when is_integer(fd) do
    wrap_tty_error(Native.restore_and_close(fd, saved_bin))
  end

  @doc """
  Returns the current window size of the terminal named by `fd`
  (`ioctl(TIOCGWINSZ)`).
  """
  @spec window_size(fd()) :: {:ok, WindowSize.t()} | {:error, term()}
  def window_size(fd) when is_integer(fd) do
    case Native.window_size(fd) do
      {:ok, {rows, cols, xp, yp}} ->
        {:ok, %WindowSize{rows: rows, cols: cols, xpixel: xp, ypixel: yp}}

      {:error, _} = err ->
        wrap_tty_error(err)
    end
  end

  @doc """
  Sets the window size of the terminal named by `fd`
  (`ioctl(TIOCSWINSZ)`).

  The common path for setting the workload's window size goes through
  the agent — `Linx.Process.pty_set_winsize/2` (lands in T3). This
  verb is for the rare case of mutating a tty fd held directly by the
  caller.
  """
  @spec set_window_size(fd(), WindowSize.t()) :: :ok | {:error, term()}
  def set_window_size(fd, %WindowSize{rows: r, cols: c, xpixel: xp, ypixel: yp})
      when is_integer(fd) do
    wrap_tty_error(Native.set_window_size(fd, {r, c, xp, yp}))
  end

  # Wrap the linx_tty NIF's {:error, {stage, errno}} pairs in a
  # %Linx.Tty.Error{}; pass :ok / {:ok, _} through untouched.
  defp wrap_tty_error({:error, {stage, errno}}),
    do: {:error, Linx.Tty.Error.from_nif(stage, errno)}

  defp wrap_tty_error(other), do: other

  @doc """
  Hands the caller's terminal over to `session`'s PTY master and
  pumps bytes both ways until the workload exits, then restores
  the terminal.

  `target` selects how the caller's terminal is reached:

    * `:controlling` — open `/dev/tty` directly. Works wherever
      the BEAM's controlling terminal is the user's terminal
      (local iex on a terminal emulator, Nerves HDMI / UART
      console). Refuses with `{:error, :no_local_tty}` when the
      caller is over SSH (the T6.0 guard).

    * `:group_leader` — pump through the caller's
      `Process.group_leader/0` via Erlang's I/O protocol. Works
      over SSH / `:remsh` and anywhere else the user's terminal
      is an Erlang process rather than a kernel tty fd. Also
      works on a local terminal; it's the universal mode.

  Returns the terminal event from the session — `{:ok, {:exited, n}}`,
  `{:ok, {:signaled, n}}` — or `{:error, _}` for a setup failure
  or a pre-exec workload error.

  ## `:group_leader` mode specifics

  Implementation: set `:io.setopts(gl, echo: false)` so `:group`
  routes input through its `:dumb` state (byte-oriented, no line
  editor); flip the driver's `:prim_tty` output mode from
  `:cooked` to `:raw` via `:sys.replace_state/2` so workload
  output bytes pass through verbatim instead of being rendered
  in caret notation (without this, the workload's `\b \b`
  backspace-erase echo arrives at the SSH client as `^( ^(`);
  spawn a reader sub-process that loops on
  `:io.get_chars(:standard_io, ~c"", 1)` and forwards bytes to
  the pump's mailbox. `N = 1` is intentional: `:group`'s
  `:dumb` state runs `collect_chars` (non-eager), which waits
  for *exactly* N chars before returning; the eager variant
  (`collect_chars_eager`, which returns whatever's available)
  is gated by `shell = noshell`, unreachable with an iex shell
  attached. One byte per round-trip is sub-microsecond and
  invisible at interactive speeds, including paste.

  Both transient state changes (echo and prim_tty output mode)
  are restored unconditionally on exit via `try/after`, even on
  a raise inside the pump.

  ### Ctrl-C handling

  `ssh_cli` intercepts byte `\\x03` (Ctrl-C) from the SSH stream
  and turns it into `exit(group, interrupt)` instead of passing
  the byte through. The pump translates that back into a literal
  `\\x03` byte to the workload's PTY in both shapes it can arrive:
  as `{:error, :interrupted}` on the reader's pending
  `:io.get_chars` (the common case), and as a direct
  `{:EXIT, ^gl, :interrupt}` to the pump's mailbox (the race case
  where the interrupt arrives between two reader round-trips).
  The workload's PTY line discipline then turns the byte into
  SIGINT for the foreground process group — the user-visible
  "Ctrl-C interrupts the running command" behaviour.
  pump output via `:io.put_chars(gl, bytes)`, which sends
  `{put_chars, :unicode, _}`. The unicode encoding is mandatory
  here — OTP's `ssh_cli` has no io_request clause for `:latin1`
  and silently drops `IO.binwrite/2`'s `{put_chars, :latin1, _}`
  via its `unhandled_request` catch-all, hanging the caller.
  Window size is seeded from `:io.columns/0` + `:io.rows/0` and
  re-checked on a polling timer (default 250ms) since SSH has no
  SIGWINCH equivalent. The choice of polling vs an event-driven
  trace hook on ssh_cli is discussed at the `@winsize_poll_ms`
  module attribute below.

  Side-effects worth knowing about, all transient (restored on
  return, even on a raise inside the pump):

    * The caller's `:echo` opt is flipped to `false`. iex's line
      editing (history, completion, `^A`/`^E`, etc.) is bypassed
      for the duration — bytes go to the workload, not the iex
      readline. Expected; the workload's own shell does its
      editing on the other side of the PTY.
    * Window-size updates lag by up to `:winsize_poll_ms` (default
      `250`). Fine for shells; barely noticeable even mid-`vim`.

  Caveat: the SSH transport keeps the line-discipline of the
  user's local terminal (your local `ssh` client puts your local
  terminal in raw mode by default; if it didn't, no amount of
  BEAM-side wrangling would deliver per-keystroke input). All
  observed nerves_ssh paths are fine here.

  ## Owner requirement

  `attach/2` *must* be called from the process that owns `session` —
  the pid that received `{:linx_process, :ready, _}` when the session
  was spawned. The pump waits for `{:linx_process, :pty_out, _}`
  events in the calling process's mailbox; if they go elsewhere it
  blocks forever. The owner defaults to the caller of `spawn/1`, so
  the natural case ("spawn and attach from the same place") works
  without thought.

  ## Restore is unconditional

  The byte pump runs in the *calling process* and blocks until the
  workload terminates. The caller's terminal is restored
  unconditionally via `try/after`, even on a crash inside the loop,
  so a wedged terminal is structurally impossible.
  """
  @spec attach(:controlling | :group_leader, session()) ::
          {:ok, {:exited, non_neg_integer()} | {:signaled, pos_integer()}}
          | {:error, :no_local_tty | :no_process | :gl_eof | term()}
  def attach(:controlling, session) when is_pid(session) do
    # Two preconditions in order:
    # 1. The session must still be running. Without this, attach
    #    happily sets up its byte pump on a session whose workload
    #    has already exited -- no :pty_out events will ever arrive,
    #    no :exited event either (it was already consumed by a
    #    prior attach), and the pump hangs forever. Ctrl-C doesn't
    #    help over SSH because ssh_cli intercepts it and the pump's
    #    reaction is to send <<3>> to a dead session.
    # 2. T6.0 guard: when the caller's terminal is fronted by
    #    Erlang's SSH daemon, /dev/tty is the BEAM's controlling
    #    tty (the HDMI / UART console on Nerves) -- *not* the SSH
    #    session. Refuse cleanly rather than silently pumping bytes
    #    to the wrong terminal.
    with :ok <- ensure_session_running(session) do
      case Env.classify_caller_terminal() do
        :ssh -> {:error, :no_local_tty}
        _ -> attach_controlling(session)
      end
    end
  end

  # How often `attach(:group_leader, _)`'s pump re-reads
  # `:io.columns` / `:io.rows` and forwards a changed window size to
  # the workload's PTY. 250ms gives a worst-case redraw lag of
  # ~250ms after the user finishes dragging their terminal corner --
  # well below "noticeable" for interactive use -- while spending
  # ~60us/s of CPU on the geometry round-trips (about 0.006% of one
  # core; sub-noise even on the rpi5).
  #
  # ## Why polling rather than an event-driven hook
  #
  # ssh_cli (lib/ssh/src/ssh_cli.erl) receives the SSH protocol's
  # `window_change` channel request as a `{ssh_cm, _, {window_change,
  # ChannelId, W, H, _, _}}` message, updates its internal `#ssh_pty{}`
  # record and the prim_tty geometry, and stops. It does not notify
  # the group (or anyone subscribed to the group) -- the new geometry
  # is only visible by querying ssh_cli back, which is what
  # :io.columns/:io.rows do.
  #
  # The event-driven alternative is `:erlang.trace(ssh_cli_pid, true,
  # [:receive])` for the lifetime of attach, pattern-matching on the
  # window_change message in the pump's receive, and reacting
  # immediately. Pros: near-zero latency (microseconds), zero
  # idle-time CPU. Cons: (1) every message ssh_cli receives gets sent
  # to our process for inspection, so the per-keystroke overhead
  # grows linearly with traffic -- still small in absolute terms but
  # not free; (2) `:erlang.trace/3` is a debugging mechanism and
  # using it as a production-shaped API is unusual, with edge cases
  # around trace token inheritance and gc of the trace state; (3)
  # tighter OTP-internals coupling than polling (we'd be depending
  # on the exact message shape ssh_cli receives, which is more
  # fragile than our existing coupling to the group's state record
  # layout).
  #
  # Polling at 250ms hits the sweet spot: human-imperceptible
  # latency, negligible CPU, no debug-API dependency. If a future
  # use case actually needs sub-100ms resize fidelity (a TUI that
  # needs to redraw before the user lets go of the corner), the
  # trace-based hook becomes worth its complexity -- until then,
  # 250ms is the right call.
  @winsize_poll_ms 250

  def attach(:group_leader, session) when is_pid(session) do
    with :ok <- ensure_session_running(session) do
      attach_group_leader(session, @winsize_poll_ms)
    end
  end

  # Refuses attach against a session whose workload has already
  # terminated, or whose GenServer is gone. `Linx.Process.info/1`
  # is a synchronous GenServer.call that returns the lifecycle
  # stage cheaply.
  defp ensure_session_running(session) do
    case Linx.Process.info(session) do
      {:ok, %{stage: stage}} when stage in [:exited, :signaled, :aborted, :errored] ->
        {:error, :no_process}

      {:ok, _info} ->
        :ok

      {:error, :no_process} ->
        {:error, :no_process}

      {:error, _} = other ->
        other
    end
  end

  @doc """
  Returns a human-readable description for error atoms `Linx.Tty`
  returns. Currently covers `:no_local_tty` (the T6.0 guard's
  refusal); falls back to `inspect/1` for any other shape so it can
  be safely chained at error sites without losing information.
  """
  @spec format_error(term()) :: binary()
  def format_error(:no_local_tty) do
    "Your iex appears to be over SSH (or :remsh); /dev/tty inside the " <>
      "BEAM is the BEAM's controlling terminal (e.g. the HDMI/UART " <>
      "console on Nerves), not your remote session. Use " <>
      "Linx.Tty.attach(:group_leader, session) instead (T6.1)."
  end

  def format_error(:no_process) do
    "There is no live workload for this session -- it has reached a " <>
      "terminal stage (exited / signaled / aborted / errored), or its " <>
      "GenServer is gone. attach/2 requires a running session. Inspect " <>
      "Linx.Process.info/1 for the terminal stage and result, or spawn " <>
      "a fresh session via Linx.Process.spawn/1."
  end

  def format_error(other), do: inspect(other)

  defp attach_group_leader(session, winsize_poll_ms) do
    gl = Process.group_leader()
    saved_echo = Keyword.get(:io.getopts(gl), :echo, true)
    saved_trap = Process.flag(:trap_exit, true)

    try do
      _ = :io.setopts(gl, echo: false)

      # Flip the driver's `:prim_tty` output mode from `:cooked` to
      # `:raw` for the lifetime of the pump. Cooked mode renders
      # non-printable bytes as caret notation (`\b` -> `^(`, `\x7F` ->
      # `^?`, etc.) -- a useful behaviour for iex's own line editor,
      # but exactly wrong for an attach pump that's supposed to relay
      # the workload's raw terminal bytes through to the caller's
      # terminal emulator. Without this, backspace from the workload's
      # PTY echo (`\b \b`) renders as `^( ^(`, vim's TUI sequences get
      # mangled, etc. See T6.1.1 in `docs/tty/PLAN.md`.
      #
      # Returns an opaque "saved" value (or `nil` if the driver
      # doesn't look like ssh_cli / user_drv with a `:prim_tty` state)
      # so the matching restore on the way out is a no-op when there's
      # nothing to undo.
      saved_tty_mode = take_prim_tty_output_quietly(gl, :raw)

      initial_ws = seed_winsize(gl, session)
      reader = spawn_link(__MODULE__, :__gl_reader__, [self(), gl])

      try do
        __pump_gl__(reader, gl, session, winsize_poll_ms, initial_ws)
      after
        # Reader is stuck in :io.get_chars; an exit signal unblocks it.
        if Process.alive?(reader), do: Process.exit(reader, :shutdown)
        # Drain its linked :EXIT message so we don't leak it past the
        # trap_exit restore below.
        receive do
          {:EXIT, ^reader, _} -> :ok
        after
          200 -> :ok
        end

        give_prim_tty_output_back(saved_tty_mode)
      end
    after
      # Only restore the field we touched. `:io.setopts/2` short-circuits
      # on options it considers `:enotsup` (e.g. `terminal: false`), so
      # restoring the whole `:io.getopts/0` result would silently drop
      # later keys -- including the echo we care about.
      _ = :io.setopts(gl, echo: saved_echo)
      Process.flag(:trap_exit, saved_trap)
    end
  end

  defp seed_winsize(gl, session) do
    case {:io.columns(gl), :io.rows(gl)} do
      {{:ok, cols}, {:ok, rows}} ->
        ws = %WindowSize{rows: rows, cols: cols, xpixel: 0, ypixel: 0}
        _ = Linx.Process.pty_set_winsize(session, ws)
        ws

      _ ->
        nil
    end
  end

  @doc false
  # Linked reader sub-process: synchronous `:io.get_chars/3` in a
  # loop, translating each batch of bytes into a pump mailbox
  # message. Exposed (under @doc false) so `spawn_link/3` can reach
  # it as an MFA -- otherwise an anonymous fun would do.
  @spec __gl_reader__(pid(), pid()) :: no_return()
  def __gl_reader__(parent, gl) when is_pid(parent) and is_pid(gl) do
    # Defensive: `spawn_link/3` already inherits the parent's GL,
    # which is the GL we want, but set it explicitly so an unusual
    # call site (e.g. tests) doesn't accidentally read from a
    # different IO server.
    Process.group_leader(self(), gl)
    gl_reader_loop(parent)
  end

  defp gl_reader_loop(parent) do
    # `N = 1`, not a larger buffer size. With echo=false `:group`
    # routes input through its `:dumb` state's `collect_chars`
    # (non-eager) handler, which waits for *exactly* N chars before
    # returning. The eager variant (`collect_chars_eager`) that
    # returns on first byte is gated by `shell = noshell`, which we
    # can't satisfy with an iex shell. So we ask for one byte per
    # round-trip; each keystroke completes a `get_chars(1)`
    # immediately, the pump forwards it, and we loop. One message
    # round-trip per byte is sub-microsecond — fine for interactive
    # use including paste.
    case :io.get_chars(:standard_io, ~c"", 1) do
      :eof ->
        send(parent, {:linx_tty_gl, :eof})

      {:error, :interrupted} ->
        # SSH Ctrl-C handling. `ssh_cli` (lib/ssh-5.5.2/src/ssh_cli.erl:408)
        # intercepts byte `\x03` from the SSH stream and turns it into
        # `exit(group, interrupt)` instead of passing the byte through.
        # If we (the reader) have a pending `:io.get_chars` request,
        # group.erl:511 replies `{error, interrupted}`. Translate that
        # back into a literal `\x03` byte for the workload so the
        # workload's PTY line discipline can turn it into SIGINT for
        # the foreground process group -- the user-visible "Ctrl-C
        # interrupts the running command" behaviour.
        send(parent, {:linx_tty_gl, :data, <<3>>})
        gl_reader_loop(parent)

      {:error, why} ->
        send(parent, {:linx_tty_gl, {:error, why}})

      bytes when is_binary(bytes) ->
        send(parent, {:linx_tty_gl, :data, bytes})
        gl_reader_loop(parent)

      bytes when is_list(bytes) ->
        send(parent, {:linx_tty_gl, :data, IO.iodata_to_binary(bytes)})
        gl_reader_loop(parent)
    end
  end

  @doc false
  # The `:group_leader`-mode pump. Exposed (under @doc false) so tests
  # can drive it directly without spinning up the full attach flow.
  #
  # `last_ws` is the most recently forwarded `Linx.Tty.WindowSize` (or
  # `nil` if the initial seed failed or hasn't happened). The polling
  # `after` clause forwards a new size only when it differs, so a quiet
  # terminal generates no work beyond the periodic `:io` round-trips.
  @spec __pump_gl__(pid(), pid(), session(), pos_integer(), WindowSize.t() | nil) ::
          {:ok, {:exited, non_neg_integer()} | {:signaled, pos_integer()}}
          | {:error, term()}
  def __pump_gl__(reader, gl, session, poll_ms, last_ws)
      when is_pid(reader) and is_pid(gl) and is_pid(session) and is_integer(poll_ms) do
    receive do
      {:linx_tty_gl, :data, bytes} ->
        _ = Linx.Process.pty_write(session, bytes)
        __pump_gl__(reader, gl, session, poll_ms, last_ws)

      {:linx_process, :pty_out, bytes} ->
        # `:io.put_chars/2`, not `IO.binwrite/2`. `:io.put_chars/2`
        # sends `{put_chars, :unicode, _}`; `IO.binwrite/2` sends
        # `{put_chars, :latin1, _}`. OTP's `ssh_cli` (lib/ssh's CLI
        # channel handler) has no io_request clause for `:latin1` --
        # it falls through to a catch-all that does
        # `erlang:display({unhandled_request, Req})` and returns no
        # reply, hanging the caller forever. `:unicode` is the only
        # encoding ssh_cli handles, and `:group` plus the local
        # `user_drv` both translate `{put_chars, :unicode, _}`
        # correctly. Implication: workload output should be UTF-8 /
        # ASCII (which is the standard interactive-shell case);
        # arbitrary binary content may fail
        # `:unicode.characters_to_binary/1` inside ssh_cli.
        _ = :io.put_chars(gl, bytes)
        __pump_gl__(reader, gl, session, poll_ms, last_ws)

      {:linx_tty_gl, :eof} ->
        {:error, :gl_eof}

      {:linx_tty_gl, {:error, why}} ->
        {:error, {:gl_reader, why}}

      {:EXIT, ^reader, reason} ->
        {:error, {:gl_reader_exit, reason}}

      {:EXIT, ^gl, :interrupt} ->
        # Race case: ssh_cli intercepted ^C and exit'd us directly
        # rather than via our reader's pending input request (see
        # group.erl:507 -- the "input = undefined" handler). Happens
        # in the tiny window between our reader's get_chars
        # round-trips. Translate to a `\x03` byte for the workload
        # so SIGINT propagation still works.
        _ = Linx.Process.pty_write(session, <<3>>)
        __pump_gl__(reader, gl, session, poll_ms, last_ws)

      {:linx_process, :exited, code} ->
        {:ok, {:exited, code}}

      {:linx_process, :signaled, signum} ->
        {:ok, {:signaled, signum}}

      {:linx_process, :error, errno, stage} ->
        {:error, Linx.Process.Error.from_agent(errno, stage)}
    after
      poll_ms ->
        new_ws = maybe_forward_winsize(gl, session, last_ws)
        __pump_gl__(reader, gl, session, poll_ms, new_ws)
    end
  end

  defp maybe_forward_winsize(gl, session, last_ws) do
    case {:io.columns(gl), :io.rows(gl)} do
      {{:ok, cols}, {:ok, rows}} ->
        ws = %WindowSize{rows: rows, cols: cols, xpixel: 0, ypixel: 0}

        if ws != last_ws do
          _ = Linx.Process.pty_set_winsize(session, ws)
          ws
        else
          last_ws
        end

      _ ->
        last_ws
    end
  end

  defp attach_controlling(session) do
    with {:ok, fd, saved} <- open_controlling_raw() do
      # Pause Erlang's prim_tty reader so it stops competing with us
      # for /dev/tty reads. See the module doc's "Coexisting with
      # iex's tty driver". `nil` when no user_drv (escript, etc.) --
      # then no one else is reading the tty and there's nothing to
      # pause.
      tty_state = take_tty_quietly()
      sigwinch_id = make_ref()

      try do
        # Arm a SIGWINCH forwarder so the pump sees terminal-resize
        # events (drag the corner of the emulator while inside the
        # attached shell) and re-seeds the workload's PTY size on the
        # fly. See `Linx.Tty.SigwinchHandler` and the module doc.
        arm_sigwinch(sigwinch_id)

        # Tell the workload's PTY about our terminal's current
        # dimensions before it sees anything, so a fresh bash inside
        # the attached child opens at the right size.
        case window_size(fd) do
          {:ok, ws} -> _ = Linx.Process.pty_set_winsize(session, ws)
          {:error, _} -> :ok
        end

        port = :erlang.open_port({:fd, fd, fd}, [:binary, :stream])
        __pump__(port, session, fd)
      after
        disarm_sigwinch(sigwinch_id)
        restore_and_close(fd, saved)
        give_tty_back(tty_state)
      end
    end
  end

  # Suspend `prim_tty`'s reader process so it doesn't pull keystrokes
  # out from under our port. Returns the opaque prim_tty state on
  # success (hand it back to give_tty_back/1) or nil if there is no
  # competing reader to suspend.
  #
  # `user_drv` is a gen_statem registered as `:user_drv`. Its state
  # data is the record `#state{tty, write, read, ...}`; field 1 (after
  # the record-name tag at position 0) is the prim_tty state, which is
  # what `prim_tty:disable_reader/1` operates on.
  #
  # We touch internal record layout here intentionally and isolated to
  # this one helper -- see the module doc. Anything unexpected (no
  # user_drv, surprising state shape, prim_tty rejecting the state)
  # falls through to "no suspend": the every-other-byte bug returns
  # for that session but nothing crashes.
  defp take_tty_quietly do
    with pid when is_pid(pid) <- Process.whereis(:user_drv),
         {_state_name, state_data} <- safe_get_state(pid),
         tty when not is_nil(tty) <- safe_elem(state_data, 1),
         :ok <- safe_disable(tty) do
      tty
    else
      _ -> nil
    end
  end

  defp give_tty_back(nil), do: :ok

  defp give_tty_back(tty) do
    try do
      :prim_tty.enable_reader(tty)
    catch
      _, _ -> :ok
    end
  end

  defp safe_get_state(pid), do: safe_get_state(pid, 1000)

  defp safe_get_state(pid, timeout) do
    try do
      :sys.get_state(pid, timeout)
    catch
      _, _ -> nil
    end
  end

  defp safe_elem(tuple, idx) when is_tuple(tuple) and tuple_size(tuple) > idx do
    elem(tuple, idx)
  end

  defp safe_elem(_, _), do: nil

  defp safe_disable(tty) do
    try do
      :prim_tty.disable_reader(tty)
    catch
      _, _ -> :error
    end
  end

  # Find the driver pid backing the caller's group leader (the SSH
  # `ssh_cli` channel handler on a Nerves SSH session, the local
  # `user_drv` on a terminal-attached iex) and flip its `:prim_tty`
  # output mode to `new_mode`. Returns `{drv, old_mode}` to hand to
  # `give_prim_tty_output_back/1`, or `nil` if the driver doesn't
  # have an addressable `:prim_tty` state (escripts, non-shell apps,
  # drivers we don't recognise).
  #
  # We touch OTP internals here -- specifically, we run a function
  # inside the driver process via `:sys.replace_state/2` that scans
  # its state record for an element that responds to
  # `:prim_tty.output_mode/1`, swaps in a `:prim_tty.reinit/2`'d
  # version with the new output mode, and shouts the previous mode
  # back to us through a one-shot ref. Same kind of OTP-internals
  # coupling T4 already accepts for `:prim_tty.disable_reader/1`.
  # Scanning rather than hard-coding the field index makes us
  # resilient to ssh_cli / user_drv record-layout reshuffles across
  # OTP versions.
  defp take_prim_tty_output_quietly(gl, new_mode) do
    # Use a short timeout (200ms) for the GL introspection: a real
    # `:group` gen_statem replies within microseconds, while
    # non-`:sys`-capable processes (test fakes, escripts' raw IO
    # servers, etc.) wedge the call until the timeout. Falling
    # through quickly on those keeps the fall-through path cheap.
    with {_state_name, group_state} <- safe_get_state(gl, 200),
         drv when is_pid(drv) <- safe_elem(group_state, 2),
         {:ok, old_mode} <- safe_replace_prim_tty_output(drv, new_mode) do
      {drv, old_mode}
    else
      _ -> nil
    end
  end

  defp give_prim_tty_output_back(nil), do: :ok

  defp give_prim_tty_output_back({drv, old_mode}) do
    _ = safe_replace_prim_tty_output(drv, old_mode)
    :ok
  end

  defp safe_replace_prim_tty_output(drv, new_mode) do
    ref = make_ref()
    parent = self()

    swap = fn state ->
      case find_prim_tty_in_state(state) do
        {path, old_tty} ->
          case swap_prim_tty_output_mode_direct(old_tty, new_mode) do
            {:ok, new_tty, old_mode} ->
              send(parent, {ref, {:ok, old_mode}})
              put_in_tuple_path(state, path, new_tty)

            :error ->
              send(parent, {ref, :swap_failed})
              state
          end

        :not_found ->
          send(parent, {ref, :no_prim_tty})
          state
      end
    end

    try do
      _ = :sys.replace_state(drv, swap, 200)

      receive do
        {^ref, {:ok, old_mode}} -> {:ok, old_mode}
        {^ref, _} -> :error
      after
        200 -> :error
      end
    catch
      _, _ -> :error
    end
  end

  # Recursively search `state` for an element that responds to
  # `:prim_tty.output_mode/1`. Returns `{path, prim_tty_state}` where
  # `path` is a list of tuple indices from the outermost state down
  # to the prim_tty field, or `:not_found`.
  #
  # Recursion is needed because the SSH driver is an
  # `ssh_client_channel` gen_server whose state record wraps the
  # `ssh_cli` callback state as a field; the `prim_tty` we want lives
  # two levels deep. Local `user_drv` has prim_tty at field index 1,
  # one level. The recursive walk handles both without us hard-coding
  # either layout.
  defp find_prim_tty_in_state(state) do
    find_prim_tty_in_state(state, [])
  end

  defp find_prim_tty_in_state(state, path_so_far) when is_tuple(state) do
    case safe_prim_tty_output_mode(state) do
      {:ok, _} ->
        {Enum.reverse(path_so_far), state}

      _ ->
        state
        |> Tuple.to_list()
        |> Enum.with_index()
        |> Enum.find_value(:not_found, fn {field, idx} ->
          case find_prim_tty_in_state(field, [idx | path_so_far]) do
            :not_found -> false
            found -> found
          end
        end)
    end
  end

  defp find_prim_tty_in_state(_, _), do: :not_found

  defp put_in_tuple_path(_state, [], value), do: value

  defp put_in_tuple_path(state, [idx | rest], value) when is_tuple(state) do
    inner = elem(state, idx)
    new_inner = put_in_tuple_path(inner, rest, value)
    put_elem(state, idx, new_inner)
  end

  defp safe_prim_tty_output_mode(maybe_tty) do
    try do
      {:ok, :prim_tty.output_mode(maybe_tty)}
    catch
      _, _ -> :error
    end
  end

  # Flip prim_tty's output mode by mutating its `options` map in
  # place, rather than calling `:prim_tty.reinit/2`. The latter ends
  # up in `tty_init/2` -- a NIF that requires a real terminal fd --
  # and crashes with `:function_clause` for SSH-fronted prim_tty
  # states whose `tty` field is `undefined` (set up via
  # `prim_tty:init_ssh/3`, not `:init/1`).
  #
  # The output-mode dispatch at `prim_tty.erl:677` is
  # `handle_request(State = #state{ options = #{ output := raw } }, ...)`,
  # so just mutating `options.output` is sufficient -- no re-init,
  # no NIF call.
  #
  # The `options` field is identified by scanning the state tuple
  # for an element that's a map with both `:input` and `:output` keys
  # (distinctive enough to single out `prim_tty`'s options map
  # without hard-coding its index against record-layout changes).
  defp swap_prim_tty_output_mode_direct(prim_tty_state, new_mode)
       when is_tuple(prim_tty_state) do
    idx =
      prim_tty_state
      |> Tuple.to_list()
      |> Enum.find_index(&prim_tty_options_map?/1)

    if idx do
      old_options = elem(prim_tty_state, idx)
      old_mode = Map.get(old_options, :output)
      new_options = Map.put(old_options, :output, new_mode)
      {:ok, put_elem(prim_tty_state, idx, new_options), old_mode}
    else
      :error
    end
  end

  defp swap_prim_tty_output_mode_direct(_, _), do: :error

  defp prim_tty_options_map?(%{input: _, output: _}), do: true
  defp prim_tty_options_map?(_), do: false

  # Register a `Linx.Tty.SigwinchHandler` instance on
  # `:erl_signal_server` keyed by `{handler, id}` so multiple
  # concurrent attaches can coexist (each `id` is a unique ref made by
  # the caller). The signal disposition is set to `:handle` regardless
  # -- it's a global property and harmless when no handlers are
  # registered.
  #
  # Soft-fails: SIGWINCH propagation is a quality-of-life feature; if
  # OTP's signal infrastructure isn't available we degrade to the
  # initial-seed-only behaviour T3 gave us, without crashing attach.
  defp arm_sigwinch(id) do
    try do
      :os.set_signal(:sigwinch, :handle)
      :gen_event.add_handler(:erl_signal_server, {Linx.Tty.SigwinchHandler, id}, self())
    catch
      _, _ -> :ok
    end

    :ok
  end

  defp disarm_sigwinch(id) do
    try do
      :gen_event.delete_handler(:erl_signal_server, {Linx.Tty.SigwinchHandler, id}, [])
    catch
      _, _ -> :ok
    end

    :ok
  end

  @doc false
  # The byte pump. Exposed (under @doc false) so tests can drive it
  # through a port wrapping a socketpair stand-in for /dev/tty without
  # touching the test runner's real terminal.
  #
  # `local_fd` is the fd of the local tty we wrapped as `port` (or
  # `nil` from the socketpair test path). When non-nil and a
  # SIGWINCH event arrives, the pump re-reads `TIOCGWINSZ` on it and
  # forwards the new size to the workload's PTY.
  #
  # The caller must own `session` -- the :pty_out events arrive in the
  # owner's mailbox, and this function expects to receive them in its
  # own mailbox. See attach/2's docs for the constraint.
  @spec __pump__(port(), session(), fd() | nil) ::
          {:ok, {:exited, non_neg_integer()} | {:signaled, pos_integer()}}
          | {:error, term()}
  def __pump__(port, session, local_fd \\ nil)
      when is_port(port) and is_pid(session) and (is_integer(local_fd) or is_nil(local_fd)) do
    receive do
      {^port, {:data, bytes}} ->
        _ = Linx.Process.pty_write(session, bytes)
        __pump__(port, session, local_fd)

      {:linx_process, :pty_out, bytes} ->
        Port.command(port, bytes)
        __pump__(port, session, local_fd)

      {:linx_tty, :sigwinch} ->
        if is_integer(local_fd) do
          case window_size(local_fd) do
            {:ok, ws} -> _ = Linx.Process.pty_set_winsize(session, ws)
            {:error, _} -> :ok
          end
        end

        __pump__(port, session, local_fd)

      {:linx_process, :exited, code} ->
        {:ok, {:exited, code}}

      {:linx_process, :signaled, signum} ->
        {:ok, {:signaled, signum}}

      {:linx_process, :error, errno, stage} ->
        {:error, Linx.Process.Error.from_agent(errno, stage)}
    end
  end
end
