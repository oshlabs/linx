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
  `{:error, {:open, :enxio}}` — a typed error a caller can pattern-match
  on, not a crash.

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
  runtime SIGWINCH-driven resize updates. See `docs/tty/PLAN.md` for
  the roadmap.
  """

  alias Linx.Tty.Native
  alias Linx.Tty.{Saved, WindowSize}

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
  `restore_and_close/2`. `{:error, {stage, errno}}` covers the failure
  paths (`stage` is one of `:open`, `:tcgetattr`, `:tcsetattr`); the
  most common case — BEAM without a controlling terminal — surfaces
  as `{:error, {:open, :enxio}}`.

  Pair every successful call with `restore_and_close/2` (idiomatically
  in a `try/after`) so the user's terminal can never be left stuck in
  raw mode.
  """
  @spec open_controlling_raw() :: {:ok, fd(), Saved.t()} | {:error, term()}
  def open_controlling_raw do
    case Native.open_controlling_raw() do
      {:ok, fd, saved_bin} -> {:ok, fd, %Saved{termios: saved_bin}}
      {:error, _} = err -> err
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
    Native.restore_and_close(fd, saved_bin)
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
        err
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
    Native.set_window_size(fd, {r, c, xp, yp})
  end

  @doc """
  Hands the BEAM's controlling terminal over to `session`'s PTY master
  and pumps bytes both ways until the workload exits, then restores
  the terminal.

  `target` chooses which local tty the caller hands over. Today only
  `:controlling` (open `/dev/tty`) is meaningful; future shapes may
  accept an explicit fd.

  Returns the terminal event from the session — `{:ok, {:exited, n}}`,
  `{:ok, {:signaled, n}}` — or `{:error, _}` for a setup failure or
  a pre-exec workload error.

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
  @spec attach(:controlling, session()) ::
          {:ok, {:exited, non_neg_integer()} | {:signaled, pos_integer()}}
          | {:error, term()}
  def attach(:controlling, session) when is_pid(session) do
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

  defp safe_get_state(pid) do
    try do
      :sys.get_state(pid, 1000)
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
        {:error, %{errno: errno, stage: stage}}
    end
  end
end
