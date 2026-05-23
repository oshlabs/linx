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

  ## Status

  T0 (scaffolding), T1 (termios + ioctl primitives), and T2
  (`attach/2`) are shipped. Window-size propagation across
  `Linx.Process` lands in T3. See `docs/tty/PLAN.md` for the roadmap.
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
      try do
        # Best-effort: tell the workload's PTY about our terminal's
        # current dimensions before it sees anything. Runtime
        # SIGWINCH-driven updates aren't wired yet (Erlang's signal
        # surface doesn't include SIGWINCH out of the box -- see
        # PLAN.md's "deferred to a follow-up"), so for now the
        # workload sees the size at attach time and that's it.
        case window_size(fd) do
          {:ok, ws} -> _ = Linx.Process.pty_set_winsize(session, ws)
          {:error, _} -> :ok
        end

        port = :erlang.open_port({:fd, fd, fd}, [:binary, :stream])
        __pump__(port, session)
      after
        restore_and_close(fd, saved)
      end
    end
  end

  @doc false
  # The byte pump. Exposed (under @doc false) so tests can drive it
  # through a port wrapping a socketpair stand-in for /dev/tty without
  # touching the test runner's real terminal.
  #
  # The caller must own `session` -- the :pty_out events arrive in the
  # owner's mailbox, and this function expects to receive them in its
  # own mailbox. See attach/2's docs for the constraint.
  @spec __pump__(port(), session()) ::
          {:ok, {:exited, non_neg_integer()} | {:signaled, pos_integer()}}
          | {:error, term()}
  def __pump__(port, session) when is_port(port) and is_pid(session) do
    receive do
      {^port, {:data, bytes}} ->
        _ = Linx.Process.pty_write(session, bytes)
        __pump__(port, session)

      {:linx_process, :pty_out, bytes} ->
        Port.command(port, bytes)
        __pump__(port, session)

      {:linx_process, :exited, code} ->
        {:ok, {:exited, code}}

      {:linx_process, :signaled, signum} ->
        {:ok, {:signaled, signum}}

      {:linx_process, :error, errno, stage} ->
        {:error, %{errno: errno, stage: stage}}
    end
  end
end
