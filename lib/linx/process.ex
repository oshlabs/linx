defmodule Linx.Process do
  @moduledoc """
  Linux process-lifecycle primitives — `clone(2)` with namespace flags,
  `setns(2)`, `execve(2)`, signal delivery and exit-status reporting —
  exposed through one GenServer per spawned child.

  ## Why a separate OS process

  `clone()`, `fork()` and `unshare()` performed inside the multithreaded
  BEAM corrupt the VM. So the actual syscalls live in a small external C
  binary — `priv/linx_process`, built from `c_src/linx_process.c` by the
  `:linx_process` Mix compiler — spawned via `Port.open` with
  `:nouse_stdio` and `{:packet, 4}` framing. Control traffic is Erlang
  External Term Format on fd 3 (BEAM → binary) and fd 4 (binary → BEAM);
  fd 0/1/2 stay free for the workload's stdio.

  This module IS the GenServer. The pid returned by `spawn/1` (and later
  `enter/2`) is the session handle: pass it to `proceed/1`, `signal/2`,
  `wait/1`, `info/1`, and `pty_master/1`.

  ## Owner events

  The owner (the caller of `spawn/1`, or `:owner` explicitly) receives
  these messages over the course of a session:

    * `{:linx_process, :ready, child_pid}` — the child reached the
      checkpoint. `child_pid` is the child's pid *as the child sees it*
      (1 inside a fresh PID namespace; otherwise the host pid).
    * `{:linx_process, :running}` — the child has `execve`'d the
      workload.
    * `{:linx_process, :exited, code}` — the workload exited normally.
    * `{:linx_process, :signaled, signum}` — the workload was killed
      by a signal.
    * `{:linx_process, :error, errno, stage}` — a pre-exec failure;
      `stage` is the atom naming the syscall that failed.

  Each session emits exactly one terminal event (`:exited` /
  `:signaled` / `:error`) and then the GenServer stops with reason
  `:normal`.

  ## Status

  P0 (scaffolding), P1 (`spawn/1` with the checkpoint protocol), and P2
  (`signal/2`, `wait/1`) are shipped; `proceed/1` is wired. `enter/2`,
  `info/1`, `pty_master/1` are still stubs — see `docs/process/PLAN.md`.
  """

  use GenServer

  # The pid that `spawn/1` and `enter/2` return is the GenServer pid.
  @type t :: pid()

  # The kinds of namespace the child may be cloned into (P1) or join (P3).
  # Each maps to a CLONE_NEW* flag in the C agent.
  @type namespace :: :net | :mount | :pid | :uts | :ipc | :user | :cgroup | :time

  @valid_namespaces ~w(net mount pid uts ipc user cgroup time)a
  @valid_stdio_atoms ~w(inherit devnull pty)a
  @valid_per_fd_atoms ~w(inherit devnull)a

  # Atoms the C agent can send back as the `stage` field of {:error, errno,
  # stage}. The Port's data is decoded with `:safe`, which requires every
  # atom in the term to already exist in the BEAM — so this list exists
  # solely to ensure these atoms are loaded at module compile time. (Naming
  # mirrors what the agent emits: `setns_<ns>` / `open_ns_<ns>` per type.)
  @error_stages [
    :execve,
    :clone,
    :fork,
    :stdio,
    :posix_openpt,
    :ptsetup,
    :ptsname,
    :pts_open,
    :setns_user,
    :setns_mount,
    :setns_uts,
    :setns_ipc,
    :setns_cgroup,
    :setns_net,
    :setns_time,
    :setns_pid,
    :open_ns_user,
    :open_ns_mount,
    :open_ns_uts,
    :open_ns_ipc,
    :open_ns_cgroup,
    :open_ns_net,
    :open_ns_time,
    :open_ns_pid
  ]

  @doc false
  def __error_stages__, do: @error_stages

  @doc """
  Spawns a child process via `clone(2)`, optionally into fresh namespaces.

  Returns `{:ok, pid}` — the pid of the GenServer that owns the child and
  is the session handle.

  `opts`:

    * `:argv` (required) — the workload argv as a list of binaries. The
      first element is the absolute path of the executable; no `$PATH`
      lookup is performed.
    * `:namespaces` — list of `t:namespace/0` atoms to create fresh.
      Defaults to `[]` (share all of the BEAM's namespaces).
    * `:env` — environment as a list of `"KEY=VALUE"` binaries. Defaults
      to inheriting the BEAM's environment.
    * `:owner` — pid to receive lifecycle events. Defaults to the caller.
    * `:stdio` — workload fd 0/1/2 plumbing. See "Stdio plumbing" below.

  ## Stdio plumbing

  `:stdio` is either a single atom shorthand applying to all three fds,
  or a keyword list giving per-fd directives.

  **Shorthand atoms:**

    * `:inherit` (default) — the workload inherits the BEAM's stdio.
    * `:devnull` — all three fds are `/dev/null`.
    * `:pty` — the agent creates a PTY pair; the workload becomes
      session leader with the slave as its controlling terminal, with
      0/1/2 dup'd onto it. The master end stays in the agent and the
      bytes are proxied through the existing control channel: writes
      via `pty_write/2`, reads delivered to the owner as
      `{:linx_process, :pty_out, bytes}`.

  **Per-fd keyword list** — `[stdin: dir, stdout: dir, stderr: dir]`,
  each `dir` one of:

    * `:inherit` — leave that fd untouched.
    * `:devnull` — dup `/dev/null` onto it.
    * `{:connect_unix, "/path/to/socket"}` — the workload connects an
      `AF_UNIX` stream socket to `path` and dup2's it onto the fd. The
      listener at `path` is the caller's responsibility (must be
      `:gen_tcp.listen`-ing before `spawn/1`).

  Per-fd PTY directives are not supported — a PTY is one device shared
  across all three fds; use the `:pty` shorthand.
  """
  @spec spawn(keyword) :: {:ok, t()} | {:error, term}
  def spawn(opts) do
    owner = Keyword.get(opts, :owner, self())

    with {:ok, request} <- build_spawn_request(opts) do
      GenServer.start_link(__MODULE__, {{:spawn, request}, owner})
    end
  end

  @doc """
  Runs a new process *inside* an existing target's namespaces via
  `setns(2)` + `execve(2)`.

  The agent opens `/proc/<target_pid>/ns/<type>` for each namespace
  type and `setns(2)`s into each, then `fork(2)`s — the child inherits
  the target's namespaces and `execve`s the workload there. Same
  checkpoint protocol as `spawn/1`: the owner gets `:ready` →
  `proceed/1` → `:running` → terminal.

  `target_pid` is the *host* pid of the process whose namespaces you
  want to join (the pid you saw in `{:linx_process, :ready, _}` when
  `:pid` was *not* in that session's `:namespaces`, or the host pid
  reported by `Linx.Process.info/1` for sessions that include
  `:pid`).

  `opts`:

    * `:argv` (required) — the workload argv.
    * `:namespaces` — which of the target's namespaces to join.
      Defaults to *all* — every namespace type the target has under
      `/proc/<target>/ns/`. Pass a list (e.g. `[:net]`) to join only
      those.
    * `:env` — workload environment as `["KEY=VAL", …]`. Defaults to
      inherit.
    * `:owner` — pid to receive lifecycle events. Defaults to the
      caller.
  """
  @spec enter(pos_integer, keyword) :: {:ok, t()} | {:error, term}
  def enter(target_pid, opts)
      when is_integer(target_pid) and target_pid > 0 and is_list(opts) do
    owner = Keyword.get(opts, :owner, self())

    with {:ok, request} <- build_enter_request(target_pid, opts) do
      GenServer.start_link(__MODULE__, {{:enter, request}, owner})
    end
  end

  @doc """
  Advances the child past the checkpoint: the agent forwards `:proceed`
  to the cloned child, which then `execve`s the workload.

  The wire-level command this sends is `:proceed`, which is also the
  Elixir verb name — one word for the same action on both sides of
  the Port boundary.

  Returns `:ok`, or `{:error, :not_ready}` if the agent has not yet
  reported `:ready` (i.e. there is no checkpoint to advance past).
  """
  @spec proceed(t()) :: :ok | {:error, term}
  def proceed(session) when is_pid(session) do
    GenServer.call(session, :proceed)
  end

  @doc """
  Sends OS signal `signum` to the workload.

  Signals delivered before the workload has `execve`'d (between
  `spawn/1` and `proceed/1`, or before the agent emits `:running`) are
  buffered and flushed in order at the moment of `:running`. Signals
  delivered after the workload has exited return `{:error, :ended}`.

  This is fire-and-forget — `signal/2` returns as soon as the signal
  has been handed to the agent (or buffered), without waiting for the
  kernel to deliver it. Use `wait/1` to observe the workload's
  response.
  """
  @spec signal(t(), pos_integer) :: :ok | {:error, term}
  def signal(session, signum) when is_pid(session) and is_integer(signum) and signum > 0 do
    GenServer.call(session, {:signal, signum})
  end

  @doc """
  Releases a parked session **without** running the workload. The
  alternative to `proceed/1` from the `:ready` state.

  When the agent is parked at the checkpoint (post-`:ready`,
  pre-`:running`), `abort/1` tells it to discard the cloned child
  rather than letting it `execve`. The agent closes the child's
  unblock pipe so the child sees EOF and `_exit`s, reaps it, and
  emits `{:status, :aborted, child_pid}` over the control channel.
  The owner then receives `{:linx_process, :aborted}` and the
  session moves to its terminal state.

  ## Use cases

    * **Setup-time rollback.** A container engine starts spawning,
      discovers setup can't complete (cgroup creation fails, a
      bind mount errors, …), and wants to cancel the workload
      cleanly without it running for even one instruction.
    * **Checkpoint-only verification.** A test or health check
      that wants to confirm namespace setup *worked* without
      actually running the workload — e.g. an integration test
      that pivots `/proc` inside a fresh mount namespace and just
      wants to verify via mountinfo.
    * **Race-with-decision.** The owner's "should I proceed?"
      logic returns false; `abort/1` is the clean discard.

  ## State semantics

    * **Pre-`:ready`** — buffered; fires the moment `:ready`
      arrives. Same shape as `signal/2`'s pre-`:running`
      buffering.
    * **`:ready` (parked)** — primary case; immediate abort.
    * **`:running`** — `{:error, :running}`. The workload is
      past the checkpoint; use `signal/2` to terminate it.
    * **Already terminal** — `{:error, :already_terminated}`.

  Fire-and-forget — `abort/1` returns as soon as the agent has
  the request. Use `wait/1` to block on the `:aborted` terminal
  event.
  """
  @spec abort(t()) :: :ok | {:error, :running | :already_terminated}
  def abort(session) when is_pid(session) do
    GenServer.call(session, :abort)
  end

  @doc """
  Synchronously waits for the workload's terminal event.

  Returns one of:

    * `{:ok, {:exited, code}}` — workload exited with `code`.
    * `{:ok, {:signaled, signum}}` — workload was killed by `signum`.
    * `{:ok, :aborted}` — `abort/1` was called from the checkpoint;
      the workload never ran.
    * `{:error, %{errno: errno, stage: stage}}` — a pre-exec failure;
      the workload never ran.
    * `{:error, :timeout}` — `timeout` elapsed before any terminal
      event arrived. The session is still alive; call `wait/1` again.
    * `{:error, :session_ended}` — the session GenServer is gone (e.g.
      the agent crashed before reporting a terminal event).

  Multiple processes may wait on the same session concurrently; all
  receive the same answer when it arrives.
  """
  @spec wait(t(), timeout()) ::
          {:ok, {:exited, non_neg_integer} | {:signaled, pos_integer} | :aborted}
          | {:error, term}
  def wait(session, timeout \\ :infinity)

  def wait(session, timeout) when is_pid(session) do
    GenServer.call(session, :wait, timeout)
  catch
    :exit, {:timeout, _} -> {:error, :timeout}
    :exit, _ -> {:error, :session_ended}
  end

  @doc """
  Returns a snapshot of the session's state — mode, host pid, current
  lifecycle stage.

  Lands incrementally as state accumulates (P1+); today returns
  `{:error, :not_yet_implemented}`.
  """
  @spec info(t()) :: {:ok, map()} | {:error, term}
  def info(_session), do: {:error, :not_yet_implemented}

  @doc """
  Writes bytes to the workload's PTY master, which the workload sees as
  input on its stdin. Returns `{:error, :no_pty}` if the session was
  not started with `stdio: :pty`.

  Fire-and-forget — bytes are handed to the agent (and from there to
  the PTY); there is no acknowledgement.
  """
  @spec pty_write(t(), iodata()) :: :ok | {:error, term}
  def pty_write(session, bytes) when is_pid(session) do
    GenServer.call(session, {:pty_write, IO.iodata_to_binary(bytes)})
  end

  @doc """
  Sets the workload's PTY window size (`TIOCSWINSZ` on the master end,
  via the agent).

  Accepts either a 4-tuple `{rows, cols, xpixel, ypixel}` or any map
  / struct exposing those fields (`Linx.Tty.WindowSize` is the
  canonical such struct, but `Linx.Process` deliberately doesn't
  depend on `Linx.Tty` — duck-typing on the field shape avoids the
  cross-subsystem dependency).

  Best-effort on the agent side: the workload will see `SIGWINCH` and
  the new size on its next `TIOCGWINSZ`, but no error is propagated
  back if the ioctl fails. Returns `{:error, :no_pty}` if the session
  wasn't started with `stdio: :pty`.
  """
  @spec pty_set_winsize(
          t(),
          {non_neg_integer, non_neg_integer, non_neg_integer, non_neg_integer}
          | %{
              :rows => non_neg_integer,
              :cols => non_neg_integer,
              :xpixel => non_neg_integer,
              :ypixel => non_neg_integer,
              optional(any) => any
            }
        ) :: :ok | {:error, term}
  def pty_set_winsize(session, {rows, cols, xpix, ypix})
      when is_pid(session) and is_integer(rows) and is_integer(cols) and
             is_integer(xpix) and is_integer(ypix) and
             rows >= 0 and cols >= 0 and xpix >= 0 and ypix >= 0 do
    GenServer.call(session, {:pty_winsize, {rows, cols, xpix, ypix}})
  end

  def pty_set_winsize(session, %{rows: r, cols: c, xpixel: xp, ypixel: yp}) do
    pty_set_winsize(session, {r, c, xp, yp})
  end

  @doc """
  Returns `{:ok, session}` if the session was started with `stdio: :pty`
  — the session pid is itself the handle to read from (via
  `{:linx_process, :pty_out, _}` events on the owner) and to write to
  (via `pty_write/2`). Returns `{:error, :no_pty}` otherwise.

  A future `Linx.Tty` subsystem will likely return something richer here
  — a struct wrapping the session, terminal-mode helpers, etc. For
  now it just confirms PTY-mode-ness.
  """
  @spec pty_master(t()) :: {:ok, t()} | {:error, term}
  def pty_master(session) when is_pid(session) do
    GenServer.call(session, :pty_master)
  end

  # --- input validation -----------------------------------------------------

  defp build_spawn_request(opts) do
    with {:ok, argv} <- fetch_argv(opts),
         {:ok, namespaces} <- fetch_namespaces(opts),
         {:ok, env} <- fetch_env(opts),
         {:ok, stdio} <- fetch_stdio(opts) do
      request = %{argv: argv, namespaces: namespaces}
      request = if env, do: Map.put(request, :env, env), else: request
      request = if stdio, do: Map.put(request, :stdio, stdio), else: request
      {:ok, request}
    end
  end

  # Enter mode omits :namespaces from the request map when the caller did
  # not specify one — the C side treats an absent :namespaces key as
  # "join every namespace the target has under /proc/<pid>/ns/".
  defp build_enter_request(target_pid, opts) do
    with {:ok, argv} <- fetch_argv(opts),
         {:ok, namespaces} <- fetch_optional_namespaces(opts),
         {:ok, env} <- fetch_env(opts),
         {:ok, stdio} <- fetch_stdio(opts) do
      request = %{target: target_pid, argv: argv}
      request = if namespaces, do: Map.put(request, :namespaces, namespaces), else: request
      request = if env, do: Map.put(request, :env, env), else: request
      request = if stdio, do: Map.put(request, :stdio, stdio), else: request
      {:ok, request}
    end
  end

  defp fetch_argv(opts) do
    case Keyword.get(opts, :argv) do
      [head | _] = argv when is_binary(head) ->
        if Enum.all?(argv, &is_binary/1),
          do: {:ok, argv},
          else: {:error, :bad_argv}

      _ ->
        {:error, :argv_required}
    end
  end

  defp fetch_namespaces(opts) do
    case Keyword.get(opts, :namespaces, []) do
      list when is_list(list) ->
        if Enum.all?(list, &(&1 in @valid_namespaces)),
          do: {:ok, list},
          else: {:error, {:bad_namespaces, list -- @valid_namespaces}}

      _ ->
        {:error, :bad_namespaces}
    end
  end

  # As above, but `:error` from Keyword.fetch — "key absent" — passes
  # through as `{:ok, nil}` so build_enter_request can elide :namespaces
  # from the wire request altogether.
  defp fetch_optional_namespaces(opts) do
    case Keyword.fetch(opts, :namespaces) do
      :error ->
        {:ok, nil}

      {:ok, list} when is_list(list) ->
        if Enum.all?(list, &(&1 in @valid_namespaces)),
          do: {:ok, list},
          else: {:error, {:bad_namespaces, list -- @valid_namespaces}}

      _ ->
        {:error, :bad_namespaces}
    end
  end

  defp fetch_env(opts) do
    case Keyword.fetch(opts, :env) do
      :error ->
        {:ok, nil}

      {:ok, list} when is_list(list) ->
        if Enum.all?(list, &is_binary/1),
          do: {:ok, list},
          else: {:error, :bad_env}

      _ ->
        {:error, :bad_env}
    end
  end

  # Decode the :stdio option into a shape the C agent can parse:
  # either an atom (:inherit / :devnull / :pty), or a keyword list of
  # per-fd directives. Returns {:ok, nil} if the key was absent (so the
  # agent uses its built-in default, :inherit).
  defp fetch_stdio(opts) do
    case Keyword.fetch(opts, :stdio) do
      :error -> {:ok, nil}
      {:ok, atom} when atom in @valid_stdio_atoms -> {:ok, atom}
      {:ok, list} when is_list(list) -> validate_per_fd_stdio(list)
      _ -> {:error, :bad_stdio}
    end
  end

  defp validate_per_fd_stdio(list) do
    Enum.reduce_while(list, {:ok, []}, fn
      {fd, directive}, {:ok, acc} when fd in [:stdin, :stdout, :stderr] ->
        case validate_per_fd_directive(directive) do
          :ok -> {:cont, {:ok, [{fd, directive} | acc]}}
          {:error, _} = err -> {:halt, err}
        end

      _other, _ ->
        {:halt, {:error, :bad_stdio}}
    end)
    |> case do
      {:ok, pairs} -> {:ok, Enum.reverse(pairs)}
      {:error, _} = err -> err
    end
  end

  defp validate_per_fd_directive(atom) when atom in @valid_per_fd_atoms, do: :ok

  defp validate_per_fd_directive({:connect_unix, path}) when is_binary(path),
    do: :ok

  defp validate_per_fd_directive(_), do: {:error, :bad_stdio}

  # --- GenServer ------------------------------------------------------------

  @impl true
  def init({command, owner}) when is_tuple(command) and tuple_size(command) == 2 do
    binary = Path.join(:code.priv_dir(:linx), "linx_process")

    if not File.exists?(binary) do
      {:stop, {:missing_binary, binary}}
    else
      port =
        Port.open(
          {:spawn_executable, binary},
          [:binary, :nouse_stdio, {:packet, 4}, :exit_status]
        )

      Port.command(port, :erlang.term_to_binary(command))

      state = %{
        port: port,
        owner: owner,
        host_pid: nil,
        child_pid: nil,
        running?: false,
        pending_signals: [],
        pending_abort?: false,
        waiters: [],
        result: nil,
        pty?: pty?(command)
      }

      {:ok, state}
    end
  end

  # A spawn/enter request is in PTY mode iff its :stdio key is exactly :pty.
  # Per-fd keyword lists never carry PTY (PTY needs all three fds wired to
  # the same slave).
  defp pty?({_tag, %{stdio: :pty}}), do: true
  defp pty?(_), do: false

  @impl true
  def handle_call(:proceed, _from, %{port: port, child_pid: child_pid} = state)
      when child_pid != nil do
    Port.command(port, :erlang.term_to_binary(:proceed))
    {:reply, :ok, state}
  end

  def handle_call(:proceed, _from, state) do
    {:reply, {:error, :not_ready}, state}
  end

  # Terminal event already arrived -- nothing to abort.
  def handle_call(:abort, _from, %{result: result} = state) when result != nil do
    {:reply, {:error, :already_terminated}, state}
  end

  # Already past the checkpoint -- abort is only valid pre-execve.
  def handle_call(:abort, _from, %{running?: true} = state) do
    {:reply, {:error, :running}, state}
  end

  # Parked at :ready -- forward :abort to the agent immediately.
  def handle_call(:abort, _from, %{port: port, child_pid: child_pid} = state)
      when child_pid != nil do
    Port.command(port, :erlang.term_to_binary(:abort))
    {:reply, :ok, state}
  end

  # Pre-:ready -- buffer the abort. The :ready handler in handle_info
  # fires it the moment the checkpoint is reached. Matches signal/2's
  # pre-:running buffering shape.
  def handle_call(:abort, _from, %{child_pid: nil} = state) do
    {:reply, :ok, %{state | pending_abort?: true}}
  end

  # The workload has already terminated; sending a signal would have no
  # target.
  def handle_call({:signal, _signum}, _from, %{result: result} = state)
      when result != nil do
    {:reply, {:error, :ended}, state}
  end

  # Pre-running: buffer signals; flushed in handle_info on :running.
  def handle_call({:signal, signum}, _from, %{running?: false} = state) do
    {:reply, :ok, %{state | pending_signals: [signum | state.pending_signals]}}
  end

  # Running: forward directly to the agent.
  def handle_call({:signal, signum}, _from, %{port: port} = state) do
    Port.command(port, :erlang.term_to_binary({:signal, signum}))
    {:reply, :ok, state}
  end

  # Terminal event already arrived -- answer immediately.
  def handle_call(:wait, _from, %{result: result} = state) when result != nil do
    {:reply, normalise_result(result), state}
  end

  # Otherwise enqueue the caller; reply when the terminal event arrives.
  def handle_call(:wait, from, state) do
    {:noreply, %{state | waiters: [from | state.waiters]}}
  end

  # PTY write -- only valid when the session is in PTY mode.
  def handle_call({:pty_write, bytes}, _from, %{pty?: true, port: port} = state)
      when port != nil do
    Port.command(port, :erlang.term_to_binary({:pty_in, bytes}))
    {:reply, :ok, state}
  end

  def handle_call({:pty_write, _bytes}, _from, %{pty?: false} = state) do
    {:reply, {:error, :no_pty}, state}
  end

  def handle_call({:pty_write, _bytes}, _from, state) do
    {:reply, {:error, :session_ended}, state}
  end

  def handle_call(:pty_master, _from, %{pty?: true} = state) do
    {:reply, {:ok, self()}, state}
  end

  def handle_call(:pty_master, _from, state) do
    {:reply, {:error, :no_pty}, state}
  end

  # Winsize forwarding -- only meaningful in PTY mode.
  def handle_call({:pty_winsize, _ws}, _from, %{pty?: false} = state) do
    {:reply, {:error, :no_pty}, state}
  end

  def handle_call({:pty_winsize, _ws}, _from, %{port: nil} = state) do
    {:reply, {:error, :session_ended}, state}
  end

  def handle_call({:pty_winsize, ws}, _from, %{port: port} = state) do
    Port.command(port, :erlang.term_to_binary({:pty_winsize, ws}))
    {:reply, :ok, state}
  end

  # Map the internal result tuple onto the shape `wait/1` documents.
  defp normalise_result({:exited, _} = r), do: {:ok, r}
  defp normalise_result({:signaled, _} = r), do: {:ok, r}
  defp normalise_result(:aborted), do: {:ok, :aborted}
  defp normalise_result({:error, _} = error), do: error

  @impl true
  def handle_info({port, {:data, payload}}, %{port: port} = state) do
    case :erlang.binary_to_term(payload, [:safe]) do
      {:status, :spawned, host_pid} ->
        {:noreply, %{state | host_pid: host_pid}}

      {:status, :ready, child_pid} ->
        send(state.owner, {:linx_process, :ready, child_pid})
        state = %{state | child_pid: child_pid}

        # Fire a buffered abort: an `abort/1` that landed before the
        # checkpoint is forwarded the moment the agent is parked there.
        state =
          if state.pending_abort? do
            Port.command(state.port, :erlang.term_to_binary(:abort))
            %{state | pending_abort?: false}
          else
            state
          end

        {:noreply, state}

      {:status, :running} ->
        send(state.owner, {:linx_process, :running})
        flush_pending_signals(state)
        {:noreply, %{state | running?: true, pending_signals: []}}

      {:status, :exited, code} ->
        send(state.owner, {:linx_process, :exited, code})
        {:noreply, finalise(state, {:exited, code})}

      {:status, :signaled, signum} ->
        send(state.owner, {:linx_process, :signaled, signum})
        {:noreply, finalise(state, {:signaled, signum})}

      {:status, :aborted, _child_pid} ->
        send(state.owner, {:linx_process, :aborted})
        {:noreply, finalise(state, :aborted)}

      {:error, errno, stage} ->
        send(state.owner, {:linx_process, :error, errno, stage})
        {:noreply, finalise(state, {:error, %{errno: errno, stage: stage}})}

      {:pty_out, bytes} ->
        send(state.owner, {:linx_process, :pty_out, bytes})
        {:noreply, state}
    end
  end

  def handle_info({port, {:exit_status, _code}}, %{port: port} = state) do
    # The agent exited. Don't stop the GenServer yet -- a wait/1 caller
    # racing the port shutdown should still see the recorded result. The
    # GenServer is linked to the spawn/1 caller, so it dies with that
    # process and nothing accumulates; meanwhile, `:result` remains
    # queryable. An explicit `stop/1` may land later for early cleanup.
    {:noreply, %{state | port: nil}}
  end

  # Any waiters still in the queue when the GenServer goes down -- e.g.
  # the spawn/1 caller dies before a terminal event arrives -- get
  # :session_ended so they don't sit blocked forever.
  @impl true
  def terminate(_reason, state) do
    Enum.each(state.waiters, &GenServer.reply(&1, {:error, :session_ended}))
    :ok
  end

  # Drain pending_signals to the agent in the order they were queued.
  defp flush_pending_signals(%{port: port, pending_signals: signals}) do
    Enum.each(Enum.reverse(signals), fn signum ->
      Port.command(port, :erlang.term_to_binary({:signal, signum}))
    end)
  end

  # Store the terminal result and answer every blocked wait/1 caller.
  defp finalise(state, result) do
    answer = normalise_result(result)
    Enum.each(state.waiters, &GenServer.reply(&1, answer))
    %{state | result: result, waiters: []}
  end
end
