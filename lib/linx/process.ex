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
  """
  @spec spawn(keyword) :: {:ok, t()} | {:error, term}
  def spawn(opts) do
    owner = Keyword.get(opts, :owner, self())

    with {:ok, request} <- build_request(opts) do
      GenServer.start_link(__MODULE__, {request, owner})
    end
  end

  @doc """
  Runs a new process *inside* an existing target's namespaces via
  `setns(2)` + `execve(2)`.

  Lands in P3; today returns `{:error, :not_yet_implemented}`.
  """
  @spec enter(pos_integer, keyword) :: {:ok, t()} | {:error, term}
  def enter(_target_pid, _opts), do: {:error, :not_yet_implemented}

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
  Synchronously waits for the workload's terminal event.

  Returns one of:

    * `{:ok, {:exited, code}}` — workload exited with `code`.
    * `{:ok, {:signaled, signum}}` — workload was killed by `signum`.
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
          {:ok, {:exited, non_neg_integer} | {:signaled, pos_integer}}
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
  Returns a handle to the workload's PTY master, when the session was
  started with `stdio: :pty`.

  Lands in P4; today returns `{:error, :not_yet_implemented}`.
  """
  @spec pty_master(t()) :: {:ok, port()} | {:error, term}
  def pty_master(_session), do: {:error, :not_yet_implemented}

  # --- input validation -----------------------------------------------------

  defp build_request(opts) do
    with {:ok, argv} <- fetch_argv(opts),
         {:ok, namespaces} <- fetch_namespaces(opts),
         {:ok, env} <- fetch_env(opts) do
      request = %{argv: argv, namespaces: namespaces}
      request = if env, do: Map.put(request, :env, env), else: request
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

  # --- GenServer ------------------------------------------------------------

  @impl true
  def init({request, owner}) do
    binary = Path.join(:code.priv_dir(:linx), "linx_process")

    if not File.exists?(binary) do
      {:stop, {:missing_binary, binary}}
    else
      port =
        Port.open(
          {:spawn_executable, binary},
          [:binary, :nouse_stdio, {:packet, 4}, :exit_status]
        )

      Port.command(port, :erlang.term_to_binary({:spawn, request}))

      state = %{
        port: port,
        owner: owner,
        host_pid: nil,
        child_pid: nil,
        running?: false,
        pending_signals: [],
        waiters: [],
        result: nil
      }

      {:ok, state}
    end
  end

  @impl true
  def handle_call(:proceed, _from, %{port: port, child_pid: child_pid} = state)
      when child_pid != nil do
    Port.command(port, :erlang.term_to_binary(:proceed))
    {:reply, :ok, state}
  end

  def handle_call(:proceed, _from, state) do
    {:reply, {:error, :not_ready}, state}
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

  # Map the internal result tuple onto the shape `wait/1` documents.
  defp normalise_result({:exited, _} = r), do: {:ok, r}
  defp normalise_result({:signaled, _} = r), do: {:ok, r}
  defp normalise_result({:error, _} = error), do: error

  @impl true
  def handle_info({port, {:data, payload}}, %{port: port} = state) do
    case :erlang.binary_to_term(payload, [:safe]) do
      {:status, :spawned, host_pid} ->
        {:noreply, %{state | host_pid: host_pid}}

      {:status, :ready, child_pid} ->
        send(state.owner, {:linx_process, :ready, child_pid})
        {:noreply, %{state | child_pid: child_pid}}

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

      {:error, errno, stage} ->
        send(state.owner, {:linx_process, :error, errno, stage})
        {:noreply, finalise(state, {:error, %{errno: errno, stage: stage}})}
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
