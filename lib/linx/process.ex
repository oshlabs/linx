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
  External Term Format on fd 3 (BEAM ↔ binary) and fd 4 (binary → BEAM);
  fd 0/1/2 stay free for the workload's stdio.

  This module IS the GenServer. The pid returned by `spawn/1` (and
  `enter/2`) is the session handle: pass it to `release/1`, `signal/2`,
  `wait/1`, `info/1`, and `pty_master/1`.

  ## Status

  Phase 1 is in flight. Today this module is a P0 skeleton — the
  binary builds, the Port machinery rounds-trips frames, and the
  public API is sketched. The real verbs (`spawn`, `enter`, `release`,
  …) all return `{:error, :not_yet_implemented}` until P1 wires them
  up. See `docs/process/PLAN.md` for the roadmap.
  """

  use GenServer

  # The pid that `spawn/1` and `enter/2` return is the GenServer pid.
  @type t :: pid()

  # The kinds of namespace the child may be cloned into (P1) or join (P3).
  # Each maps to a CLONE_NEW* flag in the C agent.
  @type namespace :: :net | :mount | :pid | :uts | :ipc | :user | :cgroup | :time

  @doc """
  Spawns a child process via `clone(2)`, optionally into fresh namespaces.

  Returns the pid of the GenServer that owns the child. Lands in P1; today
  returns `{:error, :not_yet_implemented}`.

  `opts`:

    * `:argv` (required) — the workload argv as a list of binaries.
    * `:namespaces` — list of `t:namespace/0` atoms to create fresh.
      Default: `[]` (share all of the BEAM's namespaces).
    * `:env` — environment as `[{charlist, charlist}]`. Default: inherit.
    * `:owner` — pid to receive lifecycle events. Default: the caller.
  """
  @spec spawn(keyword) :: {:ok, t()} | {:error, term}
  def spawn(_opts), do: {:error, :not_yet_implemented}

  @doc """
  Runs a new process *inside* an existing target's namespaces via
  `setns(2)` + `execve(2)`.

  Lands in P3; today returns `{:error, :not_yet_implemented}`.

  `opts` accepts `:argv`, `:namespaces` (which of the target's to join;
  default all), `:env`, `:owner`.
  """
  @spec enter(pos_integer, keyword) :: {:ok, t()} | {:error, term}
  def enter(_target_pid, _opts), do: {:error, :not_yet_implemented}

  @doc """
  Releases the checkpoint: the child may `execve` the workload now.

  Lands in P1; today returns `{:error, :not_yet_implemented}`.
  """
  @spec release(t()) :: :ok | {:error, term}
  def release(_session), do: {:error, :not_yet_implemented}

  @doc """
  Sends OS signal `signum` to the workload. Buffered until the workload
  has `execve`'d.

  Lands in P2; today returns `{:error, :not_yet_implemented}`.
  """
  @spec signal(t(), pos_integer) :: :ok | {:error, term}
  def signal(_session, _signum), do: {:error, :not_yet_implemented}

  @doc """
  Synchronously waits for the workload's terminal event.

  Lands in P2; today returns `{:error, :not_yet_implemented}`.
  """
  @spec wait(t(), timeout()) ::
          {:ok, {:exited, non_neg_integer} | {:signaled, pos_integer}} | {:error, term}
  def wait(session, timeout \\ :infinity)
  def wait(_session, _timeout), do: {:error, :not_yet_implemented}

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

  # --- GenServer scaffolding -------------------------------------------------
  #
  # P0 carries the use-GenServer architectural commitment but none of the
  # session state yet. The init/1 stub keeps the module compilable and the
  # behaviour-implemented warnings quiet; P1 fleshes it out.

  @impl true
  def init(_opts), do: {:ok, %{}}
end
