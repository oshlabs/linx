defmodule Linx.Process.Info do
  @moduledoc """
  A snapshot of a `Linx.Process` session's state.

  Returned by `Linx.Process.info/1`. Cheap to fetch — a single
  `GenServer.call` on the session that returns the relevant fields
  from the GenServer's internal state.

  ## Fields

    * `:mode` — `:spawn` (the session was created via
      `Linx.Process.spawn/1`) or `:enter` (created via
      `Linx.Process.enter/2`).
    * `:stage` — the current lifecycle stage. See "Stages" below.
    * `:host_pid` — the host's view of the workload's pid, once
      known. `nil` before the `:spawned` status arrives.
    * `:child_pid` — the workload's *own* view of its pid (= 1 in
      a fresh PID namespace; otherwise the host pid). `nil` before
      the `:ready` status arrives. This is the in-namespace value; the
      `:ready` owner message and `:host_pid` carry the host's view.
    * `:pty?` — `true` iff the session was spawned with `stdio: :pty`.
    * `:result` — the terminal result, once one has arrived. `nil`
      before that. Same shape as `Linx.Process.wait/1` returns
      under `{:ok, _}` (`{:exited, code}` / `{:signaled, signum}` /
      `:aborted`), or `{:error, %Linx.Process.Error{}}` for pre-exec
      failures.

  ## Stages

  The `:stage` field collapses the lifecycle into a single atom:

    * `:starting` — `host_pid` not yet seen; the agent is mid-clone
      or mid-fork.
    * `:spawned` — host pid known but the checkpoint hasn't been
      reached yet (the child is in pre-checkpoint setup).
    * `:ready` — child parked at the checkpoint; awaiting
      `proceed/1` or `abort/1`.
    * `:running` — child has `execve`'d the workload.
    * `:exited` — workload exited normally; see `:result`.
    * `:signaled` — workload was killed by a signal; see `:result`.
    * `:aborted` — session was aborted from the checkpoint; the
      workload never `execve`'d.
    * `:errored` — a pre-exec failure (or transport-level error)
      ended the session; see `:result`.

  The first four stages are pre-terminal (the session is still
  alive); the last four are terminal (a `wait/1` would return
  immediately).

  ## Inspect

  Compact rendering, showing mode + stage + host_pid (+ result
  payload for terminal stages):

      #Linx.Process.Info<spawn :ready host=12345>
      #Linx.Process.Info<spawn :running host=12345 pty>
      #Linx.Process.Info<enter :exited(0) host=12345>
      #Linx.Process.Info<spawn :errored(execve/2) host=12345>
  """

  @enforce_keys [:mode, :stage, :host_pid, :child_pid, :pty?, :result]
  defstruct [:mode, :stage, :host_pid, :child_pid, :pty?, :result]

  @type mode :: :spawn | :enter

  @type stage ::
          :starting
          | :spawned
          | :ready
          | :running
          | :exited
          | :signaled
          | :aborted
          | :errored

  @type result ::
          nil
          | {:exited, non_neg_integer()}
          | {:signaled, pos_integer()}
          | :aborted
          | {:error, Linx.Process.Error.t()}

  @type t :: %__MODULE__{
          mode: mode(),
          stage: stage(),
          host_pid: pos_integer() | nil,
          child_pid: pos_integer() | nil,
          pty?: boolean(),
          result: result()
        }

  defimpl Inspect do
    def inspect(%Linx.Process.Info{} = info, _opts) do
      mode = Atom.to_string(info.mode)
      stage = format_stage(info.stage, info.result)
      host = format_host(info.host_pid)
      pty = if info.pty?, do: " pty", else: ""

      "#Linx.Process.Info<#{mode} #{stage}#{host}#{pty}>"
    end

    # Terminal stages get their payload inline.
    defp format_stage(:exited, {:exited, code}), do: ":exited(#{code})"
    defp format_stage(:signaled, {:signaled, signum}), do: ":signaled(#{signum})"

    defp format_stage(:errored, {:error, %Linx.Process.Error{stage: s, code: c}}),
      do: ":errored(#{s}/#{c})"

    defp format_stage(stage, _), do: ":#{stage}"

    defp format_host(nil), do: ""
    defp format_host(pid), do: " host=#{pid}"
  end
end
