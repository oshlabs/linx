defmodule Linx.Sysctl.Reconcile.Report do
  @moduledoc """
  The outcome of one `Linx.Sysctl.Reconcile.reconcile/3` pass.

  A reconcile pass applies a list of ops (see `t:op/0`) and records what
  happened. Sysctl writes are independent per key, so the pass is
  **best-effort**: every op is attempted, and any that error land in
  `:failed` rather than aborting the rest. (Ordered subsystems like rtnl,
  where a later op depends on an earlier one, use the same report shape but a
  fail-fast strategy: `:failed` holds at most one op and `:pending` holds the
  rest. The struct is uniform; the strategy is per subsystem.)

  Fields:

    * `:converged?` — `true` iff nothing was left undone: no ops were needed,
      or every op applied. `false` iff anything failed (or, for a fail-fast
      subsystem, anything is still pending).
    * `:applied` — ops that succeeded this pass, in attempt order.
    * `:failed` — `{op, %Linx.Sysctl.Error{}}` pairs for ops that errored.
    * `:pending` — ops not attempted. Always `[]` for sysctl (best-effort
      attempts everything); non-empty only for fail-fast subsystems.
    * `:last_applied` — the **updated** ownership map to thread into the next
      pass (see `Linx.Sysctl.Reconcile` for its shape and why it is
      reconciler-held, never persisted). Carrying it here lets a loop do
      `{:ok, report} = reconcile(desired, report.last_applied)` each tick.

  ## Inspect

  Renders compactly:

      #Linx.Sysctl.Reconcile.Report<converged: 3 applied>
      #Linx.Sysctl.Reconcile.Report<2 applied, 1 failed>
  """

  alias Linx.Sysctl.Reconcile

  @enforce_keys [:converged?, :applied, :failed, :pending, :last_applied]
  defstruct [:converged?, :applied, :failed, :pending, :last_applied]

  @type t :: %__MODULE__{
          converged?: boolean(),
          applied: [Reconcile.op()],
          failed: [{Reconcile.op(), Linx.Sysctl.Error.t()}],
          pending: [Reconcile.op()],
          last_applied: Reconcile.last_applied()
        }

  defimpl Inspect do
    def inspect(%Linx.Sysctl.Reconcile.Report{} = r, _opts) do
      parts =
        []
        |> add(length(r.applied) > 0, "#{length(r.applied)} applied")
        |> add(length(r.failed) > 0, "#{length(r.failed)} failed")
        |> add(length(r.pending) > 0, "#{length(r.pending)} pending")

      body = if parts == [], do: "no-op", else: Enum.join(parts, ", ")
      tag = if r.converged?, do: "converged: ", else: ""
      "#Linx.Sysctl.Reconcile.Report<#{tag}#{body}>"
    end

    defp add(list, true, item), do: list ++ [item]
    defp add(list, false, _item), do: list
  end
end
