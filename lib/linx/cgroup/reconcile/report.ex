defmodule Linx.Cgroup.Reconcile.Report do
  @moduledoc """
  The outcome of one `Linx.Cgroup.Reconcile.reconcile/4` pass.

  cgroup limit writes are independent per interface file, so the pass is
  **best-effort**: every op is attempted, and any that error land in `:failed`
  rather than aborting the rest. (It shares the report shape of
  `Linx.Sysctl.Reconcile.Report` and `Linx.Netlink.Rtnl.Reconcile.Report`; the
  struct is uniform, the strategy is per subsystem — see the reconcile design
  notes.)

  Fields:

    * `:converged?` — `true` iff nothing was left undone: no ops were needed, or
      every op applied.
    * `:applied` — ops that succeeded this pass, in attempt order.
    * `:failed` — `{op, %Linx.Cgroup.Error{}}` pairs for ops that errored.
    * `:pending` — always `[]` for cgroup (best-effort attempts everything);
      the field exists for shape-parity with fail-fast subsystems.
    * `:last_applied` — the **updated** ownership map to thread into the next
      pass (see `Linx.Cgroup.Reconcile`). Carrying it here lets a loop do
      `{:ok, report} = reconcile(cg, desired, report.last_applied)` each tick.

  ## Inspect

      #Linx.Cgroup.Reconcile.Report<converged: 2 applied>
      #Linx.Cgroup.Reconcile.Report<1 applied, 1 failed>
  """

  alias Linx.Cgroup.Reconcile

  @enforce_keys [:converged?, :applied, :failed, :pending, :last_applied]
  defstruct [:converged?, :applied, :failed, :pending, :last_applied]

  @type t :: %__MODULE__{
          converged?: boolean(),
          applied: [Reconcile.op()],
          failed: [{Reconcile.op(), Linx.Cgroup.Error.t()}],
          pending: [Reconcile.op()],
          last_applied: Reconcile.last_applied()
        }

  defimpl Inspect do
    def inspect(%Linx.Cgroup.Reconcile.Report{} = r, _opts) do
      parts =
        []
        |> add(length(r.applied) > 0, "#{length(r.applied)} applied")
        |> add(length(r.failed) > 0, "#{length(r.failed)} failed")
        |> add(length(r.pending) > 0, "#{length(r.pending)} pending")

      body = if parts == [], do: "no-op", else: Enum.join(parts, ", ")
      tag = if r.converged?, do: "converged: ", else: ""
      "#Linx.Cgroup.Reconcile.Report<#{tag}#{body}>"
    end

    defp add(list, true, item), do: list ++ [item]
    defp add(list, false, _item), do: list
  end
end
