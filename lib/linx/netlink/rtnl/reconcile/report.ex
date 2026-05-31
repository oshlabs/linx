defmodule Linx.Netlink.Rtnl.Reconcile.Report do
  @moduledoc """
  The outcome of one `Linx.Netlink.Rtnl.Reconcile.reconcile/4` pass.

  rtnl ops are ordered (addresses must exist before the routes that use them),
  so a pass is **fail-fast**: it stops at the first op that errors, and the ops
  it had not yet reached become `:pending`. The level-triggered next pass
  re-converges them. (This is the same report shape as
  `Linx.Sysctl.Reconcile.Report`; the strategy differs because rtnl ops are
  ordered where sysctl's are independent — see the reconcile design notes.)

  Fields:

    * `:converged?` — `true` iff nothing was left undone (`:failed` and
      `:pending` both empty).
    * `:applied` — ops that succeeded this pass, in apply order. Each is a
      `Linx.Netlink.Rtnl.Diff` op (`{:create | :update | :delete, struct}`).
    * `:failed` — `{op, error}` for the op that stopped the pass (at most one,
      fail-fast).
    * `:pending` — ops not attempted after the failure.
    * `:last_applied` — the **updated** ownership map to thread into the next
      pass: `%{addresses: MapSet.t()}` of `Diff.address_key/1` values. (Routes
      are owned by their `rtm_protocol` tag, so they need no last-applied set.)

  ## Inspect

      #Linx.Netlink.Rtnl.Reconcile.Report<converged: 4 applied>
      #Linx.Netlink.Rtnl.Reconcile.Report<2 applied, 1 failed, 3 pending>
  """

  alias Linx.Netlink.Rtnl.Diff

  @enforce_keys [:converged?, :applied, :failed, :pending, :last_applied]
  defstruct [:converged?, :applied, :failed, :pending, :last_applied]

  @type t :: %__MODULE__{
          converged?: boolean(),
          applied: [Diff.op()],
          failed: [{Diff.op(), term()}],
          pending: [Diff.op()],
          last_applied: %{optional(:addresses) => MapSet.t()}
        }

  defimpl Inspect do
    def inspect(%Linx.Netlink.Rtnl.Reconcile.Report{} = r, _opts) do
      parts =
        []
        |> add(length(r.applied) > 0, "#{length(r.applied)} applied")
        |> add(length(r.failed) > 0, "#{length(r.failed)} failed")
        |> add(length(r.pending) > 0, "#{length(r.pending)} pending")

      body = if parts == [], do: "no-op", else: Enum.join(parts, ", ")
      tag = if r.converged?, do: "converged: ", else: ""
      "#Linx.Netlink.Rtnl.Reconcile.Report<#{tag}#{body}>"
    end

    defp add(list, true, item), do: list ++ [item]
    defp add(list, false, _item), do: list
  end
end
