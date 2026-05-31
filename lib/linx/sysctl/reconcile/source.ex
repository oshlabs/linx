defmodule Linx.Sysctl.Reconcile.Source do
  @moduledoc """
  `Linx.Reconcile.Source` adapter for sysctls — lets the generic
  `Linx.Reconcile` loop drive `Linx.Sysctl.Reconcile`.

  The `scope` is the sysctl `:in` target (`:self`, `{:pid, n}`, `{:path, p}`),
  forwarded as the `:in` option of each pass. Sysctl has no kernel multicast,
  so `subscribe/2` returns `:unsupported` — the loop runs timer-only, which is
  exactly right for a subsystem that never changes behind your back.

  This is a thin delegation; for direct control use `Linx.Sysctl.Reconcile`.
  """

  @behaviour Linx.Reconcile.Source

  alias Linx.Sysctl.Reconcile

  @impl true
  def reconcile(scope, desired, last_applied, opts) do
    Reconcile.reconcile(desired, last_applied, Keyword.put(opts, :in, scope))
  end

  @impl true
  def subscribe(_scope, _owner), do: :unsupported
end
