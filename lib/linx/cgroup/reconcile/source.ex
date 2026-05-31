defmodule Linx.Cgroup.Reconcile.Source do
  @moduledoc """
  `Linx.Reconcile.Source` adapter for cgroup limits — lets the generic
  `Linx.Reconcile` loop drive `Linx.Cgroup.Reconcile`.

  The `scope` is the cgroup path (e.g. `"/sys/fs/cgroup/myorg/web-42"`).
  cgroupfs has no change-notification multicast, so `subscribe/2` returns
  `:unsupported` — the loop runs timer-only, which suits limit knobs that only
  change when something writes them.

  Reconciling the cgroup's *limits* is mechanism; its *existence* and
  *membership* are lifecycle the consumer's composite owns. A loop pointed at a
  not-yet-created cgroup simply reports the writes as failed until the composite
  creates it — it never tries to create it itself.

  This is a thin delegation; for direct control use `Linx.Cgroup.Reconcile`.
  """

  @behaviour Linx.Reconcile.Source

  alias Linx.Cgroup.Reconcile

  @impl true
  def reconcile(scope, desired, last_applied, opts) do
    Reconcile.reconcile(scope, desired, last_applied, opts)
  end

  @impl true
  def subscribe(_scope, _owner), do: :unsupported
end
