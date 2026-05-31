defmodule Linx.Netlink.Rtnl.Reconcile.Source do
  @moduledoc """
  `Linx.Reconcile.Source` adapter for rtnetlink — lets the generic
  `Linx.Reconcile` loop drive `Linx.Netlink.Rtnl.Reconcile` and
  `Linx.Netlink.Rtnl.Monitor`.

  The `scope` is a `t:Linx.Netlink.Socket.netns/0` (`:host`, `{:pid, n}`,
  `{:path, p}`). Each pass opens a short-lived rtnetlink socket in that
  namespace, runs the ordered single-shot reconcile, and closes it — so the
  loop owns no socket lifecycle, and the per-namespace scoping that makes
  reconcilers unable to fight each other (see the reconcile design notes) falls
  out for free. `subscribe/2` starts a `Monitor` on the same namespace for
  low-latency wakeups; on `ENOBUFS` it emits `:resync_needed`, which the loop
  treats like any other hint — look now, re-diff full state.

  This is a thin delegation; for direct control use `Linx.Netlink.Rtnl.Reconcile`.
  """

  @behaviour Linx.Reconcile.Source

  alias Linx.Netlink.{Rtnl, Socket}
  alias Linx.Netlink.Rtnl.{Address, Monitor, Reconcile, Route}

  @impl true
  def reconcile(scope, desired, last_applied, opts) do
    with_socket(scope, fn sock -> Reconcile.reconcile(sock, desired, last_applied, opts) end)
  end

  @impl true
  def subscribe(scope, owner), do: Monitor.subscribe(owner, netns: scope)

  @impl true
  def observe(scope, _opts) do
    with_socket(scope, fn sock ->
      with {:ok, addresses} <- Address.list(sock),
           {:ok, routes} <- Route.list(sock) do
        {:ok, %{addresses: addresses, routes: routes}}
      end
    end)
  end

  # Opens a socket in `scope`, runs `fun`, and always closes it.
  defp with_socket(scope, fun) do
    case Rtnl.open(scope) do
      {:ok, sock} ->
        try do
          fun.(sock)
        after
          Socket.close(sock)
        end

      {:error, _} = error ->
        error
    end
  end
end
