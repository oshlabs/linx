defmodule Linx.Netlink.Rtnl.Reconcile do
  @moduledoc """
  Single-shot declarative reconciliation for rtnetlink — observe the kernel,
  diff against a desired state, and apply the minimal change, in one
  caller-driven pass scoped to the socket's network namespace.

  This is the mechanism half of declarative networking: it holds no long-lived
  state and owns no process. The cadence, persistence, and supervision are the
  consumer's (see the reconcile design notes). It composes
  `Linx.Netlink.Rtnl.Diff` (the per-resource diffs) and the `Route`/`Address`
  actuation verbs into an ordered apply pass.

  ## Scope

  This pass reconciles **addresses and routes** on interfaces that already
  exist in the namespace. Link lifecycle (creating veth/ipvlan, MTU, admin
  state) is kind-specific and belongs to the composite/consumer; rules and
  neighbours reuse the same `Diff` engine and slot in the same way. Interfaces
  are observed (to resolve names to indices) but not created or deleted here.

  ## Desired state

  A map authored by interface **name** (indices are ephemeral, so you never
  write them down — they are resolved against a fresh link list each pass):

      %{
        addresses: [
          {"eth0", "10.0.0.2", 24},
          {"eth0", "fc00::1", 64}
        ],
        routes: [
          {"10.50.0.0", 24, "10.0.0.1"},
          {"10.60.0.0", 24, "10.0.0.1", table: 100, metric: 50},
          {:default, "10.0.0.1"}
        ]
      }

  Address entries are `{interface, ip, prefixlen}`. Route entries are
  `{dst, prefix, gateway}` / `{dst, prefix, gateway, opts}` /
  `{:default, gateway}` / `{:default, gateway, opts}`, where `opts` is
  `Route`'s `:table`/`:metric` (the `:protocol` is forced to this
  reconciler's ownership tag).

  ## Ownership

  Routes are owned by `rtm_protocol`: every route this reconciler installs is
  tagged with `:protocol` (default `default_protocol/0`), and the route diff
  considers only observed routes carrying that tag — connected routes and
  other writers are invisible to it, and never deleted. Addresses have no
  ownership field, so they are owned three-way via the `last_applied` set
  threaded between passes (foreign addresses that merely appeared are left
  alone). See `Linx.Netlink.Rtnl.Diff`.

  ## Strategy and ordering

  Apply order follows the kernel's layering: address creates first (so a
  route's gateway is reachable), then route creates/updates, then route
  deletes, then address deletes. The pass is **fail-fast** — it stops at the
  first error and reports the rest as pending; the next pass re-converges.

  ## Example

      {:ok, sock} = Rtnl.open()

      desired = %{
        addresses: [{"eth0", "10.0.0.2", 24}],
        routes: [{:default, "10.0.0.1"}]
      }

      {:ok, r} = Reconcile.reconcile(sock, desired)
      r.converged?
      {:ok, r2} = Reconcile.reconcile(sock, desired, r.last_applied)  # idempotent
  """

  alias Linx.IP
  alias Linx.Netlink.Socket
  alias Linx.Netlink.Rtnl.{Address, Diff, Link, Route}
  alias Linx.Netlink.Rtnl.Reconcile.Report

  # RTPROT for routes this reconciler owns. 76 = ASCII 'L' (Linx) — an
  # otherwise-unassigned rtm_protocol value. Override with the :protocol option
  # when several reconcilers share a namespace.
  @rtprot_linx 76

  @af_inet 2
  @af_inet6 10
  @rt_scope_universe 0

  @typedoc "Address entry: `{interface_name, ip, prefixlen}`."
  @type address_spec :: {String.t(), binary() | IP.t(), non_neg_integer()}

  @typedoc "Route entry — see the moduledoc."
  @type route_spec ::
          {binary() | IP.t(), non_neg_integer(), binary() | IP.t()}
          | {binary() | IP.t(), non_neg_integer(), binary() | IP.t(), keyword()}
          | {:default, binary() | IP.t()}
          | {:default, binary() | IP.t(), keyword()}

  @typedoc "Desired state, authored by interface name."
  @type desired :: %{
          optional(:addresses) => [address_spec()],
          optional(:routes) => [route_spec()]
        }

  @typedoc "Reconciler-held ownership, threaded between passes."
  @type last_applied :: %{optional(:addresses) => MapSet.t()}

  @doc "The default route-ownership `rtm_protocol` (76, ASCII 'L')."
  @spec default_protocol() :: pos_integer()
  def default_protocol, do: @rtprot_linx

  @doc """
  Runs one reconcile pass against `desired` in the socket's namespace.

  Returns `{:ok, %Report{}}` — per-op kernel failures live in the report's
  `:failed`, since a partial apply is a normal transient state the next pass
  corrects. Returns `{:error, {:normalize, reason}}` if the desired state is
  invalid (an unknown interface, an unparseable address, a family mismatch) —
  nothing is applied in that case. Returns `{:error, term}` if observing the
  kernel fails.

  ## Options

    * `:protocol` — the route-ownership tag (integer or a `Route` protocol
      atom). Default `default_protocol/0`.
  """
  @spec reconcile(Socket.t(), desired(), last_applied(), keyword()) ::
          {:ok, Report.t()} | {:error, term()}
  def reconcile(socket, desired, last_applied \\ %{}, opts \\ [])
      when is_map(desired) and is_map(last_applied) and is_list(opts) do
    protocol = Keyword.get(opts, :protocol, @rtprot_linx)

    with {:ok, links} <- Link.list(socket),
         by_name = Map.new(links, &{&1.name, &1.index}),
         by_index = Map.new(links, &{&1.index, &1.name}),
         {:ok, norm} <- normalize(desired, by_name, protocol),
         {:ok, observed_addrs} <- Address.list(socket),
         {:ok, observed_routes} <- Route.list(socket) do
      owned_addrs = Map.get(last_applied, :addresses, MapSet.new())

      addr_ops = Diff.addresses(norm.addresses, observed_addrs, owned_addrs)
      route_ops = Diff.routes(norm.routes, observed_routes, protocol)
      ordered = order_ops(addr_ops, route_ops)

      {applied, failed, pending} = run(ordered, socket, by_index, protocol)
      new_owned = recompute_owned(owned_addrs, applied)

      {:ok,
       %Report{
         converged?: failed == [] and pending == [],
         applied: applied,
         failed: failed,
         pending: pending,
         last_applied: %{addresses: new_owned}
       }}
    end
  end

  @doc false
  # Orders diff ops by the kernel's L2->L3 layering: bring addresses up before
  # the routes that depend on them, and tear routes down before the addresses
  # they used. Pure.
  @spec order_ops([Diff.op()], [Diff.op()]) :: [Diff.op()]
  def order_ops(addr_ops, route_ops) do
    creates(addr_ops) ++
      creates(route_ops) ++ updates(route_ops) ++ deletes(route_ops) ++ deletes(addr_ops)
  end

  defp creates(ops), do: for(op <- ops, match?({:create, _}, op), do: op)
  defp updates(ops), do: for(op <- ops, match?({:update, _}, op), do: op)
  defp deletes(ops), do: for(op <- ops, match?({:delete, _}, op), do: op)

  # --- apply (fail-fast) ----------------------------------------------------

  defp run(ops, socket, by_index, protocol), do: run(ops, socket, by_index, protocol, [])

  defp run([], _socket, _by_index, _protocol, applied), do: {Enum.reverse(applied), [], []}

  defp run([op | rest], socket, by_index, protocol, applied) do
    case apply_op(op, socket, by_index, protocol) do
      :ok -> run(rest, socket, by_index, protocol, [op | applied])
      {:error, err} -> {Enum.reverse(applied), [{op, err}], rest}
    end
  end

  defp apply_op({:create, %Address{} = a}, socket, by_index, _protocol) do
    Address.add(socket, by_index[a.index], a.address, a.prefixlen)
  end

  defp apply_op({:delete, %Address{} = a}, socket, by_index, _protocol) do
    case by_index[a.index] do
      # The interface is gone, so the address is too — nothing to delete.
      nil -> :ok
      name -> Address.delete(socket, name, a.address, a.prefixlen)
    end
  end

  # Create and update both go through replace/5 (NLM_F_CREATE | NLM_F_REPLACE):
  # idempotent install-or-overwrite, the reconciler's apply verb.
  defp apply_op({op, %Route{} = r}, socket, _by_index, protocol) when op in [:create, :update] do
    Route.replace(socket, route_dst(r), r.dst_len, r.gateway, route_opts(r, protocol))
  end

  defp apply_op({:delete, %Route{} = r}, socket, _by_index, protocol) do
    Route.delete(socket, route_dst(r), r.dst_len, r.gateway, route_opts(r, protocol))
  end

  defp route_dst(%Route{dst_len: 0, family: family}), do: default_destination(family)
  defp route_dst(%Route{dst: dst}), do: dst

  defp route_opts(%Route{} = r, protocol) do
    [table: Route.target_table(r), protocol: protocol]
    |> maybe_put(:metric, r.priority)
  end

  defp maybe_put(opts, _key, nil), do: opts
  defp maybe_put(opts, key, value), do: Keyword.put(opts, key, value)

  # Address ownership after a pass: only the ops that actually ran changed the
  # kernel, so start from the prior set and apply just the applied creates and
  # deletes. Failed/pending keys keep their prior ownership (retried next pass).
  defp recompute_owned(owned, applied) do
    Enum.reduce(applied, owned, fn
      {:create, %Address{} = a}, acc -> MapSet.put(acc, Diff.address_key(a))
      {:delete, %Address{} = a}, acc -> MapSet.delete(acc, Diff.address_key(a))
      _op, acc -> acc
    end)
  end

  # --- normalize (desired-by-name -> index-bearing structs) -----------------

  @doc false
  @spec normalize(desired(), %{optional(String.t()) => integer()}, 0..255 | atom()) ::
          {:ok, %{addresses: [Address.t()], routes: [Route.t()]}} | {:error, {:normalize, term()}}
  def normalize(desired, by_name, protocol) do
    with {:ok, addresses} <- normalize_addresses(Map.get(desired, :addresses, []), by_name),
         {:ok, routes} <- normalize_routes(Map.get(desired, :routes, []), protocol) do
      {:ok, %{addresses: addresses, routes: routes}}
    end
  end

  defp normalize_addresses(specs, by_name) do
    reduce_ok(specs, fn {ifname, ip, prefixlen} ->
      with {:ok, index} <- resolve_index(ifname, by_name),
           {:ok, %IP{family: family} = parsed} <- coerce_ip(ip) do
        {:ok,
         %Address{
           family: family_int(family),
           index: index,
           address: parsed,
           prefixlen: prefixlen,
           scope: @rt_scope_universe
         }}
      end
    end)
  end

  defp normalize_routes(specs, protocol) do
    reduce_ok(specs, fn spec -> normalize_route(spec, protocol) end)
  end

  defp normalize_route({:default, gateway}, protocol),
    do: normalize_route({:default, gateway, []}, protocol)

  defp normalize_route({:default, gateway, opts}, protocol) do
    with {:ok, %IP{family: family}} <- coerce_ip(gateway) do
      build_route(default_destination(family), 0, gateway, opts, protocol)
    end
  end

  defp normalize_route({dst, prefix, gateway}, protocol),
    do: build_route(dst, prefix, gateway, [], protocol)

  defp normalize_route({dst, prefix, gateway, opts}, protocol),
    do: build_route(dst, prefix, gateway, opts, protocol)

  defp build_route(dst, prefix, gateway, opts, protocol) do
    opts = Keyword.put(opts, :protocol, protocol)

    case Route.build(dst, prefix, gateway, @rt_scope_universe, opts) do
      {:ok, route} -> {:ok, route}
      {:error, reason} -> {:error, {:normalize, {:route, reason}}}
    end
  end

  defp resolve_index(ifname, by_name) do
    case Map.fetch(by_name, ifname) do
      {:ok, index} -> {:ok, index}
      :error -> {:error, {:normalize, {:unknown_interface, ifname}}}
    end
  end

  defp coerce_ip(%IP{} = ip), do: {:ok, ip}

  defp coerce_ip(string) when is_binary(string) do
    case IP.parse(string) do
      {:ok, ip} -> {:ok, ip}
      {:error, reason} -> {:error, {:normalize, {:bad_address, reason}}}
    end
  end

  # Maps fun over the list, short-circuiting on the first {:error, _}.
  defp reduce_ok(list, fun) do
    Enum.reduce_while(list, {:ok, []}, fn item, {:ok, acc} ->
      case fun.(item) do
        {:ok, value} -> {:cont, {:ok, [value | acc]}}
        {:error, _} = error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, acc} -> {:ok, Enum.reverse(acc)}
      {:error, _} = error -> error
    end
  end

  # Accepts both the atom family (from a parsed IP, in normalize) and the int
  # family (from a built %Route{}, in apply).
  defp default_destination(f) when f in [:inet, @af_inet], do: "0.0.0.0"
  defp default_destination(f) when f in [:inet6, @af_inet6], do: "::"

  defp family_int(:inet), do: @af_inet
  defp family_int(:inet6), do: @af_inet6
end
