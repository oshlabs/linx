defmodule Linx.Netlink.Rtnl.Diff do
  @moduledoc """
  Per-resource diffs for rtnetlink — the minimal set of create / update /
  delete operations that converge observed kernel state onto a desired state.

  This is the diff half of declarative reconciliation for rtnl, mirroring
  `Linx.Netfilter.Diff`. It is pure: it operates on lists of decoded structs
  (`%Route{}`, `%Address{}`, …) and returns ops; applying them, observing, and
  ordering across resource types are the reconciler's job (a later phase).

  ## Ops

  Each diff returns a list of `t:op/0`:

    * `{:create, item}` — desired, absent from the kernel. `item` is the
      desired struct to install.
    * `{:update, item}` — present but with a changed mutable value (a route's
      gateway, a neighbour's link-layer address). `item` is the desired struct;
      apply it with the resource's replace verb (`NLM_F_REPLACE`).
    * `{:delete, item}` — owned, present, no longer desired. `item` is the
      *observed* struct (it carries the kernel's index/handle).

  ## Ownership: two-way vs three-way

  A reconciler must delete only what it owns, never another writer's state.
  The kernel gives us the ownership marker for exactly one resource:

    * **Routes — two-way.** `rtm_protocol` tags every route with its origin, so
      ownership lives in the kernel. `routes/3` filters observed routes to a
      given protocol and diffs against that; connected routes
      (`RTPROT_KERNEL`) and other writers' routes simply never enter the
      managed set. Tag desired routes with the same protocol (see
      `Linx.Netlink.Rtnl.Route`'s `:protocol` option).

    * **Everything else — three-way.** `ifaddrmsg`, links, rules, and
      neighbours carry no ownership field, so deletion is gated by a
      `last_applied` key set — the keys this reconciler installed on a previous
      pass (the `kubectl apply` last-applied-configuration trick). Only an
      observed item whose key is in that set and is no longer desired is
      deleted; foreign state that merely appeared is left alone.

  The `last_applied` set is a `MapSet` of the keys returned by this module's
  `*_key/1` functions; it is reconciler-held and never persisted. The
  reconciler rebuilds it each pass from the keys it successfully applied.

  ## Keys (identity) and mutable values

  | Resource | Key | Mutable value (→ `:update`) |
  |---|---|---|
  | Route | `{table, family, dst, dst_len, metric}` | gateway |
  | Address | `{index, family, address, prefixlen}` | — (key is the whole identity) |
  | Neighbour | `{ifindex, dst}` | lladdr |
  | Rule | `{priority, family, src/dst/fwmark/table}` | — |
  | Link | `name` | — (existence only; attribute reconcile is out of scope) |

  Addresses are additionally filtered to `RT_SCOPE_UNIVERSE`, dropping
  `fe80::/64` link-locals the kernel manages itself.

  Desired and observed must be keyed in the same space. Authoring is by
  interface *name*, but `:index`-bearing structs are the diff currency, so the
  reconciler resolves names to indices (from a fresh `Link.list`) before
  diffing — see the reconcile design notes.
  """

  alias Linx.IP
  alias Linx.MAC
  alias Linx.Netlink.Rtnl.Route

  @typedoc "A diff operation. `:create`/`:update` carry the desired struct; `:delete` the observed one."
  @type op :: {:create, struct()} | {:update, struct()} | {:delete, struct()}

  # RT_SCOPE_UNIVERSE — global-scope addresses; link-locals are RT_SCOPE_LINK.
  @rt_scope_universe 0

  # --- generic engine -------------------------------------------------------

  @doc """
  Two-way diff: ownership is encoded in `observed` (already filtered to what we
  own), so every observed item not desired is deletable.

  `key` maps a struct to its identity; `value` maps it to its mutable value
  (default: a constant, i.e. no `:update` ops).
  """
  @spec two_way([struct()], [struct()], (struct() -> term()), (struct() -> term())) :: [op()]
  def two_way(desired, observed, key, value \\ &no_value/1)
      when is_function(key, 1) and is_function(value, 1) do
    deletable = observed |> Enum.map(key) |> MapSet.new()
    compute(desired, observed, deletable, key, value)
  end

  @doc """
  Three-way diff: an observed item is deletable only if its key is in
  `owned_keys` (a `MapSet` of `key/1` values from a previous pass). Foreign
  state is left untouched.
  """
  @spec three_way([struct()], [struct()], MapSet.t(), (struct() -> term()), (struct() -> term())) ::
          [op()]
  def three_way(desired, observed, owned_keys, key, value \\ &no_value/1)
      when is_function(key, 1) and is_function(value, 1) do
    compute(desired, observed, owned_keys, key, value)
  end

  defp compute(desired, observed, deletable, key, value) do
    by_desired = Map.new(desired, &{key.(&1), &1})
    by_observed = Map.new(observed, &{key.(&1), &1})

    creates =
      for {k, item} <- by_desired, not Map.has_key?(by_observed, k), do: {:create, item}

    updates =
      for {k, item} <- by_desired,
          {:ok, obs} <- [Map.fetch(by_observed, k)],
          value.(item) != value.(obs),
          do: {:update, item}

    deletes =
      for {k, obs} <- by_observed,
          MapSet.member?(deletable, k),
          not Map.has_key?(by_desired, k),
          do: {:delete, obs}

    creates ++ updates ++ deletes
  end

  defp no_value(_), do: nil

  # --- routes (two-way, protocol-owned) -------------------------------------

  @doc """
  Diffs desired routes against observed, owning by `protocol` (an
  `rtm_protocol` integer, or the same atoms `Route` accepts). Observed routes
  carrying a different protocol — connected, DHCP, other writers — are ignored.
  """
  @spec routes([Route.t()], [Route.t()], 0..255 | atom()) :: [op()]
  def routes(desired, observed, protocol) do
    want = protocol_int(protocol)
    owned = Enum.filter(observed, &(&1.protocol == want))
    two_way(desired, owned, &route_key/1, &route_value/1)
  end

  @doc """
  Identity of a route: `{table, family, dst, dst_len, metric}`.

  A `dst_len` of 0 is the default route; its `dst` is canonicalised to
  `:default` so a desired default (built with `dst = 0.0.0.0`/`::`) keys the
  same as a kernel-observed one (which omits `RTA_DST`, leaving `dst = nil`).
  """
  @spec route_key(Route.t()) :: term()
  def route_key(%Route{dst_len: 0} = r) do
    {Route.target_table(r), r.family, :default, 0, r.priority || 0}
  end

  def route_key(%Route{} = r) do
    {Route.target_table(r), r.family, ip_key(r.dst), r.dst_len, r.priority || 0}
  end

  defp route_value(%Route{gateway: gw}), do: ip_key(gw)

  # --- addresses (three-way, scope-universe) --------------------------------

  @doc """
  Diffs desired addresses against observed, deleting only owned keys. Observed
  addresses outside `RT_SCOPE_UNIVERSE` (link-locals) are dropped first.
  """
  @spec addresses([struct()], [struct()], MapSet.t()) :: [op()]
  def addresses(desired, observed, owned_keys) do
    universe = Enum.filter(observed, &(&1.scope == @rt_scope_universe))
    three_way(desired, universe, owned_keys, &address_key/1)
  end

  @doc "Identity of an address: `{index, family, address, prefixlen}`."
  @spec address_key(struct()) :: term()
  def address_key(%{index: index, family: family, address: address, prefixlen: prefixlen}) do
    {index, family, ip_key(address), prefixlen}
  end

  # --- neighbours (three-way, lladdr is the mutable value) ------------------

  @doc "Diffs desired neighbours against observed, deleting only owned keys."
  @spec neighbours([struct()], [struct()], MapSet.t()) :: [op()]
  def neighbours(desired, observed, owned_keys) do
    three_way(desired, observed, owned_keys, &neighbour_key/1, &neighbour_value/1)
  end

  @doc "Identity of a neighbour: `{ifindex, dst}`."
  @spec neighbour_key(struct()) :: term()
  def neighbour_key(%{ifindex: ifindex, dst: dst}), do: {ifindex, ip_key(dst)}

  defp neighbour_value(%{lladdr: lladdr}), do: mac_key(lladdr)

  # --- rules (three-way) ----------------------------------------------------

  @doc "Diffs desired policy-routing rules against observed, deleting only owned keys."
  @spec rules([struct()], [struct()], MapSet.t()) :: [op()]
  def rules(desired, observed, owned_keys) do
    three_way(desired, observed, owned_keys, &rule_key/1)
  end

  @doc "Identity of a rule: priority, family, selectors, and target table."
  @spec rule_key(struct()) :: term()
  def rule_key(rule) do
    {rule.priority, rule.family, ip_key(rule.src), rule.src_len, ip_key(rule.dst), rule.dst_len,
     rule.fwmark, Linx.Netlink.Rtnl.Rule.target_table(rule)}
  end

  # --- links (three-way, existence only) ------------------------------------

  @doc """
  Diffs desired links against observed by name, deleting only owned names.

  Existence only — reconciling link *attributes* (MTU, admin state, address)
  is a separate concern and out of scope here.
  """
  @spec links([struct()], [struct()], MapSet.t()) :: [op()]
  def links(desired, observed, owned_keys) do
    three_way(desired, observed, owned_keys, &link_key/1)
  end

  @doc "Identity of a link: its `name`."
  @spec link_key(struct()) :: term()
  def link_key(%{name: name}), do: name

  # --- helpers --------------------------------------------------------------

  defp ip_key(nil), do: nil
  defp ip_key(%IP{} = ip), do: IP.to_string(ip)

  defp mac_key(nil), do: nil
  defp mac_key(%MAC{} = mac), do: MAC.to_string(mac)

  defp protocol_int(p) when is_integer(p), do: p

  defp protocol_int(a) when is_atom(a) do
    case a do
      :redirect -> 1
      :kernel -> 2
      :boot -> 3
      :static -> 4
      :ra -> 9
      :dhcp -> 16
    end
  end
end
