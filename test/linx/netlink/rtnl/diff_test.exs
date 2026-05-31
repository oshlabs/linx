defmodule Linx.Netlink.Rtnl.DiffTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  import Linx.IP
  import Linx.MAC

  alias Linx.Netlink.Rtnl.{Address, Diff, Link, Neighbour, Route, Rule}

  # --- generic engine properties --------------------------------------------
  #
  # Exercised with plain maps: key = & &1.k, value = & &1.v.

  # A small key space (0..15) so desired/observed overlap often, exercising
  # updates and deletes. Built from a list of pairs (collisions collapse,
  # last-wins) rather than `map_of`, whose unique-key retry trips
  # `TooManyDuplicatesError` on so few possible keys.
  defp kv_map do
    map(list_of(tuple({integer(0..15), integer(0..3)}), max_length: 10), &Map.new/1)
  end
  defp items(m), do: Enum.map(m, fn {k, v} -> %{k: k, v: v} end)
  defp keyset(m), do: m |> Map.keys() |> MapSet.new()

  property "diffing a state against itself yields no ops" do
    check all(m <- kv_map()) do
      assert Diff.two_way(items(m), items(m), & &1.k, & &1.v) == []
    end
  end

  property "two-way: creates and deletes partition by key set; updates are differing shared keys" do
    check all(dm <- kv_map(), om <- kv_map()) do
      ops = Diff.two_way(items(dm), items(om), & &1.k, & &1.v)

      created = for({:create, i} <- ops, do: i.k) |> MapSet.new()
      deleted = for({:delete, i} <- ops, do: i.k) |> MapSet.new()
      updated = for({:update, i} <- ops, do: i.k) |> MapSet.new()

      assert created == MapSet.difference(keyset(dm), keyset(om))
      assert deleted == MapSet.difference(keyset(om), keyset(dm))

      shared = MapSet.intersection(keyset(dm), keyset(om))
      expected_updates = for k <- shared, dm[k] != om[k], into: MapSet.new(), do: k
      assert updated == expected_updates
    end
  end

  property "three-way: deletes are exactly (observed − desired) ∩ owned; foreign state is left" do
    check all(dm <- kv_map(), om <- kv_map(), owned <- list_of(integer(0..15))) do
      owned_set = MapSet.new(owned)
      ops = Diff.three_way(items(dm), items(om), owned_set, & &1.k, & &1.v)

      deleted = for({:delete, i} <- ops, do: i.k) |> MapSet.new()
      expected = MapSet.intersection(MapSet.difference(keyset(om), keyset(dm)), owned_set)
      assert deleted == expected
      assert MapSet.subset?(deleted, owned_set)
    end
  end

  property "three-way creates/updates ignore ownership (only deletes are gated)" do
    check all(dm <- kv_map(), om <- kv_map()) do
      # With nothing owned, no deletes — but creates/updates still happen.
      ops = Diff.three_way(items(dm), items(om), MapSet.new(), & &1.k, & &1.v)
      assert [] == for({:delete, _} <- ops, do: :x)
      created = for({:create, i} <- ops, do: i.k) |> MapSet.new()
      assert created == MapSet.difference(keyset(dm), keyset(om))
    end
  end

  # Reference apply: fold ops over the observed-by-key map exactly as a
  # reconciler would (create/update put, delete drops). Convergence is the
  # property that actually matters — the op-set tests above only describe the
  # ops, not that applying them reaches the goal.
  defp apply_ops(observed, ops, keyfn) do
    base = Map.new(observed, &{keyfn.(&1), &1})

    Enum.reduce(ops, base, fn
      {:create, i}, acc -> Map.put(acc, keyfn.(i), i)
      {:update, i}, acc -> Map.put(acc, keyfn.(i), i)
      {:delete, o}, acc -> Map.delete(acc, keyfn.(o))
    end)
  end

  property "two-way: applying the ops converges to desired, and a re-diff is empty" do
    check all(dm <- kv_map(), om <- kv_map()) do
      key = & &1.k
      val = & &1.v
      ops = Diff.two_way(items(dm), items(om), key, val)
      post = apply_ops(items(om), ops, key)

      # The post-state is exactly desired, keyed.
      assert post == Map.new(items(dm), &{key.(&1), &1})
      # And the loop has reached a fixpoint: nothing left to do.
      assert Diff.two_way(items(dm), Map.values(post), key, val) == []
    end
  end

  property "three-way: applying converges desired, preserves foreign state, reaches a fixpoint" do
    check all(dm <- kv_map(), om <- kv_map(), owned <- list_of(integer(0..15))) do
      key = & &1.k
      val = & &1.v
      owned_set = MapSet.new(owned)
      ops = Diff.three_way(items(dm), items(om), owned_set, key, val)
      post = apply_ops(items(om), ops, key)

      # Every desired item is present with its desired value.
      for d <- items(dm), do: assert(post[d.k] == d)

      # Foreign observed items (not owned, not desired) are untouched.
      for {k, o} <- Map.new(items(om), &{&1.k, &1}),
          not MapSet.member?(owned_set, k),
          not Map.has_key?(dm, k),
          do: assert(post[k] == o)

      # Re-diffing with the same ownership leaves only foreign-cleanup nothing:
      # desired is satisfied, so no create/update remains.
      redo = Diff.three_way(items(dm), Map.values(post), owned_set, key, val)
      assert [] == for({op, _} <- redo, op in [:create, :update], do: :x)
    end
  end

  # --- routes: two-way, protocol-owned --------------------------------------

  defp route(dst, len, gw, opts) do
    {:ok, r} = Route.build(dst, len, gw, 0, opts)
    r
  end

  describe "routes/3" do
    test "owns only its protocol; foreign-protocol routes never enter the diff" do
      desired = [route("10.1.0.0", 24, "10.0.0.1", protocol: :static)]

      observed = [
        route("10.1.0.0", 24, "10.0.0.1", protocol: :static),
        route("10.2.0.0", 24, "10.0.0.9", protocol: :kernel),
        route("10.3.0.0", 24, "10.0.0.1", protocol: :static)
      ]

      ops = Diff.routes(desired, observed, :static)
      # 10.1 matches (no-op), 10.2 is foreign (ignored), 10.3 is ours but
      # unwanted (delete).
      assert [{:delete, %Route{dst: ~IP"10.3.0.0"}}] = ops
    end

    test "a changed gateway is an :update, not delete+create" do
      desired = [route("10.1.0.0", 24, "10.0.0.2", protocol: :static)]
      observed = [route("10.1.0.0", 24, "10.0.0.1", protocol: :static)]

      assert [{:update, %Route{gateway: gw}}] = Diff.routes(desired, observed, :static)
      assert gw == ~IP"10.0.0.2"
    end

    test "protocol may be given as an integer" do
      desired = [route("10.1.0.0", 24, "10.0.0.1", protocol: 4)]
      observed = []
      assert [{:create, %Route{}}] = Diff.routes(desired, observed, 4)
    end
  end

  describe "route_key/1" do
    test "metric is part of the key (two metrics = two routes)" do
      refute Diff.route_key(route("10.1.0.0", 24, "10.0.0.1", metric: 100)) ==
               Diff.route_key(route("10.1.0.0", 24, "10.0.0.1", metric: 200))
    end

    test "a built default route keys the same as a kernel-observed one (nil dst)" do
      built = route("0.0.0.0", 0, "10.0.0.1", [])
      observed = %Route{family: 2, dst_len: 0, dst: nil, table: 254, priority: nil}
      assert Diff.route_key(built) == Diff.route_key(observed)
    end
  end

  # --- addresses: three-way, scope-universe ---------------------------------

  defp addr(index, ip, prefixlen, scope \\ 0) do
    {:ok, parsed} = Linx.IP.parse(ip)

    %Address{
      family: parsed.family,
      index: index,
      address: parsed,
      prefixlen: prefixlen,
      scope: scope
    }
  end

  describe "addresses/3" do
    test "deletes only owned addresses; foreign ones that appeared are kept" do
      desired = [addr(2, "10.0.0.2", 24)]

      observed = [
        addr(2, "10.0.0.2", 24),
        # ours from a prior pass, no longer desired -> delete
        addr(2, "10.0.0.3", 24),
        # appeared from elsewhere, not owned -> keep
        addr(2, "10.0.0.9", 24)
      ]

      owned =
        MapSet.new([
          Diff.address_key(addr(2, "10.0.0.2", 24)),
          Diff.address_key(addr(2, "10.0.0.3", 24))
        ])

      ops = Diff.addresses(desired, observed, owned)
      assert [{:delete, %Address{address: ~IP"10.0.0.3"}}] = ops
    end

    test "link-local (non-universe scope) addresses are filtered out of observed" do
      desired = []
      # RT_SCOPE_LINK = 253; a fe80::/64 link-local the kernel manages.
      observed = [addr(2, "fe80::1", 64, 253)]
      owned = MapSet.new([Diff.address_key(addr(2, "fe80::1", 64, 253))])

      # Even though it's "owned" and not desired, scope filtering drops it.
      assert [] == Diff.addresses(desired, observed, owned)
    end
  end

  # --- neighbours: three-way, lladdr is the mutable value -------------------

  defp neigh(ifindex, ip, mac) do
    {:ok, dst} = Linx.IP.parse(ip)
    {:ok, lladdr} = Linx.MAC.parse(mac)
    %Neighbour{family: dst.family, ifindex: ifindex, dst: dst, lladdr: lladdr}
  end

  test "neighbours/3 emits :update when the link-layer address changes" do
    desired = [neigh(2, "10.0.0.5", "02:00:00:00:00:02")]
    observed = [neigh(2, "10.0.0.5", "02:00:00:00:00:01")]
    owned = MapSet.new([Diff.neighbour_key(neigh(2, "10.0.0.5", "02:00:00:00:00:01"))])

    assert [{:update, %Neighbour{lladdr: ~MAC"02:00:00:00:00:02"}}] =
             Diff.neighbours(desired, observed, owned)
  end

  # --- rules / links: three-way existence -----------------------------------

  test "rules/3 keys by priority, family, selectors and table" do
    {:ok, src} = Linx.IP.parse("10.0.0.0")
    r = %Rule{family: 2, priority: 100, src: src, src_len: 24, table: 100}
    desired = [r]
    observed = [%Rule{family: 2, priority: 200, src: src, src_len: 24, table: 100}]
    owned = MapSet.new([Diff.rule_key(Enum.at(observed, 0))])

    ops = Diff.rules(desired, observed, owned)
    assert Enum.any?(ops, &match?({:create, %Rule{priority: 100}}, &1))
    assert Enum.any?(ops, &match?({:delete, %Rule{priority: 200}}, &1))
  end

  test "links/3 keys by name and deletes only owned names" do
    desired = [%Link{name: "iv0"}]
    observed = [%Link{name: "iv0"}, %Link{name: "eth0"}, %Link{name: "iv1"}]
    # Only the linx-created interfaces are owned; eth0 is foreign.
    owned = MapSet.new(["iv0", "iv1"])

    ops = Diff.links(desired, observed, owned)
    assert [{:delete, %Link{name: "iv1"}}] = ops
  end
end
