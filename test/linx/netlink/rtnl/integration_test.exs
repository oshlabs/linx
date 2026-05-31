defmodule Linx.Netlink.Rtnl.IntegrationTest do
  @moduledoc """
  Exercises the mutating rtnetlink verbs against the live kernel.

  Each test runs in its own throwaway network namespace, created with
  `ip netns` — so it needs root and `iproute2`, and is tagged `:integration`
  (excluded from the default `mix test`). The namespace is seeded with a
  `dummy0` interface to act as a macvlan/ipvlan parent.
  """
  use ExUnit.Case, async: false

  import Linx.IP
  import Linx.MAC
  alias Linx.Netlink.{Error, Rtnl, Socket}
  alias Linx.Netlink.Rtnl.{Address, Link, Neighbour, Route, Rule}

  @moduletag :integration

  setup do
    netns = "linx_test_#{System.unique_integer([:positive])}"

    {_, 0} = System.cmd("ip", ~w(netns add #{netns}), stderr_to_stdout: true)
    on_exit(fn -> System.cmd("ip", ~w(netns del #{netns})) end)

    {_, 0} =
      System.cmd("ip", ~w(-n #{netns} link add dummy0 type dummy), stderr_to_stdout: true)

    netns_path = "/var/run/netns/#{netns}"
    {:ok, socket} = Rtnl.open({:path, netns_path})
    on_exit(fn -> Socket.close(socket) end)

    %{socket: socket, netns_path: netns_path}
  end

  test "set_up/2 and set_down/2 toggle a link's administrative state", %{socket: socket} do
    assert :ok = Link.set_up(socket, "dummy0")
    assert {:ok, link} = Link.get(socket, "dummy0")
    assert Link.up?(link)

    assert :ok = Link.set_down(socket, "dummy0")
    assert {:ok, link} = Link.get(socket, "dummy0")
    refute Link.up?(link)
  end

  test "create_macvlan/4 creates a macvlan on its parent", %{socket: socket} do
    assert :ok = Link.create_macvlan(socket, "mv0", "dummy0", :bridge)

    assert {:ok, %Link{name: "mv0", link: parent}} = Link.get(socket, "mv0")
    assert {:ok, %Link{index: ^parent}} = Link.get(socket, "dummy0")
  end

  test "create_ipvlan/4 creates an ipvlan on its parent", %{socket: socket} do
    assert :ok = Link.create_ipvlan(socket, "iv0", "dummy0", :l3)
    assert {:ok, %Link{name: "iv0"}} = Link.get(socket, "iv0")
  end

  test "delete/2 removes a link", %{socket: socket} do
    assert :ok = Link.create_macvlan(socket, "mv0", "dummy0")
    assert {:ok, _} = Link.get(socket, "mv0")

    assert :ok = Link.delete(socket, "mv0")
    assert {:error, %Error{errno: :enodev}} = Link.get(socket, "mv0")
  end

  test "Address.add/4 assigns an IPv4 address to a link", %{socket: socket} do
    assert :ok = Link.set_up(socket, "dummy0")
    assert :ok = Address.add(socket, "dummy0", "10.99.0.2", 24)
  end

  test "Route.add_default/2 installs a default route", %{socket: socket} do
    assert :ok = Link.set_up(socket, "dummy0")
    assert :ok = Address.add(socket, "dummy0", "10.99.0.2", 24)
    assert :ok = Route.add_default(socket, "10.99.0.1")
  end

  test "Address.add/4 then delete/4 round-trips, visible via list/2",
       %{socket: socket} do
    assert :ok = Link.set_up(socket, "dummy0")
    assert :ok = Address.add(socket, "dummy0", "10.99.0.2", 24)

    {:ok, before} = Address.list(socket, "dummy0")
    assert Enum.any?(before, &(&1.address == ~IP"10.99.0.2"))

    assert :ok = Address.delete(socket, "dummy0", "10.99.0.2", 24)

    {:ok, after_delete} = Address.list(socket, "dummy0")
    refute Enum.any?(after_delete, &(&1.address == ~IP"10.99.0.2"))
  end

  test "Address.add/4 assigns an IPv6 address to a link", %{socket: socket} do
    assert :ok = Link.set_up(socket, "dummy0")
    assert :ok = Address.add(socket, "dummy0", "fc00::1", 64)

    {:ok, addresses} = Address.list(socket, "dummy0")
    assert Enum.any?(addresses, &match?(%Address{family: 10}, &1))
  end

  test "Route.add/4 installs a destination-prefix route, delete/4 removes it",
       %{socket: socket} do
    assert :ok = Link.set_up(socket, "dummy0")
    assert :ok = Address.add(socket, "dummy0", "10.99.0.2", 24)
    assert :ok = Route.add(socket, "10.50.0.0", 24, "10.99.0.1")

    {:ok, routes} = Route.list(socket)

    assert Enum.any?(routes, fn r ->
             r.dst == ~IP"10.50.0.0" and r.gateway == ~IP"10.99.0.1"
           end)

    assert :ok = Route.delete(socket, "10.50.0.0", 24, "10.99.0.1")

    {:ok, after_delete} = Route.list(socket)

    refute Enum.any?(after_delete, fn r ->
             r.dst == ~IP"10.50.0.0" and r.gateway == ~IP"10.99.0.1"
           end)
  end

  # --- M6: link kinds, sub-message dispatch, and link config ----------------

  test "create_veth/3 creates a pair of interfaces", %{socket: socket} do
    assert :ok = Link.create_veth(socket, "v0a", "v0b")

    assert {:ok, %Link{name: "v0a"}} = Link.get(socket, "v0a")
    assert {:ok, %Link{name: "v0b"}} = Link.get(socket, "v0b")
  end

  test "create_vlan/4 creates a VLAN sub-interface on a parent", %{socket: socket} do
    assert :ok = Link.create_vlan(socket, "dummy0.42", "dummy0", 42)

    assert {:ok, %Link{name: "dummy0.42", link: parent}} =
             Link.get(socket, "dummy0.42")

    assert {:ok, %Link{index: ^parent}} = Link.get(socket, "dummy0")
  end

  test "create_bridge/2 and create_dummy/2 work without info_data", %{socket: socket} do
    assert :ok = Link.create_bridge(socket, "br0")
    assert :ok = Link.create_dummy(socket, "dummy1")
    assert {:ok, %Link{name: "br0"}} = Link.get(socket, "br0")
    assert {:ok, %Link{name: "dummy1"}} = Link.get(socket, "dummy1")
  end

  test "set_master/3 enslaves a link to a bridge", %{socket: socket} do
    assert :ok = Link.create_bridge(socket, "br0")
    assert :ok = Link.create_dummy(socket, "dummy1")
    assert {:ok, %Link{index: br_index}} = Link.get(socket, "br0")

    assert :ok = Link.set_master(socket, "dummy1", "br0")
    assert {:ok, %Link{master: ^br_index}} = Link.get(socket, "dummy1")
  end

  test "set_mtu/3 changes a link's MTU", %{socket: socket} do
    assert :ok = Link.set_mtu(socket, "dummy0", 1400)
    assert {:ok, %Link{mtu: 1400}} = Link.get(socket, "dummy0")
  end

  test "set_name/3 renames a link", %{socket: socket} do
    assert :ok = Link.set_name(socket, "dummy0", "renamed0")
    assert {:ok, %Link{name: "renamed0"}} = Link.get(socket, "renamed0")
  end

  test "set_address/3 changes a link's MAC address", %{socket: socket} do
    assert :ok = Link.set_address(socket, "dummy0", "02:11:22:33:44:55")

    assert {:ok, %Link{address: ~MAC"02:11:22:33:44:55"}} = Link.get(socket, "dummy0")
  end

  test "decoded macvlan link carries its kind and mode via the dispatch DSL",
       %{socket: socket} do
    assert :ok = Link.create_macvlan(socket, "mv1", "dummy0", :bridge)

    # The decoded %Link{}.linkinfo is a %LinkInfo{} whose info_data is the
    # kind-specific %LinkInfo.Macvlan{} — built by the codec's runtime
    # dispatch on :kind.
    assert {:ok, link} = Link.get(socket, "mv1")
    assert link.linkinfo.kind == "macvlan"
    assert link.linkinfo.info_data.mode == 4
  end

  # --- M7: neighbours and rules ---------------------------------------------

  test "Neighbour.add/4 installs a permanent entry, delete/3 removes it",
       %{socket: socket} do
    assert :ok = Link.set_up(socket, "dummy0")
    assert :ok = Address.add(socket, "dummy0", "10.99.0.2", 24)

    assert :ok = Neighbour.add(socket, "dummy0", "10.99.0.10", "02:aa:bb:cc:dd:ee")

    {:ok, neighbours} = Neighbour.list(socket, "dummy0")

    assert Enum.any?(neighbours, fn n ->
             n.dst == ~IP"10.99.0.10" and n.lladdr == ~MAC"02:aa:bb:cc:dd:ee"
           end)

    assert :ok = Neighbour.delete(socket, "dummy0", "10.99.0.10")

    {:ok, after_delete} = Neighbour.list(socket, "dummy0")
    refute Enum.any?(after_delete, &(&1.dst == ~IP"10.99.0.10"))
  end

  test "Rule.add/2 installs a policy-routing rule, delete/2 removes it",
       %{socket: socket} do
    opts = [from: "10.0.0.0/24", table: 100, priority: 1000]

    assert :ok = Rule.add(socket, opts)

    {:ok, rules} = Rule.list(socket)

    assert Enum.any?(rules, fn r ->
             r.src == ~IP"10.0.0.0" and r.src_len == 24 and r.priority == 1000 and
               Rule.target_table(r) == 100
           end)

    assert :ok = Rule.delete(socket, opts)

    {:ok, after_delete} = Rule.list(socket)

    refute Enum.any?(after_delete, fn r ->
             r.src == ~IP"10.0.0.0" and r.priority == 1000
           end)
  end

  # --- Phase 1: route actuation parity (opts, replace, idempotency) ---------

  test "replace/5 upserts: installs, then changes the gateway in place",
       %{socket: socket} do
    assert :ok = Link.set_up(socket, "dummy0")
    assert :ok = Address.add(socket, "dummy0", "10.99.0.2", 24)

    # No prior route: replace acts as create.
    assert :ok = Route.replace(socket, "10.60.0.0", 24, "10.99.0.1")

    {:ok, routes} = Route.list(socket)
    assert Enum.any?(routes, &(&1.dst == ~IP"10.60.0.0" and &1.gateway == ~IP"10.99.0.1"))

    # Existing route: replace updates the gateway in place (no delete+add).
    assert :ok = Route.replace(socket, "10.60.0.0", 24, "10.99.0.3")

    {:ok, routes2} = Route.list(socket)
    matching = Enum.filter(routes2, &(&1.dst == ~IP"10.60.0.0"))
    assert [%Route{gateway: ~IP"10.99.0.3"}] = matching
  end

  test "add/5 honours :table, :protocol and :metric; visible via list/1",
       %{socket: socket} do
    assert :ok = Link.set_up(socket, "dummy0")
    assert :ok = Address.add(socket, "dummy0", "10.99.0.2", 24)

    assert :ok =
             Route.add(socket, "10.70.0.0", 24, "10.99.0.1",
               table: 100,
               protocol: :static,
               metric: 50
             )

    {:ok, routes} = Route.list(socket)
    assert r = Enum.find(routes, &(&1.dst == ~IP"10.70.0.0"))
    assert Route.target_table(r) == 100
    assert r.protocol == 4
    assert r.priority == 50

    assert :ok = Route.delete(socket, "10.70.0.0", 24, "10.99.0.1", table: 100, metric: 50)
    {:ok, after_delete} = Route.list(socket)
    refute Enum.any?(after_delete, &(&1.dst == ~IP"10.70.0.0"))
  end

  test "add/5 is strict (EEXIST on a duplicate) where replace/5 is idempotent",
       %{socket: socket} do
    assert :ok = Link.set_up(socket, "dummy0")
    assert :ok = Address.add(socket, "dummy0", "10.99.0.2", 24)

    assert :ok = Route.add(socket, "10.80.0.0", 24, "10.99.0.1")
    assert {:error, %Error{errno: :eexist}} = Route.add(socket, "10.80.0.0", 24, "10.99.0.1")
    # replace tolerates the existing route.
    assert :ok = Route.replace(socket, "10.80.0.0", 24, "10.99.0.1")
  end

  # --- Phase 4: single-shot reconcile (addresses + routes) ------------------

  alias Linx.Netlink.Rtnl.Reconcile
  alias Linx.Netlink.Rtnl.Reconcile.Report

  defp has_addr?(socket, ip), do: Enum.any?(addrs(socket), &(&1.address == ip))
  defp addrs(socket), do: (fn {:ok, a} -> a end).(Address.list(socket, "dummy0"))
  defp owns_route?(socket, dst), do: Enum.any?(routes76(socket), &(&1.dst == dst))

  defp routes76(socket),
    do: (fn {:ok, r} -> Enum.filter(r, &(&1.protocol == 76)) end).(Route.list(socket))

  test "reconcile converges addresses and routes, then is idempotent", %{socket: socket} do
    assert :ok = Link.set_up(socket, "dummy0")

    desired = %{
      addresses: [{"dummy0", "10.99.0.2", 24}],
      routes: [{"10.50.0.0", 24, "10.99.0.1"}, {:default, "10.99.0.1"}]
    }

    assert {:ok, %Report{} = r} = Reconcile.reconcile(socket, desired)
    assert r.converged?
    assert r.failed == []
    assert length(r.applied) == 3
    assert has_addr?(socket, ~IP"10.99.0.2")
    assert owns_route?(socket, ~IP"10.50.0.0")

    # Second pass with the threaded last_applied: nothing to do.
    assert {:ok, %Report{} = r2} = Reconcile.reconcile(socket, desired, r.last_applied)
    assert r2.converged?
    assert r2.applied == []
  end

  test "reconcile repairs drift: a hand-deleted address is restored", %{socket: socket} do
    assert :ok = Link.set_up(socket, "dummy0")
    desired = %{addresses: [{"dummy0", "10.99.0.2", 24}], routes: []}

    assert {:ok, r} = Reconcile.reconcile(socket, desired)
    assert has_addr?(socket, ~IP"10.99.0.2")

    # Out-of-band drift.
    assert :ok = Address.delete(socket, "dummy0", "10.99.0.2", 24)
    refute has_addr?(socket, ~IP"10.99.0.2")

    # Next pass restores it.
    assert {:ok, r2} = Reconcile.reconcile(socket, desired, r.last_applied)
    assert r2.converged?
    assert [{:create, %Address{}}] = r2.applied
    assert has_addr?(socket, ~IP"10.99.0.2")
  end

  test "reconcile deletes an owned address dropped from desired, leaves a foreign one",
       %{socket: socket} do
    assert :ok = Link.set_up(socket, "dummy0")

    # Own two addresses.
    assert {:ok, r} =
             Reconcile.reconcile(socket, %{
               addresses: [{"dummy0", "10.99.0.2", 24}, {"dummy0", "10.99.0.3", 24}]
             })

    # A foreign address appears out of band (never owned by us).
    assert :ok = Address.add(socket, "dummy0", "10.99.0.9", 24)

    # Desired now wants only .2; .3 is ours-and-unwanted, .9 is foreign.
    assert {:ok, r2} =
             Reconcile.reconcile(
               socket,
               %{addresses: [{"dummy0", "10.99.0.2", 24}]},
               r.last_applied
             )

    assert r2.converged?
    assert [{:delete, %Address{address: ~IP"10.99.0.3"}}] = r2.applied
    assert has_addr?(socket, ~IP"10.99.0.2")
    refute has_addr?(socket, ~IP"10.99.0.3")
    # Foreign address untouched.
    assert has_addr?(socket, ~IP"10.99.0.9")
  end

  test "reconcile updates a route's gateway in place", %{socket: socket} do
    assert :ok = Link.set_up(socket, "dummy0")
    assert :ok = Address.add(socket, "dummy0", "10.99.0.2", 24)

    assert {:ok, r} = Reconcile.reconcile(socket, %{routes: [{"10.50.0.0", 24, "10.99.0.1"}]})
    assert r.converged?

    assert {:ok, r2} =
             Reconcile.reconcile(
               socket,
               %{routes: [{"10.50.0.0", 24, "10.99.0.5"}]},
               r.last_applied
             )

    assert [{:update, %Route{gateway: ~IP"10.99.0.5"}}] = r2.applied

    matching = Enum.filter(routes76(socket), &(&1.dst == ~IP"10.50.0.0"))
    assert [%Route{gateway: ~IP"10.99.0.5"}] = matching
  end

  test "reconcile ignores routes owned by another protocol", %{socket: socket} do
    assert :ok = Link.set_up(socket, "dummy0")
    assert :ok = Address.add(socket, "dummy0", "10.99.0.2", 24)

    # A foreign (static-protocol) route the reconciler must never touch.
    assert :ok = Route.add(socket, "10.77.0.0", 24, "10.99.0.1", protocol: :static)

    # Reconcile an empty desired: it must not delete the foreign route.
    assert {:ok, r} = Reconcile.reconcile(socket, %{routes: []})
    assert r.converged?
    assert r.applied == []

    {:ok, all} = Route.list(socket)
    assert Enum.any?(all, &(&1.dst == ~IP"10.77.0.0" and &1.protocol == 4))
  end

  test "reconcile is fail-fast: the first failing op stops the pass, the rest stay pending",
       %{socket: socket} do
    assert :ok = Link.set_up(socket, "dummy0")

    # No address in 10.99.0.0/24, so a route via 10.99.0.1 is unreachable and
    # the kernel rejects it (ENETUNREACH). Two such routes: ordered apply stops
    # at the first failure and never attempts the second.
    desired = %{routes: [{"10.50.0.0", 24, "10.99.0.1"}, {"10.60.0.0", 24, "10.99.0.1"}]}

    assert {:ok, %Report{} = r} = Reconcile.reconcile(socket, desired)

    refute r.converged?
    assert r.applied == []
    # Fail-fast: exactly one failed (structured error), exactly one pending.
    assert [{{:create, %Route{}}, %Error{}}] = r.failed
    assert [{:create, %Route{}}] = r.pending
    # Nothing was installed, and ownership claims nothing it didn't apply.
    assert routes76(socket) == []
    assert r.last_applied == %{addresses: MapSet.new()}
  end

  # --- Phase 5: the rtnl Monitor --------------------------------------------

  alias Linx.Netlink.Rtnl.Monitor
  alias Linx.Netlink.Rtnl.Monitor.Event

  test "Monitor forwards address and route events to the owner",
       %{socket: socket, netns_path: path} do
    assert :ok = Link.set_up(socket, "dummy0")

    # subscribe/2 joins the multicast groups synchronously in init, so events
    # caused after this call are captured (queued in the socket buffer).
    {:ok, mon} = Monitor.subscribe(self(), netns: {:path, path})

    assert :ok = Address.add(socket, "dummy0", "10.99.0.2", 24)

    assert_receive {:linx_rtnl, :event,
                    %Event{op: :new_addr, resource: %Address{address: ~IP"10.99.0.2"}}},
                   2_000

    assert :ok = Route.add(socket, "10.50.0.0", 24, "10.99.0.1")

    assert_receive {:linx_rtnl, :event,
                    %Event{op: :new_route, resource: %Route{dst: ~IP"10.50.0.0"}}},
                   2_000

    assert :ok = Address.delete(socket, "dummy0", "10.99.0.2", 24)
    assert_receive {:linx_rtnl, :event, %Event{op: :del_addr}}, 2_000

    assert :ok = Monitor.stop(mon)
  end

  test "Monitor wakes on out-of-band drift (level-triggered)",
       %{socket: socket, netns_path: path} do
    assert :ok = Link.set_up(socket, "dummy0")
    {:ok, mon} = Monitor.subscribe(self(), netns: {:path, path})

    # A change made by anyone in the namespace is observed — the event is a
    # wake-up; a reconciler would re-list and re-diff here.
    {_, 0} =
      System.cmd("ip", ~w(-n) ++ [netns_name(path)] ++ ~w(addr add 10.99.0.7/24 dev dummy0))

    assert_receive {:linx_rtnl, :event,
                    %Event{op: :new_addr, resource: %Address{address: ~IP"10.99.0.7"}}},
                   2_000

    assert :ok = Monitor.stop(mon)
  end

  defp netns_name(path), do: Path.basename(path)
end
