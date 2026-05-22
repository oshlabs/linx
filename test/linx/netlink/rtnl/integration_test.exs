defmodule Linx.Netlink.Rtnl.IntegrationTest do
  @moduledoc """
  Exercises the mutating rtnetlink verbs against the live kernel.

  Each test runs in its own throwaway network namespace, created with
  `ip netns` — so it needs root and `iproute2`, and is tagged `:integration`
  (excluded from the default `mix test`). The namespace is seeded with a
  `dummy0` interface to act as a macvlan/ipvlan parent.
  """
  use ExUnit.Case, async: false

  alias Linx.Netlink.{Error, Rtnl, Socket}
  alias Linx.Netlink.Rtnl.{Address, Link, Route}

  @moduletag :integration

  setup do
    netns = "linx_test_#{System.unique_integer([:positive])}"

    {_, 0} = System.cmd("ip", ~w(netns add #{netns}), stderr_to_stdout: true)
    on_exit(fn -> System.cmd("ip", ~w(netns del #{netns})) end)

    {_, 0} =
      System.cmd("ip", ~w(-n #{netns} link add dummy0 type dummy), stderr_to_stdout: true)

    {:ok, socket} = Rtnl.open({:path, "/var/run/netns/#{netns}"})
    on_exit(fn -> Socket.close(socket) end)

    %{socket: socket}
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
    assert Enum.any?(before, &(&1.address == <<10, 99, 0, 2>>))

    assert :ok = Address.delete(socket, "dummy0", "10.99.0.2", 24)

    {:ok, after_delete} = Address.list(socket, "dummy0")
    refute Enum.any?(after_delete, &(&1.address == <<10, 99, 0, 2>>))
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
             r.dst == <<10, 50, 0, 0>> and r.gateway == <<10, 99, 0, 1>>
           end)

    assert :ok = Route.delete(socket, "10.50.0.0", 24, "10.99.0.1")

    {:ok, after_delete} = Route.list(socket)

    refute Enum.any?(after_delete, fn r ->
             r.dst == <<10, 50, 0, 0>> and r.gateway == <<10, 99, 0, 1>>
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

    assert {:ok, %Link{address: <<0x02, 0x11, 0x22, 0x33, 0x44, 0x55>>}} =
             Link.get(socket, "dummy0")
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
end
