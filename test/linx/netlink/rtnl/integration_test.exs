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
end
