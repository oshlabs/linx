defmodule Linx.Netlink.Rtnl.RouteTest do
  use ExUnit.Case, async: true

  import Linx.IP
  alias Linx.Netlink.{Attr, Rtnl, Socket}
  alias Linx.Netlink.Rtnl.Route

  test "encodes the rtmsg header and the gateway attribute" do
    message = %Route{
      family: 2,
      dst_len: 0,
      table: 254,
      protocol: 3,
      scope: 0,
      type: 1,
      gateway: ~IP"10.0.0.1"
    }

    # struct rtmsg: family 2, dst_len 0, src_len 0, tos 0, table 254,
    # protocol 3, scope 0, type 1, flags 0.
    assert <<2, 0, 0, 0, 254, 3, 0, 1, 0::native-32, attrs::binary>> = Route.encode(message)
    # RTA_GATEWAY (5), the 4-byte IPv4 gateway address.
    assert Attr.decode(attrs) == [{5, <<10, 0, 0, 1>>}]
  end

  test "encode/decode round-trip" do
    message = %Route{
      family: 2,
      dst_len: 0,
      table: 254,
      protocol: 3,
      scope: 0,
      type: 1,
      gateway: ~IP"10.0.0.1"
    }

    assert Route.decode(Route.encode(message)) == message
  end

  test "encodes a destination-prefix route with dst, gateway and oif" do
    message = %Route{
      family: 2,
      dst_len: 24,
      table: 254,
      protocol: 3,
      scope: 0,
      type: 1,
      dst: ~IP"10.50.0.0",
      gateway: ~IP"10.99.0.1",
      oif: 3
    }

    assert <<2, 24, 0, 0, 254, 3, 0, 1, 0::native-32, attrs::binary>> = Route.encode(message)

    decoded = Attr.decode(attrs)
    assert {1, <<10, 50, 0, 0>>} in decoded
    assert {4, <<3::native-32>>} in decoded
    assert {5, <<10, 99, 0, 1>>} in decoded
  end

  test "list/1 returns the host namespace's routes" do
    {:ok, socket} = Rtnl.open()

    assert {:ok, routes} = Route.list(socket)
    # Every Linux host has at least one route in its main table.
    assert routes != []
    assert Enum.all?(routes, &match?(%Route{family: family} when family in [2, 10], &1))

    assert :ok = Socket.close(socket)
  end

  test "get/2 resolves loopback to its loopback route" do
    {:ok, socket} = Rtnl.open()

    # 127.0.0.1 always routes through the local table on a Linux host.
    assert {:ok, %Route{family: 2, dst: dst}} = Route.get(socket, "127.0.0.1")
    assert dst == ~IP"127.0.0.1"

    assert :ok = Socket.close(socket)
  end

  test "get/2 accepts a Linx.IP" do
    {:ok, socket} = Rtnl.open()

    assert {:ok, %Route{family: 2}} = Route.get(socket, ~IP"127.0.0.1")

    assert :ok = Socket.close(socket)
  end

  test "get/2 returns a parse error for a malformed address" do
    {:ok, socket} = Rtnl.open()

    assert {:error, {:bad_address, "not-an-ip"}} = Route.get(socket, "not-an-ip")

    assert :ok = Socket.close(socket)
  end
end
