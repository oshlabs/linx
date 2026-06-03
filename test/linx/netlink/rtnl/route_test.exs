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

  # struct rtmsg header is 12 bytes (8 u8 fields + a u32 flags).
  defp attrs_of(msg),
    do: msg |> Route.encode() |> binary_part(12, byte_size(Route.encode(msg)) - 12)

  describe "build/5 options" do
    test "metric becomes RTA_PRIORITY (6)" do
      assert {:ok, msg} = Route.build("10.50.0.0", 24, "10.99.0.1", 0, metric: 50)
      assert msg.priority == 50
      assert {6, <<50::native-32>>} in Attr.decode(attrs_of(msg))
    end

    test "a table <= 255 goes in the header byte; no RTA_TABLE" do
      assert {:ok, msg} = Route.build("10.50.0.0", 24, "10.99.0.1", 0, table: 100)
      assert msg.table == 100
      assert msg.table_ext == nil
      assert Route.target_table(msg) == 100
      refute Enum.any?(Attr.decode(attrs_of(msg)), &match?({15, _}, &1))
    end

    test "a table > 255 moves to RTA_TABLE (15); header byte is unspec (0)" do
      assert {:ok, msg} = Route.build("10.50.0.0", 24, "10.99.0.1", 0, table: 1000)
      assert msg.table == 0
      assert msg.table_ext == 1000
      assert Route.target_table(msg) == 1000
      assert {15, <<1000::native-32>>} in Attr.decode(attrs_of(msg))
    end

    test "protocol accepts a named atom or a raw integer" do
      assert {:ok, %{protocol: 4}} =
               Route.build("10.50.0.0", 24, "10.99.0.1", 0, protocol: :static)

      assert {:ok, %{protocol: 4}} = Route.build("10.50.0.0", 24, "10.99.0.1", 0, protocol: 4)
    end

    test "defaults: main table (254), boot protocol (3), no metric" do
      assert {:ok, msg} = Route.build("10.50.0.0", 24, "10.99.0.1", 0)
      assert msg.table == 254
      assert msg.protocol == 3
      assert msg.priority == nil
    end

    test "rejects bad options" do
      assert {:error, {:bad_option, :table, 0}} =
               Route.build("10.0.0.0", 24, "10.0.0.1", 0, table: 0)

      assert {:error, {:bad_option, :protocol, :bogus}} =
               Route.build("10.0.0.0", 24, "10.0.0.1", 0, protocol: :bogus)

      assert {:error, {:bad_option, :metric, -1}} =
               Route.build("10.0.0.0", 24, "10.0.0.1", 0, metric: -1)
    end

    test "still validates family agreement and prefix width" do
      assert {:error, {:family_mismatch, _}} = Route.build("10.0.0.0", 24, "fc00::1", 0)
      assert {:error, {:bad_prefix, 40}} = Route.build("10.0.0.0", 40, "10.0.0.1", 0)
    end
  end

  describe "target_table/1" do
    test "prefers table_ext when present, else the header byte" do
      assert Route.target_table(%Route{table: 0, table_ext: 1000}) == 1000
      assert Route.target_table(%Route{table: 254, table_ext: nil}) == 254
    end
  end

  describe "Inspect" do
    test "shows non-default table, metric, and protocol" do
      {:ok, msg} =
        Route.build("10.50.0.0", 24, "10.99.0.1", 0, table: 100, metric: 50, protocol: :static)

      s = inspect(msg)
      assert s =~ "10.50.0.0/24"
      assert s =~ "via 10.99.0.1"
      assert s =~ "table=100"
      assert s =~ "metric=50"
      assert s =~ "proto=4"
    end

    test "hides defaults (main table, boot proto, no metric)" do
      {:ok, msg} = Route.build("10.50.0.0", 24, "10.99.0.1", 0)
      s = inspect(msg)
      refute s =~ "table="
      refute s =~ "metric="
      refute s =~ "proto="
    end
  end
end
