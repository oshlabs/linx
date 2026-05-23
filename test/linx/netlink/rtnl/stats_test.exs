defmodule Linx.Netlink.Rtnl.StatsTest do
  use ExUnit.Case, async: true

  alias Linx.Netlink.{Attr, Rtnl, Socket}
  alias Linx.Netlink.Rtnl.Stats
  alias Linx.Netlink.Rtnl.Stats.Link64

  describe "encode/1" do
    test "encodes the if_stats_msg header with ifindex and filter_mask" do
      # AF_UNSPEC (0), 3 pad bytes, ifindex 2, filter_mask 1 (LINK_64).
      assert <<0, 0, 0, 0, 2::native-32, 1::native-32>> =
               Stats.encode(%Stats{ifindex: 2, filter_mask: 1})
    end

    test "a nil :link is omitted, not zero-padded" do
      # No attribute bytes follow the 12-byte header.
      assert <<_::binary-size(12)>> = Stats.encode(%Stats{ifindex: 2, filter_mask: 1})
    end

    test "a non-nil :link is encoded as IFLA_STATS_LINK_64 with packed counters" do
      message = %Stats{
        ifindex: 7,
        filter_mask: 1,
        link: %Link64{rx_packets: 100, tx_packets: 200, rx_bytes: 12_345}
      }

      assert <<_::binary-size(12), attrs::binary>> = Stats.encode(message)
      assert [{1, payload}] = Attr.decode(attrs)
      # 25 counters, packed u64 native-endian = 200 bytes.
      assert byte_size(payload) == 200
      assert <<100::native-64, 200::native-64, 12_345::native-64, _::binary>> = payload
    end
  end

  describe "decode/1" do
    test "decodes the header and a LINK_64 attribute" do
      payload =
        for v <- 1..25, into: <<>>, do: <<v::native-unsigned-64>>

      body =
        <<0, 0, 0, 0, 9::native-32, 1::native-32>> <> Attr.encode([{1, payload}])

      assert %Stats{ifindex: 9, filter_mask: 1, link: %Link64{} = link} = Stats.decode(body)

      assert link.rx_packets == 1
      assert link.tx_packets == 2
      assert link.rx_otherhost_dropped == 25
    end

    test "tolerates the 192-byte (pre-5.19) layout — extra field stays nil" do
      payload = for v <- 1..24, into: <<>>, do: <<v::native-unsigned-64>>

      body =
        <<0, 0, 0, 0, 9::native-32, 1::native-32>> <> Attr.encode([{1, payload}])

      assert %Stats{link: %Link64{rx_nohandler: 24, rx_otherhost_dropped: nil}} =
               Stats.decode(body)
    end
  end

  test "encode/decode round-trip" do
    counters = Link64.__counters__()

    link =
      counters
      |> Enum.with_index(1)
      |> Enum.reduce(%Link64{}, fn {name, i}, acc -> Map.put(acc, name, i * 1000) end)

    message = %Stats{ifindex: 3, filter_mask: 1, link: link}
    assert Stats.decode(Stats.encode(message)) == message
  end

  test "list/1 returns one Stats entry per interface in the namespace" do
    {:ok, socket} = Rtnl.open()

    assert {:ok, stats} = Stats.list(socket)
    # Every host has at least loopback.
    assert stats != []
    assert Enum.all?(stats, &match?(%Stats{ifindex: i, link: %Link64{}} when is_integer(i), &1))

    assert :ok = Socket.close(socket)
  end

  test "get/2 returns loopback's stats" do
    {:ok, socket} = Rtnl.open()

    assert {:ok, %Stats{ifindex: index, link: %Link64{} = link}} = Stats.get(socket, "lo")
    assert index > 0
    # Loopback always has at least the counters defined; values may be 0
    # on a very fresh namespace but the fields themselves must be present.
    assert is_integer(link.rx_packets)
    assert is_integer(link.tx_packets)

    assert :ok = Socket.close(socket)
  end

  test "get/2 reports a missing interface clearly" do
    {:ok, socket} = Rtnl.open()

    assert {:error, %Linx.Netlink.Error{errno: :enodev, message: msg}} =
             Stats.get(socket, "nosuchif0")

    assert msg =~ "nosuchif0"

    assert :ok = Socket.close(socket)
  end
end
