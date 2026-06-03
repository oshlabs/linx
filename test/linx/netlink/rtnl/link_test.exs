defmodule Linx.Netlink.Rtnl.LinkTest do
  use ExUnit.Case, async: true

  alias Linx.Netlink.{Attr, Error, Rtnl, Socket}
  alias Linx.Netlink.Rtnl.Link

  describe "create_macvlan/create_ipvlan input validation" do
    test "an unknown macvlan mode is a tagged tuple, not a crash" do
      assert {:error, {:bad_mode, :nonsense}} =
               Link.create_macvlan(:fake_socket, "ct0", "eth0", :nonsense)
    end

    test "an unknown ipvlan mode is a tagged tuple, not a crash" do
      assert {:error, {:bad_mode, :nope}} =
               Link.create_ipvlan(:fake_socket, "ct0", "eth0", :nope)
    end
  end

  describe "decode/1" do
    test "decodes an ifinfomsg body with IFLA attributes" do
      # ifinfomsg: AF_UNSPEC, ifi_type ARPHRD_ETHER (1), index 2, flags
      # IFF_UP, change 0; then IFLA_IFNAME "eth0" and IFLA_MTU 1500.
      body =
        <<0::8, 0::8, 1::native-16, 2::native-signed-32, 0x1::native-32, 0::native-32>> <>
          Attr.encode([{3, "eth0" <> <<0>>}, {4, <<1500::native-32>>}])

      assert %Link{index: 2, type: 1, flags: 0x1, name: "eth0", mtu: 1500} = Link.decode(body)
    end

    test "name and mtu are nil when their attributes are absent" do
      body = <<0::8, 0::8, 0::native-16, 9::native-signed-32, 0::native-32, 0::native-32>>
      assert %Link{index: 9, name: nil, mtu: nil} = Link.decode(body)
    end

    test "decodes IFLA_LINK as the parent interface index" do
      body =
        <<0::8, 0::8, 0::native-16, 7::native-signed-32, 0::native-32, 0::native-32>> <>
          Attr.encode([{5, <<3::native-32>>}])

      assert %Link{index: 7, link: 3} = Link.decode(body)
    end
  end

  test "up?/1 reflects the IFF_UP flag" do
    assert Link.up?(%Link{index: 1, flags: 0x1})
    refute Link.up?(%Link{index: 1, flags: 0x0})
  end

  test "list/1 returns the namespace's links, including loopback" do
    {:ok, socket} = Rtnl.open()

    assert {:ok, links} = Link.list(socket)
    assert Enum.any?(links, &(&1.name == "lo"))
    assert Enum.all?(links, &match?(%Link{index: index} when is_integer(index), &1))

    assert :ok = Socket.close(socket)
  end

  test "get/2 fetches a link by name" do
    {:ok, socket} = Rtnl.open()

    assert {:ok, %Link{name: "lo", index: index}} = Link.get(socket, "lo")
    assert index > 0

    assert :ok = Socket.close(socket)
  end

  test "get/2 returns a Linx.Netlink.Error for an unknown interface" do
    {:ok, socket} = Rtnl.open()

    assert {:error, %Error{errno: :enodev, code: 19, message: msg}} =
             Link.get(socket, "nosuchif0")

    # The kernel rarely attaches an ext-ack message for this case, so the
    # verb synthesizes one naming the missing interface.
    assert msg =~ "nosuchif0"

    assert :ok = Socket.close(socket)
  end

  test "create_macvlan/4 reports a missing parent interface clearly" do
    {:ok, socket} = Rtnl.open()

    assert {:error, %Error{errno: :enodev, message: msg}} =
             Link.create_macvlan(socket, "web0", "nopar0")

    # The error is re-wrapped so the caller knows it was the *parent* lookup
    # that failed, with the parent's name in the message.
    assert msg =~ "parent"
    assert msg =~ "nopar0"

    assert :ok = Socket.close(socket)
  end
end
