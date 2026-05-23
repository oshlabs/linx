defmodule Linx.Netlink.Rtnl.AddressTest do
  use ExUnit.Case, async: true

  import Linx.IP
  alias Linx.Netlink.{Attr, Rtnl, Socket}
  alias Linx.Netlink.Rtnl.Address

  test "encodes the ifaddrmsg header and the IFA attributes" do
    message = %Address{
      family: 2,
      prefixlen: 24,
      flags: 0,
      scope: 0,
      index: 3,
      address: ~IP"10.0.0.5",
      local: ~IP"10.0.0.5"
    }

    # struct ifaddrmsg: family 2, prefixlen 24, flags 0, scope 0, index 3.
    assert <<2, 24, 0, 0, 3::native-32, attrs::binary>> = Address.encode(message)
    # IFA_ADDRESS (1) and IFA_LOCAL (2), each the 4-byte IPv4 address.
    assert Attr.decode(attrs) == [{1, <<10, 0, 0, 5>>}, {2, <<10, 0, 0, 5>>}]
  end

  test "encode/decode round-trip" do
    message = %Address{
      family: 2,
      prefixlen: 16,
      flags: 0,
      scope: 0,
      index: 7,
      address: ~IP"192.168.1.1",
      local: ~IP"192.168.1.1"
    }

    assert Address.decode(Address.encode(message)) == message
  end

  test "encode/decode round-trip for IPv6" do
    ip = ~IP"fe80::1"

    message = %Address{
      family: 10,
      prefixlen: 64,
      flags: 0,
      scope: 0,
      index: 2,
      address: ip,
      local: ip
    }

    assert Address.decode(Address.encode(message)) == message
  end

  test "list/1 returns the host namespace's addresses" do
    {:ok, socket} = Rtnl.open()

    assert {:ok, addresses} = Address.list(socket)
    # Every Linux host has loopback's 127.0.0.1.
    assert Enum.any?(addresses, &(&1.address == ~IP"127.0.0.1"))

    assert :ok = Socket.close(socket)
  end

  test "list/2 returns only addresses of the given link" do
    {:ok, socket} = Rtnl.open()

    assert {:ok, lo_addresses} = Address.list(socket, "lo")
    assert lo_addresses != []
    assert Enum.any?(lo_addresses, &(&1.address == ~IP"127.0.0.1"))

    assert :ok = Socket.close(socket)
  end
end
