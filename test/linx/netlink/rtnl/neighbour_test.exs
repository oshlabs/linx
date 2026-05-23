defmodule Linx.Netlink.Rtnl.NeighbourTest do
  use ExUnit.Case, async: true

  import Linx.IP
  import Linx.MAC
  alias Linx.Netlink.{Rtnl, Socket}
  alias Linx.Netlink.Rtnl.Neighbour

  test "encode/decode round-trip" do
    message = %Neighbour{
      family: 2,
      ifindex: 3,
      state: 0x80,
      flags: 0,
      type: 1,
      dst: ~IP"10.0.0.5",
      lladdr: ~MAC"02:aa:bb:cc:dd:ee"
    }

    assert Neighbour.decode(Neighbour.encode(message)) == message
  end

  test "encode/decode round-trip for IPv6" do
    message = %Neighbour{
      family: 10,
      ifindex: 2,
      state: 0x80,
      flags: 0,
      type: 1,
      dst: ~IP"fe80::1",
      lladdr: ~MAC"02:11:22:33:44:55"
    }

    assert Neighbour.decode(Neighbour.encode(message)) == message
  end

  test "list/1 returns the host's neighbour table" do
    {:ok, socket} = Rtnl.open()

    assert {:ok, neighbours} = Neighbour.list(socket)
    assert is_list(neighbours)
    assert Enum.all?(neighbours, &match?(%Neighbour{}, &1))

    assert :ok = Socket.close(socket)
  end
end
