defmodule Linx.Netlink.Rtnl.NeighbourTest do
  use ExUnit.Case, async: true

  alias Linx.Netlink.{Rtnl, Socket}
  alias Linx.Netlink.Rtnl.Neighbour

  test "encode/decode round-trip" do
    message = %Neighbour{
      family: 2,
      ifindex: 3,
      state: 0x80,
      flags: 0,
      type: 1,
      dst: <<10, 0, 0, 5>>,
      lladdr: <<0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE>>
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
      dst: <<0xFE80::16, 0::96, 1::16>>,
      lladdr: <<0x02, 0x11, 0x22, 0x33, 0x44, 0x55>>
    }

    assert Neighbour.decode(Neighbour.encode(message)) == message
  end

  test "list/1 returns the host's neighbour table" do
    {:ok, socket} = Rtnl.open()

    # The neighbour table may be empty on a freshly booted host — just check
    # the shape rather than any specific entry.
    assert {:ok, neighbours} = Neighbour.list(socket)
    assert is_list(neighbours)
    assert Enum.all?(neighbours, &match?(%Neighbour{}, &1))

    assert :ok = Socket.close(socket)
  end
end
