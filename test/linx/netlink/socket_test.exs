defmodule Linx.Netlink.SocketTest do
  use ExUnit.Case, async: true

  alias Linx.Netlink.Socket

  # NETLINK_ROUTE — opening a socket of this family is unprivileged.
  @netlink_route 0

  test "opens and closes a socket in the host netns" do
    assert {:ok, %Socket{netns: :host, protocol: @netlink_route} = socket} =
             Socket.open(@netlink_route)

    assert :ok = Socket.close(socket)
  end

  test "next_seq/1 hands out increasing sequence numbers starting at 1" do
    {:ok, socket} = Socket.open(@netlink_route)

    assert 1 = Socket.next_seq(socket)
    assert 2 = Socket.next_seq(socket)
    assert 3 = Socket.next_seq(socket)

    assert :ok = Socket.close(socket)
  end

  @tag :integration
  test "opens a socket in another netns via the setns NIF" do
    # /proc/self/ns/net is the BEAM's own netns; entering it exercises the
    # Socket.Native setns path without needing a second namespace to exist.
    assert {:ok, %Socket{netns: {:path, _}} = socket} =
             Socket.open(@netlink_route, {:path, "/proc/self/ns/net"})

    assert :ok = Socket.close(socket)
  end
end
