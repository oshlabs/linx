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

  test "next_seq/1 wraps at 32 bits and skips the reserved 0 (m2)" do
    # The wire field is 32 bits; an unmasked 64-bit counter value would
    # never match its echoed reply after 2³² requests.
    {:ok, socket} = Socket.open(@netlink_route)

    :atomics.put(socket.seq, 1, 0xFFFFFFFF)
    assert 1 = Socket.next_seq(socket)
    assert 2 = Socket.next_seq(socket)

    assert :ok = Socket.close(socket)
  end

  describe "recv_datagram/2" do
    # RTM_GETLINK dump request bytes: nlmsghdr (len=32, type=18,
    # flags=NLM_F_REQUEST|NLM_F_DUMP, seq=1, pid=0) + zeroed ifinfomsg.
    @getlink_dump <<32::native-32, 18::native-16, 0x0301::native-16, 1::native-32, 0::native-32,
                    0::128>>

    test "returns a whole datagram with the default 64 KiB read" do
      {:ok, socket} = Socket.open(@netlink_route)
      :ok = :socket.send(socket.socket, @getlink_dump)

      assert {:ok, data} = Socket.recv_datagram(socket)
      # Every host has at least loopback, so the first dump chunk carries
      # at least one full RTM_NEWLINK (> its 16-byte header).
      assert byte_size(data) > 16

      assert :ok = Socket.close(socket)
    end

    test "surfaces kernel-flagged truncation instead of a cut buffer" do
      {:ok, socket} = Socket.open(@netlink_route)
      :ok = :socket.send(socket.socket, @getlink_dump)

      # A 128-byte read cannot hold even one link message; the kernel sets
      # MSG_TRUNC and recv_datagram must refuse the cut buffer.
      assert {:error, :truncated} = Socket.recv_datagram(socket, 128)

      assert :ok = Socket.close(socket)
    end
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
