defmodule Linx.Netlink.RequestTest do
  use ExUnit.Case, async: true

  alias Linx.Netlink.{Attr, Error, Message, Request, Socket}

  @netlink_route 0
  # rtnetlink link message types, and the IFLA_IFNAME attribute.
  @rtm_getlink 18
  @rtm_newlink 16
  @ifla_ifname 3
  # NLM_F_DUMP — ask for the whole table.
  @nlm_f_dump 0x300
  # struct ifinfomsg — 16 zero bytes is a valid "match anything" dump body.
  @ifinfomsg <<0::128>>

  test "talk/4 dumps the host's links as a multipart reply" do
    {:ok, socket} = Socket.open(@netlink_route)

    assert {:ok, messages} = Request.talk(socket, @rtm_getlink, @nlm_f_dump, @ifinfomsg)

    # Every host has at least loopback; each reply is an RTM_NEWLINK.
    assert messages != []
    assert Enum.all?(messages, &match?(%Message{type: @rtm_newlink}, &1))

    assert :ok = Socket.close(socket)
  end

  test "talk/4 surfaces a kernel error as a Linx.Netlink.Error" do
    {:ok, socket} = Socket.open(@netlink_route)

    # A non-dump RTM_GETLINK for an interface that does not exist: the kernel
    # answers with NLMSG_ERROR (-ENODEV).
    payload = @ifinfomsg <> Attr.encode([{@ifla_ifname, "nosuchif0" <> <<0>>}])

    assert {:error, %Error{errno: :enodev, code: 19} = error} =
             Request.talk(socket, @rtm_getlink, 0, payload)

    # NETLINK_EXT_ACK gives the kernel an option to attach a description, but
    # not every error path supplies one — accept either.
    assert is_nil(error.message) or is_binary(error.message)

    assert :ok = Socket.close(socket)
  end
end
