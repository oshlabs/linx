defmodule Linx.Netlink.RequestTest do
  use ExUnit.Case, async: true

  import Bitwise

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

  # The terminal classifications below can't be provoked on demand through a
  # real socket, so they are exercised via consume/3 (a @doc false seam) with
  # synthesized messages.
  describe "consume/3 — dump termination edge cases" do
    # NLMSG_DONE = 3; NLM_F_MULTI = 0x02; NLM_F_DUMP_INTR = 0x10.
    @nlmsg_done 3
    @nlm_f_multi 0x02
    @nlm_f_dump_intr 0x10

    defp data_msg(seq, flags \\ @nlm_f_multi) do
      %Message{type: @rtm_newlink, flags: flags, seq: seq, payload: <<0::128>>}
    end

    test "a DONE carrying a negative dump_done_errno is an error, not success" do
      # -ENOMEM (-12): the kernel aborted the dump partway; the collected
      # messages are an incomplete snapshot.
      done = %Message{
        type: @nlmsg_done,
        flags: @nlm_f_multi,
        seq: 7,
        payload: <<-12::native-signed-32>>
      }

      assert {:halt, {:error, %Error{errno: :enomem, code: 12}}} =
               Request.consume([data_msg(7), done], 7, [])
    end

    test "a DONE with errno 0 terminates the dump successfully" do
      done = %Message{
        type: @nlmsg_done,
        flags: @nlm_f_multi,
        seq: 7,
        payload: <<0::native-signed-32>>
      }

      msg = data_msg(7)
      assert {:halt, {:ok, [^msg]}} = Request.consume([msg, done], 7, [])
    end

    test "an empty-payload DONE (old kernels) still terminates successfully" do
      done = %Message{type: @nlmsg_done, flags: @nlm_f_multi, seq: 7, payload: <<>>}

      msg = data_msg(7)
      assert {:halt, {:ok, [^msg]}} = Request.consume([msg, done], 7, [])
    end

    test "NLM_F_DUMP_INTR on a data message aborts with :dump_interrupted" do
      interrupted = data_msg(7, @nlm_f_multi ||| @nlm_f_dump_intr)

      assert {:halt, {:error, :dump_interrupted}} =
               Request.consume([data_msg(7), interrupted], 7, [])
    end

    test "NLM_F_DUMP_INTR on the DONE aborts with :dump_interrupted" do
      done = %Message{
        type: @nlmsg_done,
        flags: @nlm_f_multi ||| @nlm_f_dump_intr,
        seq: 7,
        payload: <<0::native-signed-32>>
      }

      assert {:halt, {:error, :dump_interrupted}} =
               Request.consume([data_msg(7), done], 7, [])
    end
  end
end
