defmodule Linx.Netlink.MessageTest do
  use ExUnit.Case, async: true

  alias Linx.Netlink.Message

  test "encodes a message with a computed nlmsg_len" do
    msg = %Message{type: 18, flags: 0x05, seq: 42, pid: 0, payload: <<1, 2, 3, 4>>}

    assert Message.encode(msg) ==
             <<20::native-32, 18::native-16, 5::native-16, 42::native-32, 0::native-32, 1, 2, 3,
               4>>
  end

  test "encode/decode round-trip" do
    msg = %Message{type: 16, flags: 2, seq: 7, pid: 123, payload: <<9, 9, 9>>}
    assert Message.decode(Message.encode(msg)) == [msg]
  end

  test "decodes several messages from one buffer" do
    a = %Message{type: 16, seq: 1, payload: <<0xAA>>}
    b = %Message{type: 16, seq: 2, payload: <<0xBB, 0xCC>>}

    assert Message.decode(Message.encode(a) <> Message.encode(b)) == [a, b]
  end

  test "decode ignores a trailing partial header" do
    msg = %Message{type: 3, seq: 1, payload: <<>>}
    assert Message.decode(Message.encode(msg) <> <<0, 0>>) == [msg]
  end

  test "decode raises when nlmsg_len overruns the buffer" do
    assert_raise ArgumentError, fn ->
      Message.decode(<<999::native-32, 16::native-16, 0::native-16, 0::native-32, 0::native-32>>)
    end
  end
end
