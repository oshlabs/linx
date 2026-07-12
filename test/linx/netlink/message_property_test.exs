defmodule Linx.Netlink.MessagePropertyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Linx.Netlink.Message

  defp message do
    gen all(
          type <- integer(0..0xFFFF),
          flags <- integer(0..0xFFFF),
          seq <- integer(0..0xFFFFFFFF),
          pid <- integer(0..0xFFFFFFFF),
          payload <- binary()
        ) do
      %Message{type: type, flags: flags, seq: seq, pid: pid, payload: payload}
    end
  end

  property "encoded message lists round-trip as one datagram" do
    check all(messages <- list_of(message(), max_length: 32)) do
      datagram = messages |> Enum.map(&Message.encode/1) |> IO.iodata_to_binary()
      assert Message.decode(datagram) == messages
    end
  end

  property "every encoded message ends on a four-byte boundary" do
    check all(message <- message()) do
      assert rem(byte_size(Message.encode(message)), 4) == 0
    end
  end

  property "lengths below the fixed header are rejected" do
    check all(
            len <- integer(0..15),
            type <- integer(0..0xFFFF),
            flags <- integer(0..0xFFFF),
            seq <- integer(0..0xFFFFFFFF),
            pid <- integer(0..0xFFFFFFFF)
          ) do
      frame =
        <<len::native-32, type::native-16, flags::native-16, seq::native-32, pid::native-32>>

      assert_raise ArgumentError, fn -> Message.decode(frame) end
    end
  end

  property "a payload length that overruns the datagram is rejected" do
    check all(
            actual_payload <- binary(max_length: 128),
            missing_bytes <- integer(1..128)
          ) do
      claimed_payload_len = byte_size(actual_payload) + missing_bytes
      len = 16 + claimed_payload_len
      frame = <<len::native-32, 1::native-16, 0::native-16, 0::native-32, 0::native-32>>

      assert_raise ArgumentError, fn -> Message.decode(frame <> actual_payload) end
    end
  end
end
