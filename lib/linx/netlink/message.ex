defmodule Linx.Netlink.Message do
  @moduledoc """
  A netlink message — the `nlmsghdr` header (`include/uapi/linux/netlink.h`)
  and its payload — and the framing codec for it.

  Every netlink message, of every protocol family, has the same 16-byte
  header:

      0       4      6      8            12            16
      +-------+------+------+------------+------------+----- ... -----+
      |  len  | type | flags|    seq     |    pid     |    payload    |
      +-------+------+------+------------+------------+----- ... -----+

  All fields are in native byte order; `len` covers the header and payload.
  This module frames a message for sending and splits a received buffer back
  into messages. It does not interpret `type` — that is a protocol family's
  job — beyond using each message's `len` to find the next one.

  A single receive can carry several messages — notably a multipart dump
  batch — so `decode/1` returns a list.
  """

  @enforce_keys [:type]
  defstruct [:type, flags: 0, seq: 0, pid: 0, payload: <<>>]

  # The fixed nlmsghdr size, and the NLMSG_ALIGNTO boundary messages align to.
  @header_size 16
  @align 4

  @type t :: %__MODULE__{
          type: 0..0xFFFF,
          flags: 0..0xFFFF,
          seq: non_neg_integer,
          pid: non_neg_integer,
          payload: binary
        }

  @doc """
  Encodes a message into its on-the-wire binary, computing `nlmsg_len`.

  The result is padded to the 4-byte alignment boundary, so encoded messages
  concatenate into a valid multi-message buffer.
  """
  @spec encode(t) :: binary
  def encode(%__MODULE__{type: type, flags: flags, seq: seq, pid: pid, payload: payload}) do
    len = @header_size + byte_size(payload)
    pad = padding(len)

    <<len::native-32, type::native-16, flags::native-16, seq::native-32, pid::native-32>> <>
      payload <> <<0::size(pad * 8)>>
  end

  @doc """
  Decodes a received buffer into its list of messages, in order.

  A trailing run too short to form a header is ignored (alignment padding).
  Raises `ArgumentError` if a message's `nlmsg_len` overruns the buffer.
  """
  @spec decode(binary) :: [t]
  def decode(binary) when is_binary(binary), do: decode(binary, [])

  defp decode(rest, acc) when byte_size(rest) < @header_size, do: Enum.reverse(acc)

  defp decode(
         <<len::native-32, type::native-16, flags::native-16, seq::native-32, pid::native-32,
           rest::binary>>,
         acc
       ) do
    if len < @header_size do
      raise ArgumentError, "netlink message length #{len} is below the 16-byte header"
    end

    payload_len = len - @header_size

    case rest do
      <<payload::binary-size(payload_len), tail::binary>> ->
        msg = %__MODULE__{type: type, flags: flags, seq: seq, pid: pid, payload: payload}
        decode(skip_padding(tail, padding(len)), [msg | acc])

      _ ->
        raise ArgumentError,
              "netlink message claims length #{len} but the buffer is shorter"
    end
  end

  defp padding(len), do: rem(@align - rem(len, @align), @align)

  # Drop up to `pad` bytes of inter-message padding, tolerating a final
  # message the kernel left unpadded.
  defp skip_padding(binary, 0), do: binary

  defp skip_padding(binary, pad) do
    case binary do
      <<_::binary-size(pad), rest::binary>> -> rest
      _ -> <<>>
    end
  end
end
