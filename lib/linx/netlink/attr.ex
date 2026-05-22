defmodule Linx.Netlink.Attr do
  @moduledoc """
  Encoding and decoding of netlink attributes — the type-length-value (TLV)
  elements that carry a message's variable-length data.

  This is a generic codec: it knows the TLV wire format (`struct rtattr` —
  `include/uapi/linux/rtnetlink.h`) but nothing about what any attribute
  *means*. An attribute is a `{type, value}` pair — a 16-bit integer type and
  a raw binary payload — and a list of them is what this module encodes and
  decodes. Interpreting a type, or a value's shape, belongs to the per-message
  codec above this layer.

  The TLV pair is deliberately a tuple, not a struct: it is a wire primitive,
  not domain data. The named-field structs (`Linx.Netlink.Message`, and the
  per-resource structs above it) model the domain.

  Nested attributes — an attribute whose payload is itself a list of
  attributes — need no special support: `encode/1` the inner list and pass the
  result as the outer attribute's value; on decode, `decode/1` the value of an
  attribute already known to be nested.

  One attribute on the wire:

      0      2      4
      +------+------+------ ... ------+- ... -+
      | len  | type |     payload     |  pad  |
      +------+------+------ ... ------+- ... -+

  `len` (native byte order, as everywhere in netlink) covers the 4-byte header
  and the payload but not the padding; each attribute is zero-padded to the
  next 4-byte boundary.
  """

  # struct rtattr fields are RTA_ALIGNTO-aligned, and RTA_ALIGNTO is 4.
  @align 4

  @type attr :: {type :: 0..0xFFFF, value :: binary}

  @doc """
  Encodes a list of `{type, value}` attributes into a binary.

  `value` is any iodata; for a nested attribute, pass `encode/1` of the inner
  list. Attributes appear in the result in list order.
  """
  @spec encode([{0..0xFFFF, iodata}]) :: binary
  def encode(attrs) when is_list(attrs) do
    attrs
    |> Enum.map(&encode_one/1)
    |> IO.iodata_to_binary()
  end

  defp encode_one({type, value}) when type in 0..0xFFFF do
    payload = IO.iodata_to_binary(value)
    len = 4 + byte_size(payload)
    pad = padding(len)
    <<len::native-16, type::native-16>> <> payload <> <<0::size(pad * 8)>>
  end

  @doc """
  Decodes a binary into its list of `{type, value}` attributes, in order.

  `value` is the raw payload, with the header and padding stripped. A trailing
  run too short to be an attribute header is treated as alignment padding and
  ignored. Raises `ArgumentError` if an attribute's declared length is
  inconsistent with the data.
  """
  @spec decode(binary) :: [attr]
  def decode(binary) when is_binary(binary), do: decode(binary, [])

  defp decode(rest, acc) when byte_size(rest) < 4, do: Enum.reverse(acc)

  defp decode(<<len::native-16, type::native-16, rest::binary>>, acc) do
    if len < 4 do
      raise ArgumentError, "netlink attribute length #{len} is below the 4-byte header"
    end

    payload_len = len - 4

    case rest do
      <<payload::binary-size(payload_len), tail::binary>> ->
        decode(skip_padding(tail, padding(len)), [{type, payload} | acc])

      _ ->
        raise ArgumentError,
              "netlink attribute claims length #{len} but the data is shorter"
    end
  end

  # Zero bytes following a TLV of total length `len`, aligning the next
  # attribute to a 4-byte boundary.
  defp padding(len), do: rem(@align - rem(len, @align), @align)

  # Drop up to `pad` bytes of inter-attribute padding. The kernel pads every
  # attribute, but tolerate a final one left unpadded.
  defp skip_padding(binary, 0), do: binary

  defp skip_padding(binary, pad) do
    case binary do
      <<_::binary-size(pad), rest::binary>> -> rest
      _ -> <<>>
    end
  end
end
