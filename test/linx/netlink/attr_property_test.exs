defmodule Linx.Netlink.AttrPropertyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Linx.Netlink.Attr

  # A single TLV attribute: a 16-bit type and an arbitrary binary payload.
  defp attr, do: tuple({integer(0..0xFFFF), binary()})

  property "decode then encode round-trips a list of attributes, in order" do
    check all(attrs <- list_of(attr())) do
      assert Attr.decode(Attr.encode(attrs)) == attrs
    end
  end

  property "encoding aligns every attribute to a 4-byte boundary" do
    check all(attrs <- list_of(attr(), min_length: 1)) do
      assert rem(byte_size(Attr.encode(attrs)), 4) == 0
    end
  end
end
