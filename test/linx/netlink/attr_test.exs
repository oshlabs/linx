defmodule Linx.Netlink.AttrTest do
  use ExUnit.Case, async: true

  alias Linx.Netlink.Attr

  test "encodes an attribute with its header and 4-byte padding" do
    # type 3, 3-byte payload -> len 7, padded out to 8 bytes.
    assert Attr.encode([{3, "abc"}]) == <<7::native-16, 3::native-16, "abc", 0>>
  end

  test "encodes an already-aligned payload with no padding" do
    assert Attr.encode([{5, <<1, 0, 0, 0>>}]) ==
             <<8::native-16, 5::native-16, 1, 0, 0, 0>>
  end

  test "encodes multiple attributes in list order" do
    assert Attr.encode([{1, "a"}, {2, "bb"}]) ==
             <<5::native-16, 1::native-16, "a", 0, 0, 0, 6::native-16, 2::native-16, "bb", 0, 0>>
  end

  test "decode is the inverse of encode" do
    attrs = [{3, "interface"}, {5, <<2, 0, 0, 0>>}, {1, ""}]
    assert Attr.decode(Attr.encode(attrs)) == attrs
  end

  test "round-trips nested attributes" do
    inner = Attr.encode([{1, "macvlan"}, {2, <<4, 0, 0, 0>>}])
    [{18, payload}] = Attr.decode(Attr.encode([{18, inner}]))

    assert Attr.decode(payload) == [{1, "macvlan"}, {2, <<4, 0, 0, 0>>}]
  end

  test "decode ignores trailing alignment padding" do
    assert Attr.decode(Attr.encode([{1, "x"}]) <> <<0, 0>>) == [{1, "x"}]
  end

  test "decode of an empty binary is an empty list" do
    assert Attr.decode(<<>>) == []
  end

  test "decode raises on an inconsistent attribute length" do
    assert_raise ArgumentError, fn ->
      Attr.decode(<<99::native-16, 1::native-16, "x">>)
    end
  end
end
