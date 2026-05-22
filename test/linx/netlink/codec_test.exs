# Codec fixtures — separate top-level modules so the DSL's @before_compile
# runs against a normal module, exactly as a real codec module compiles.

# Two leaf codecs used as dispatch targets.
defmodule Linx.Netlink.CodecTest.A do
  @moduledoc false
  use Linx.Netlink.Codec

  codec do
    attr(1, :value, :u32)
  end
end

defmodule Linx.Netlink.CodecTest.B do
  @moduledoc false
  use Linx.Netlink.Codec

  codec do
    attr(1, :text, :string)
  end
end

# A dispatched codec — :payload's sub-codec is chosen at runtime from :kind.
defmodule Linx.Netlink.CodecTest.Dispatched do
  @moduledoc false
  use Linx.Netlink.Codec

  codec do
    attr(1, :kind, :string)

    attr(
      2,
      :payload,
      {:dispatch, :kind,
       %{
         "a" => Linx.Netlink.CodecTest.A,
         "b" => Linx.Netlink.CodecTest.B
       }}
    )
  end
end

defmodule Linx.Netlink.CodecTest.Sample do
  @moduledoc false
  use Linx.Netlink.Codec

  codec do
    header do
      field(:family, :u8)
      pad(1)
      field(:index, :s32)
    end

    attr(1, :label, :string)
    attr(2, :mtu, :u32)
  end
end

defmodule Linx.Netlink.CodecTest.Inner do
  @moduledoc false
  use Linx.Netlink.Codec

  # No header block — a bare attribute set, the shape a nested attribute takes.
  codec do
    attr(1, :kind, :string)
  end
end

defmodule Linx.Netlink.CodecTest.Outer do
  @moduledoc false
  use Linx.Netlink.Codec

  codec do
    header do
      field(:version, :u8)
    end

    # Attribute 5's value is itself a codec — the module escape hatch.
    attr(5, :inner, Linx.Netlink.CodecTest.Inner)
  end
end

defmodule Linx.Netlink.CodecTest do
  use ExUnit.Case, async: true

  alias Linx.Netlink.Attr
  alias Linx.Netlink.CodecTest.{Inner, Outer, Sample}

  test "the generated struct defaults header fields to 0 and attributes to nil" do
    assert %Sample{family: 0, index: 0, label: nil, mtu: nil} = %Sample{}
  end

  describe "encode/1 and decode/1" do
    test "round-trip a fully populated message" do
      message = %Sample{family: 2, index: 7, label: "eth0", mtu: 1500}
      assert Sample.decode(Sample.encode(message)) == message
    end

    test "omit nil attributes and decode them back as nil" do
      message = %Sample{family: 0, index: 1, label: "x", mtu: nil}
      assert Sample.decode(Sample.encode(message)) == message
    end

    test "encode the fixed header at its declared layout" do
      # family u8, one pad byte, index s32 — 6 bytes, then no attributes.
      assert Sample.encode(%Sample{family: 2, index: 7}) == <<2, 0, 7::native-signed-32>>
    end
  end

  describe "the module escape hatch" do
    test "round-trips a nested codec as an attribute value" do
      message = %Outer{version: 1, inner: %Inner{kind: "macvlan"}}
      assert Outer.decode(Outer.encode(message)) == message
    end

    test "a header-less codec is a bare attribute set" do
      assert Inner.encode(%Inner{kind: "vlan"}) == Attr.encode([{1, "vlan" <> <<0>>}])
    end
  end

  test "__codec__/0 reflects the declared schema as data" do
    codec = Sample.__codec__()

    assert codec.module == Sample
    assert {:field, :index, :s32} in codec.header
    assert {:pad, 1} in codec.header
    assert {1, :label, :string} in codec.attrs
  end

  describe "dispatch escape hatch" do
    alias Linx.Netlink.CodecTest.{A, B, Dispatched}

    test "round-trips a value whose sub-codec is chosen from the kind field" do
      a_msg = %Dispatched{kind: "a", payload: %A{value: 42}}
      b_msg = %Dispatched{kind: "b", payload: %B{text: "hello"}}

      assert Dispatched.decode(Dispatched.encode(a_msg)) == a_msg
      assert Dispatched.decode(Dispatched.encode(b_msg)) == b_msg
    end

    test "encoding an unknown kind raises a clear error" do
      assert_raise ArgumentError, ~r/no codec registered/, fn ->
        Dispatched.encode(%Dispatched{kind: "unknown", payload: %A{value: 1}})
      end
    end

    test "decoding an unknown kind keeps the raw bytes rather than crashing" do
      attrs =
        Linx.Netlink.Attr.encode([
          {1, "x" <> <<0>>},
          {2, <<99, 88, 77>>}
        ])

      decoded = Dispatched.decode(attrs)
      assert decoded.kind == "x"
      assert decoded.payload == <<99, 88, 77>>
    end
  end
end
