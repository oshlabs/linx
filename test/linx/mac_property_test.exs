defmodule Linx.MACPropertyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Linx.MAC

  property "decode then encode round-trips the raw 6 bytes" do
    check all(bytes <- binary(length: 6)) do
      assert MAC.encode(MAC.decode(bytes)) == bytes
    end
  end

  property "to_string then parse round-trips any MAC" do
    check all(bytes <- binary(length: 6)) do
      mac = MAC.decode(bytes)
      assert {:ok, ^mac} = MAC.parse(MAC.to_string(mac))
    end
  end

  property "decode returns nil for any non-6-byte binary" do
    check all(bytes <- binary(), byte_size(bytes) != 6) do
      assert MAC.decode(bytes) == nil
    end
  end
end
