defmodule Linx.IPPropertyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Linx.IP

  # Any well-formed address is exactly 4 (IPv4) or 16 (IPv6) bytes.
  defp ip_bytes, do: one_of([binary(length: 4), binary(length: 16)])

  property "decode then encode round-trips the raw address bytes" do
    check all(bytes <- ip_bytes()) do
      assert IP.encode(IP.decode(bytes)) == bytes
    end
  end

  property "to_string then parse round-trips any address" do
    check all(bytes <- ip_bytes()) do
      ip = IP.decode(bytes)
      assert {:ok, ^ip} = IP.parse(IP.to_string(ip))
    end
  end

  property "decode tags the family from the byte width" do
    check all(bytes <- binary(length: 4)) do
      assert %IP{family: :inet} = IP.decode(bytes)
    end

    check all(bytes <- binary(length: 16)) do
      assert %IP{family: :inet6} = IP.decode(bytes)
    end
  end
end
