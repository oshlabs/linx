defmodule Linx.IPTest do
  use ExUnit.Case, async: true

  import Linx.IP
  alias Linx.IP
  alias Linx.IP.Subnet

  doctest Linx.IP

  describe "parse/1" do
    test "parses an IPv4 dotted-quad" do
      assert {:ok, %IP{family: :inet, bytes: <<10, 0, 0, 5>>}} = IP.parse("10.0.0.5")
    end

    test "parses an IPv6 string in canonical form" do
      assert {:ok, %IP{family: :inet6, bytes: bytes}} = IP.parse("fc00::1")
      assert byte_size(bytes) == 16
    end

    test "rejects malformed input" do
      assert {:error, {:bad_address, "not an ip"}} = IP.parse("not an ip")
    end
  end

  describe "to_string/1" do
    test "renders IPv4" do
      assert IP.to_string(%IP{family: :inet, bytes: <<10, 0, 0, 5>>}) == "10.0.0.5"
    end

    test "renders IPv6 in compressed canonical form" do
      {:ok, ip} = IP.parse("fc00::1")
      assert IP.to_string(ip) == "fc00::1"
    end
  end

  describe "~IP sigil" do
    test "builds an IPv4 address" do
      assert ~IP"10.0.0.5" == %IP{family: :inet, bytes: <<10, 0, 0, 5>>}
    end

    test "builds an IPv6 address" do
      assert %IP{family: :inet6} = ~IP"fc00::1"
    end

    test "builds a subnet when the literal contains /" do
      assert %Subnet{prefix: 24, address: %IP{family: :inet}} = ~IP"10.0.0.0/24"
    end
  end

  describe "Inspect" do
    test "renders an IPv4 address as a ~IP sigil literal" do
      assert inspect(~IP"10.0.0.5") == ~s|~IP"10.0.0.5"|
    end

    test "renders an IPv6 address as a ~IP sigil literal" do
      assert inspect(~IP"fc00::1") == ~s|~IP"fc00::1"|
    end
  end
end
