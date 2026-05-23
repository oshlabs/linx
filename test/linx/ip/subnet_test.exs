defmodule Linx.IP.SubnetTest do
  use ExUnit.Case, async: true

  import Linx.IP
  alias Linx.IP.Subnet

  describe "parse/1" do
    test "parses an IPv4 CIDR" do
      assert {:ok, %Subnet{prefix: 24}} = Subnet.parse("10.0.0.0/24")
    end

    test "parses an IPv6 CIDR" do
      assert {:ok, %Subnet{prefix: 64}} = Subnet.parse("fc00::/64")
    end

    test "rejects prefixes outside the address family's range" do
      assert {:error, {:bad_subnet, "10.0.0.0/33"}} = Subnet.parse("10.0.0.0/33")
      assert {:error, {:bad_subnet, "fc00::/129"}} = Subnet.parse("fc00::/129")
    end

    test "rejects garbage" do
      assert {:error, {:bad_subnet, "10.0.0.0"}} = Subnet.parse("10.0.0.0")
      assert {:error, {:bad_subnet, "not a subnet"}} = Subnet.parse("not a subnet")
    end
  end

  describe "contains?/2" do
    test "true when the IP falls inside the subnet" do
      assert Subnet.contains?(~IP"10.0.0.0/8", ~IP"10.99.0.5")
      assert Subnet.contains?(~IP"10.0.0.0/8", ~IP"10.0.0.0")
    end

    test "false when the IP is outside" do
      refute Subnet.contains?(~IP"10.0.0.0/24", ~IP"10.0.1.5")
    end

    test "false when the families differ" do
      refute Subnet.contains?(~IP"10.0.0.0/8", ~IP"fc00::1")
      refute Subnet.contains?(~IP"fc00::/16", ~IP"10.0.0.5")
    end

    test "/0 contains every address of its family" do
      assert Subnet.contains?(~IP"0.0.0.0/0", ~IP"1.2.3.4")
      assert Subnet.contains?(~IP"::/0", ~IP"fc00::1")
    end

    test "/32 (/128 for v6) matches only its exact address" do
      assert Subnet.contains?(~IP"10.0.0.5/32", ~IP"10.0.0.5")
      refute Subnet.contains?(~IP"10.0.0.5/32", ~IP"10.0.0.6")
    end
  end

  describe "network/1" do
    test "zeroes the host bits" do
      assert Subnet.network(~IP"10.0.42.5/24") == ~IP"10.0.42.0"
      assert Subnet.network(~IP"10.99.0.0/8") == ~IP"10.0.0.0"
    end

    test "/32 leaves the address unchanged" do
      assert Subnet.network(~IP"10.0.0.5/32") == ~IP"10.0.0.5"
    end
  end

  describe "broadcast/1" do
    test "fills the host bits with ones for IPv4" do
      assert Subnet.broadcast(~IP"10.0.42.5/24") == ~IP"10.0.42.255"
      assert Subnet.broadcast(~IP"10.0.0.0/16") == ~IP"10.0.255.255"
    end

    test "is nil for IPv6 (no broadcast)" do
      assert Subnet.broadcast(~IP"fc00::/16") == nil
    end
  end

  describe "Inspect" do
    test "renders as a ~IP CIDR sigil literal" do
      assert inspect(~IP"10.0.0.0/24") == ~s|~IP"10.0.0.0/24"|
      assert inspect(~IP"fc00::/16") == ~s|~IP"fc00::/16"|
    end
  end
end
