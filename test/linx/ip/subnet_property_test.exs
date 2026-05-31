defmodule Linx.IP.SubnetPropertyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties

  alias Linx.IP
  alias Linx.IP.Subnet

  # An address (4 or 16 bytes) paired with a prefix valid for its width.
  defp ip_and_prefix do
    gen all(
          bytes <- one_of([binary(length: 4), binary(length: 16)]),
          prefix <- integer(0..(byte_size(bytes) * 8))
        ) do
      {IP.decode(bytes), prefix}
    end
  end

  property "parse round-trips a rendered address/prefix (host bits preserved)" do
    check all({ip, prefix} <- ip_and_prefix()) do
      str = "#{IP.to_string(ip)}/#{prefix}"
      assert {:ok, %Subnet{address: ^ip, prefix: ^prefix}} = Subnet.parse(str)
    end
  end

  property "a subnet contains its own address, its network, and (v4) its broadcast" do
    check all({ip, prefix} <- ip_and_prefix()) do
      subnet = %Subnet{address: ip, prefix: prefix}
      assert Subnet.contains?(subnet, ip)
      assert Subnet.contains?(subnet, Subnet.network(subnet))

      if ip.family == :inet do
        assert Subnet.contains?(subnet, Subnet.broadcast(subnet))
      end
    end
  end

  property "network/1 zeroes the host bits and is idempotent" do
    check all({ip, prefix} <- ip_and_prefix()) do
      subnet = %Subnet{address: ip, prefix: prefix}
      net = Subnet.network(subnet)
      # Re-deriving the network from the already-zeroed address is a no-op.
      assert Subnet.network(%Subnet{subnet | address: net}) == net
    end
  end

  property "contains?/2 is always false across mismatched families" do
    check all(
            v4 <- binary(length: 4),
            v6 <- binary(length: 16),
            prefix <- integer(0..32)
          ) do
      subnet = %Subnet{address: IP.decode(v4), prefix: prefix}
      refute Subnet.contains?(subnet, IP.decode(v6))
    end
  end
end
