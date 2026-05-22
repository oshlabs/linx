defmodule Linx.Netlink.Rtnl.AddressTest do
  use ExUnit.Case, async: true

  alias Linx.Netlink.Attr
  alias Linx.Netlink.Rtnl.Address

  test "encodes the ifaddrmsg header and the IFA attributes" do
    message = %Address{
      family: 2,
      prefixlen: 24,
      flags: 0,
      scope: 0,
      index: 3,
      address: <<10, 0, 0, 5>>,
      local: <<10, 0, 0, 5>>
    }

    # struct ifaddrmsg: family 2, prefixlen 24, flags 0, scope 0, index 3.
    assert <<2, 24, 0, 0, 3::native-32, attrs::binary>> = Address.encode(message)
    # IFA_ADDRESS (1) and IFA_LOCAL (2), each the 4-byte IPv4 address.
    assert Attr.decode(attrs) == [{1, <<10, 0, 0, 5>>}, {2, <<10, 0, 0, 5>>}]
  end

  test "encode/decode round-trip" do
    message = %Address{
      family: 2,
      prefixlen: 16,
      flags: 0,
      scope: 0,
      index: 7,
      address: <<192, 168, 1, 1>>,
      local: <<192, 168, 1, 1>>
    }

    assert Address.decode(Address.encode(message)) == message
  end
end
