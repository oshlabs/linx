defmodule Linx.Netlink.Rtnl.RouteTest do
  use ExUnit.Case, async: true

  alias Linx.Netlink.Attr
  alias Linx.Netlink.Rtnl.Route

  test "encodes the rtmsg header and the gateway attribute" do
    message = %Route{
      family: 2,
      dst_len: 0,
      table: 254,
      protocol: 3,
      scope: 0,
      type: 1,
      gateway: <<10, 0, 0, 1>>
    }

    # struct rtmsg: family 2, dst_len 0, src_len 0, tos 0, table 254,
    # protocol 3, scope 0, type 1, flags 0.
    assert <<2, 0, 0, 0, 254, 3, 0, 1, 0::native-32, attrs::binary>> = Route.encode(message)
    # RTA_GATEWAY (5), the 4-byte IPv4 gateway address.
    assert Attr.decode(attrs) == [{5, <<10, 0, 0, 1>>}]
  end

  test "encode/decode round-trip" do
    message = %Route{
      family: 2,
      dst_len: 0,
      table: 254,
      protocol: 3,
      scope: 0,
      type: 1,
      gateway: <<10, 0, 0, 1>>
    }

    assert Route.decode(Route.encode(message)) == message
  end
end
