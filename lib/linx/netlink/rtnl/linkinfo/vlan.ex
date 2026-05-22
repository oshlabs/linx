defmodule Linx.Netlink.Rtnl.LinkInfo.Vlan do
  @moduledoc """
  `IFLA_INFO_DATA` for a `vlan` link — the per-kind data inside
  `IFLA_LINKINFO`.

  A `vlan` carries an `IFLA_VLAN_ID` (a `u16`). Egress/ingress QoS maps and
  the protocol selector are not modeled here yet.
  """

  use Linx.Netlink.Codec

  codec do
    # IFLA_VLAN_ID — the 802.1Q VLAN tag.
    attr(1, :id, :u16)
  end
end
