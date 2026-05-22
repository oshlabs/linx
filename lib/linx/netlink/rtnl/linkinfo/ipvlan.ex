defmodule Linx.Netlink.Rtnl.LinkInfo.Ipvlan do
  @moduledoc """
  `IFLA_INFO_DATA` for an `ipvlan` link — the per-kind data inside
  `IFLA_LINKINFO`.

  An `ipvlan` carries a single `IFLA_IPVLAN_MODE` attribute (a `u16` — unlike
  macvlan's `u32` mode); modes are L2, L3 or L3S
  (`include/uapi/linux/if_link.h`).
  """

  use Linx.Netlink.Codec

  codec do
    # IFLA_IPVLAN_MODE — l2 / l3 / l3s. `nla_put_u16` in the kernel.
    attr(1, :mode, :u16)
  end
end
