defmodule Linx.Netlink.Rtnl.LinkInfo.Macvlan do
  @moduledoc """
  `IFLA_INFO_DATA` for a `macvlan` link — the per-kind data inside
  `IFLA_LINKINFO`.

  A `macvlan` carries a single `IFLA_MACVLAN_MODE` attribute (a `u32`); the
  modes are listed at `include/uapi/linux/if_link.h`.
  """

  use Linx.Netlink.Codec

  codec do
    # IFLA_MACVLAN_MODE — bridge / private / vepa / passthru / source.
    attr(1, :mode, :u32)
  end
end
