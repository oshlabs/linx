defmodule Linx.Netlink.Rtnl.LinkInfo.Veth do
  @moduledoc """
  `IFLA_INFO_DATA` for a `veth` link — the per-kind data inside
  `IFLA_LINKINFO`.

  `veth` carries one attribute, `VETH_INFO_PEER`, whose payload is *itself*
  an entire `RTM_*LINK` message (an `ifinfomsg` plus `IFLA_*` attributes)
  describing the peer end of the pair. The codec captures that exactly by
  pointing the attribute at `Linx.Netlink.Rtnl.Link` — a `%Link{}` is the
  type of the peer.
  """

  use Linx.Netlink.Codec

  codec do
    # VETH_INFO_PEER — a full Link message describing the peer end.
    attr(1, :peer, Linx.Netlink.Rtnl.Link)
  end
end
