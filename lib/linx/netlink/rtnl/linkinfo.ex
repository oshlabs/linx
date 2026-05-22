defmodule Linx.Netlink.Rtnl.LinkInfo do
  @moduledoc """
  `IFLA_LINKINFO` — a link's kind and kind-specific data.

  A bare attribute set carrying `IFLA_INFO_KIND` (the kind string —
  `"macvlan"`, `"veth"`, `"bridge"`, …) and `IFLA_INFO_DATA` (the kind-
  specific payload, decoded by the matching sub-module).

  The `:info_data` field is **dispatched** on the `:kind` value — the codec
  DSL chooses the right sub-codec module at encode and decode time, so
  `%LinkInfo{kind: "macvlan", info_data: %LinkInfo.Macvlan{mode: 4}}` is the
  natural shape on both sides of the wire.

  Kinds without per-kind data (`"bridge"`, `"dummy"`) simply leave
  `:info_data` `nil` — the DSL's `nil`-omission rule keeps the attribute off
  the wire.
  """

  use Linx.Netlink.Codec

  codec do
    # IFLA_INFO_KIND — the kind string; must be decoded before info_data so
    # the dispatch can pick the right sub-codec.
    attr(1, :kind, :string)

    # IFLA_INFO_DATA — kind-specific. The sub-codec is chosen at runtime from
    # the :kind value via the codec DSL's dispatch escape hatch.
    attr(
      2,
      :info_data,
      {:dispatch, :kind,
       %{
         "macvlan" => Linx.Netlink.Rtnl.LinkInfo.Macvlan,
         "ipvlan" => Linx.Netlink.Rtnl.LinkInfo.Ipvlan,
         "vlan" => Linx.Netlink.Rtnl.LinkInfo.Vlan,
         "veth" => Linx.Netlink.Rtnl.LinkInfo.Veth
       }}
    )
  end
end
