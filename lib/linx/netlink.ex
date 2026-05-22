defmodule Linx.Netlink do
  @moduledoc """
  Netlink for Elixir — a client for the Linux kernel's `AF_NETLINK` interface.

  Netlink is how userspace talks to many kernel subsystems: the networking
  stack (rtnetlink), and — through generic netlink — WireGuard, nl80211 and
  more. `Linx.Netlink` speaks it directly, encoding and decoding messages in
  Elixir; a small NIF handles the one thing the BEAM cannot do safely on its
  own — entering another network namespace.

  The library is layered, lower layers ignorant of higher ones:

    * `Linx.Netlink.Socket` — an `AF_NETLINK` socket in a chosen network
      namespace, for any netlink protocol family.

  Each protocol family then lives in its own namespace. The first is
  rtnetlink — the kernel's networking interface — under `Linx.Netlink.Rtnl`.
  """
end
