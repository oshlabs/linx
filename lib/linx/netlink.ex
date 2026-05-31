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
    * `Linx.Netlink.Message` / `Linx.Netlink.Attr` — the pure wire codec: the
      `nlmsghdr` envelope and the type-length-value attributes inside it.
    * `Linx.Netlink.Request` — sends a request and collects the kernel's
      reply, including multipart dumps.
    * `Linx.Netlink.Constants` — the core netlink constants every family
      shares.
    * `Linx.Netlink.Codec` — a DSL for declaring a message's wire format; the
      per-family codecs are built with it.

  Each protocol family then lives in its own namespace. The first is
  rtnetlink — the kernel's networking interface — under `Linx.Netlink.Rtnl`.

  ## Example

      # List the host's network interfaces.
      {:ok, sock} = Linx.Netlink.Rtnl.open()
      {:ok, links} = Linx.Netlink.Rtnl.Link.list(sock)
      :ok = Linx.Netlink.Socket.close(sock)

  ## Status

  Two protocol families ship today: **rtnetlink** (`Linx.Netlink.Rtnl` —
  links, addresses, routes, neighbours, rules) and **nfnetlink**
  (`Linx.Netlink.Nfnl` — the transport under `Linx.Netfilter`). The
  wire layers (`Socket`, `Message`, `Attr`, `Request`, `Codec`) are
  family-agnostic and shared across both. A concurrent-request
  connection process, a multicast monitor, and generic netlink
  (`NETLINK_GENERIC`) are future work.
  """
end
