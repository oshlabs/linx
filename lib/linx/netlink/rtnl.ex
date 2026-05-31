defmodule Linx.Netlink.Rtnl do
  @moduledoc """
  rtnetlink (`NETLINK_ROUTE`) — the kernel's networking-stack interface:
  links, addresses, routes and neighbours.

  This is the first `Linx.Netlink` protocol family. Each kind of object has
  its own module. Open a socket for the family with `open/1` and pass it to
  those modules' functions.

  ## Example

      {:ok, sock} = Linx.Netlink.Rtnl.open()
      {:ok, links} = Linx.Netlink.Rtnl.Link.list(sock)
      {:ok, addrs} = Linx.Netlink.Rtnl.Address.list(sock)
      :ok = Linx.Netlink.Socket.close(sock)

  ## Status

  Shipped resource modules: `Linx.Netlink.Rtnl.Link` (create / list /
  configure / delete — macvlan, ipvlan, veth, vlan, bridge, dummy),
  `Address`, `Route`, `Neighbour`, `Rule`, and read-only `Stats`. One
  socket drives all of them; cross-namespace work opens the socket in
  the target netns (`open({:pid, n})`).
  """

  alias Linx.Netlink.Socket

  # NETLINK_ROUTE — the rtnetlink protocol number for socket(2).
  @netlink_route 0

  @doc """
  Opens an rtnetlink socket in network namespace `netns`.

  See `Linx.Netlink.Socket.open/2` for the `netns` forms. Close the socket
  with `Linx.Netlink.Socket.close/1`.
  """
  @spec open(Socket.netns()) :: {:ok, Socket.t()} | {:error, term}
  def open(netns \\ :host), do: Socket.open(@netlink_route, netns)
end
