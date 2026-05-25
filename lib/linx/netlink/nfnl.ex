defmodule Linx.Netlink.Nfnl do
  @moduledoc """
  nfnetlink (`NETLINK_NETFILTER`) — the kernel's netfilter-control
  interface: nf_tables (the modern firewall), conntrack, NFLOG, NFQUEUE.

  This is the second `Linx.Netlink` protocol family (after
  `Linx.Netlink.Rtnl`). nfnetlink multiplexes several sub-subsystems
  inside one netlink family — identified by the high byte of
  `nlmsghdr.type` (`subsys_id`). The map (`include/uapi/linux/netfilter/nfnetlink.h`):

  | subsys_id | Name | Linx module |
  |---|---|---|
  | 1  | CTNETLINK | `Linx.Netfilter.Conntrack` (future) |
  | 3  | QUEUE     | `Linx.Netfilter.Queue` (future) |
  | 4  | ULOG      | `Linx.Netfilter.Log` (NFLOG; N7) |
  | 10 | NFTABLES  | `Linx.Netfilter` core (N0–N7) |
  | 12 | HOOK      | (deferred) |

  Open a socket with `open/1` and pass it to the appropriate higher-level
  module (`Linx.Netfilter`, eventually `Linx.Netfilter.{Conntrack,Log,Queue}`).

  Codec helpers — `nfgenmsg` header encoding, subsys-id multiplexing on
  `nlmsghdr.type`, batched-transaction envelope (`NFNL_MSG_BATCH_BEGIN` /
  `NFNL_MSG_BATCH_END`), and the `NFT_MSG_GETGEN` / `NEWGEN` codec — live
  in `Linx.Netlink.Nfnl.Codec`.
  """

  alias Linx.Netlink.Socket

  # NETLINK_NETFILTER — the nfnetlink protocol number for socket(2).
  # `include/uapi/linux/netlink.h`.
  @netlink_netfilter 12

  @doc """
  Opens an nfnetlink socket in network namespace `netns`.

  See `Linx.Netlink.Socket.open/2` for the `netns` forms (`:host`,
  `{:pid, n}`, `{:path, p}`). Close the socket with
  `Linx.Netlink.Socket.close/1`.
  """
  @spec open(Socket.netns()) :: {:ok, Socket.t()} | {:error, term}
  def open(netns \\ :host), do: Socket.open(@netlink_netfilter, netns)
end
