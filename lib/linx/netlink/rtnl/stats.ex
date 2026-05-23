defmodule Linx.Netlink.Rtnl.Stats do
  @moduledoc """
  rtnetlink interface statistics — the `RTM_GETSTATS` reads.

  `get/2` returns one interface's counters; `list/1` dumps every
  interface's. Both verbs are read-only — no `CAP_NET_ADMIN` needed.

  The counters live on the `:link` field as a `Linx.Netlink.Rtnl.Stats.Link64`
  sub-struct. `IFLA_STATS_LINK_64` is the only stats class Linx decodes
  today; the kernel exposes others (XSTATS, OFFLOAD_XSTATS, AF_SPEC) under
  sibling attribute IDs and they will be added as the need arises.

  The wire format — `struct if_stats_msg` (`include/uapi/linux/rtnetlink.h`)
  and the `IFLA_STATS_*` attributes (`include/uapi/linux/if_link.h`) — is
  declared with the `Linx.Netlink.Codec` DSL.
  """

  use Linx.Netlink.Codec

  import Linx.Netlink.Constants

  alias Linx.Netlink.{Message, Request, Socket}
  alias Linx.Netlink.Rtnl.Link
  alias Linx.Netlink.Rtnl.Stats.Link64

  # rtnetlink stats message type — include/uapi/linux/rtnetlink.h.
  @rtm_getstats 94

  # The kernel's `IFLA_STATS_FILTER_BIT(ATTR)` is `1 << (ATTR - 1)`.
  # IFLA_STATS_LINK_64 has id 1, so the bit that selects it is 1 << 0 = 1.
  @stats_link_64_filter 0x1

  codec do
    # struct if_stats_msg — include/uapi/linux/rtnetlink.h.
    header do
      field(:family, :u8)
      pad(3)
      field(:ifindex, :u32)
      field(:filter_mask, :u32)
    end

    # IFLA_STATS_* — include/uapi/linux/if_link.h. The link_64 payload is
    # a packed C struct (not nested TLVs), so its codec is a hand-written
    # value-type module rather than another Codec block.
    attr(1, :link, Link64)
  end

  @doc """
  Returns the statistics for the link named `name`.

  Resolves the interface index by name first, then issues a single
  `RTM_GETSTATS` request with that index. Returns
  `{:error, %Linx.Netlink.Error{}}` if there is no such interface.
  """
  @spec get(Socket.t(), binary) :: {:ok, t()} | {:error, term}
  def get(%Socket{} = socket, name) when is_binary(name) do
    with {:ok, %Link{index: index}} <- Link.get(socket, name) do
      message = %__MODULE__{ifindex: index, filter_mask: @stats_link_64_filter}

      case Request.talk(socket, @rtm_getstats, 0, encode(message)) do
        {:ok, [%Message{payload: body} | _]} -> {:ok, decode(body)}
        {:ok, []} -> {:error, :no_reply}
        {:error, _} = error -> error
      end
    end
  end

  @doc """
  Returns the statistics for every link in the socket's namespace.
  """
  @spec list(Socket.t()) :: {:ok, [t()]} | {:error, term}
  def list(%Socket{} = socket) do
    message = %__MODULE__{filter_mask: @stats_link_64_filter}

    case Request.talk(socket, @rtm_getstats, nlm_f_dump(), encode(message)) do
      {:ok, messages} -> {:ok, Enum.map(messages, &decode(&1.payload))}
      {:error, _} = error -> error
    end
  end

  defimpl Inspect do
    def inspect(%{ifindex: ifindex, link: link}, _opts) do
      counters =
        case link do
          %{rx_packets: rxp, rx_bytes: rxb, tx_packets: txp, tx_bytes: txb} ->
            " rx=#{rxp || 0}p/#{rxb || 0}B tx=#{txp || 0}p/#{txb || 0}B"

          _ ->
            ""
        end

      "#Linx.Netlink.Rtnl.Stats<ifindex=#{ifindex}#{counters}>"
    end
  end
end
