defmodule Linx.Netlink.Rtnl.Route do
  @moduledoc """
  rtnetlink routes — the `RTM_*ROUTE` messages.

  `add_default/2` installs an IPv4 default route via a gateway. The wire
  format — `struct rtmsg` and the `RTA_*` attributes
  (`include/uapi/linux/rtnetlink.h`) — is declared with the
  `Linx.Netlink.Codec` DSL. Routes to a specific destination prefix are a
  later addition.
  """

  use Linx.Netlink.Codec

  import Bitwise
  import Linx.Netlink.Constants

  alias Linx.Netlink.{Request, Socket}

  # RTM_NEWROUTE — create a route.
  @rtm_newroute 24

  # rtmsg field values — include/uapi/linux/rtnetlink.h.
  @af_inet 2
  @rt_table_main 254
  @rtprot_boot 3
  @rt_scope_universe 0
  @rtn_unicast 1

  codec do
    # struct rtmsg — include/uapi/linux/rtnetlink.h.
    header do
      field(:family, :u8)
      field(:dst_len, :u8)
      field(:src_len, :u8)
      field(:tos, :u8)
      field(:table, :u8)
      field(:protocol, :u8)
      field(:scope, :u8)
      field(:type, :u8)
      field(:flags, :u32)
    end

    # RTA_* attributes — include/uapi/linux/rtnetlink.h.
    attr(5, :gateway, :binary)
  end

  @doc """
  Adds an IPv4 default route (`0.0.0.0/0`) via `gateway`, a dotted-quad string.
  """
  @spec add_default(Socket.t(), binary) :: :ok | {:error, term}
  def add_default(%Socket{} = socket, gateway) when is_binary(gateway) do
    with {:ok, gw} <- parse_ipv4(gateway) do
      # dst_len 0 is the default route 0.0.0.0/0; the main table, universe
      # scope, a plain unicast route installed by userspace (RTPROT_BOOT).
      message = %__MODULE__{
        family: @af_inet,
        dst_len: 0,
        table: @rt_table_main,
        protocol: @rtprot_boot,
        scope: @rt_scope_universe,
        type: @rtn_unicast,
        gateway: gw
      }

      flags = nlm_f_create() ||| nlm_f_excl() ||| nlm_f_ack()

      case Request.talk(socket, @rtm_newroute, flags, encode(message)) do
        {:ok, _} -> :ok
        {:error, _} = error -> error
      end
    end
  end

  # A dotted-quad string to its four network-order bytes.
  defp parse_ipv4(string) do
    case :inet.parse_ipv4_address(String.to_charlist(string)) do
      {:ok, {a, b, c, d}} -> {:ok, <<a, b, c, d>>}
      {:error, _} -> {:error, {:bad_address, string}}
    end
  end
end
