defmodule Linx.Netlink.Rtnl.Address do
  @moduledoc """
  rtnetlink interface addresses — the `RTM_*ADDR` messages.

  `add/4` assigns an IPv4 address to a link. The wire format —
  `struct ifaddrmsg` and the `IFA_*` attributes
  (`include/uapi/linux/if_addr.h`) — is declared with the `Linx.Netlink.Codec`
  DSL.
  """

  use Linx.Netlink.Codec

  import Bitwise
  import Linx.Netlink.Constants

  alias Linx.Netlink.{Request, Socket}
  alias Linx.Netlink.Rtnl.Link

  # RTM_NEWADDR — create an address.
  @rtm_newaddr 20

  # AF_INET, and RT_SCOPE_UNIVERSE — a globally-routable address.
  @af_inet 2
  @rt_scope_universe 0

  codec do
    # struct ifaddrmsg — include/uapi/linux/if_addr.h.
    header do
      field(:family, :u8)
      field(:prefixlen, :u8)
      field(:flags, :u8)
      field(:scope, :u8)
      field(:index, :u32)
    end

    # IFA_* attributes — include/uapi/linux/if_addr.h.
    attr(1, :address, :binary)
    attr(2, :local, :binary)
  end

  @doc """
  Adds IPv4 address `ip` — a dotted-quad string — with prefix length `prefix`
  to the link named `link_name`.
  """
  @spec add(Socket.t(), binary, binary, 0..32) :: :ok | {:error, term}
  def add(%Socket{} = socket, link_name, ip, prefix)
      when is_binary(link_name) and is_binary(ip) and prefix in 0..32 do
    with {:ok, addr} <- parse_ipv4(ip),
         {:ok, %Link{index: index}} <- Link.get(socket, link_name) do
      message = %__MODULE__{
        family: @af_inet,
        prefixlen: prefix,
        scope: @rt_scope_universe,
        index: index,
        # IFA_LOCAL is the interface's own address; IFA_ADDRESS equals it for
        # an ordinary (non-point-to-point) link.
        local: addr,
        address: addr
      }

      flags = nlm_f_create() ||| nlm_f_excl() ||| nlm_f_ack()

      case Request.talk(socket, @rtm_newaddr, flags, encode(message)) do
        {:ok, _} -> :ok
        {:error, _} = error -> error
      end
    end
  end

  # A dotted-quad string to its four network-order bytes — the wire form an
  # IFA_ADDRESS / IFA_LOCAL attribute carries.
  defp parse_ipv4(string) do
    case :inet.parse_ipv4_address(String.to_charlist(string)) do
      {:ok, {a, b, c, d}} -> {:ok, <<a, b, c, d>>}
      {:error, _} -> {:error, {:bad_address, string}}
    end
  end
end
