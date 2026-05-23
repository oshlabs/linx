defmodule Linx.Netlink.Rtnl.Neighbour do
  @moduledoc """
  rtnetlink neighbours — the kernel's ARP (IPv4) and NDP (IPv6) tables.

  A neighbour entry maps an IP address to a link-layer (MAC) address on a
  given interface. `list/1` and `list/2` read entries; `add/4` and `delete/3`
  install and remove them.

  `%Neighbour{}.dst` is a `Linx.IP`; `:lladdr` is a `Linx.MAC`. Verbs accept
  either strings or the corresponding structs.

  The wire format — `struct ndmsg` and the `NDA_*` attributes
  (`include/uapi/linux/neighbour.h`) — is declared with the
  `Linx.Netlink.Codec` DSL.
  """

  use Linx.Netlink.Codec

  import Bitwise
  import Linx.Netlink.Constants

  alias Linx.{IP, MAC}
  alias Linx.Netlink.{Request, Socket}
  alias Linx.Netlink.Rtnl.Link

  # rtnetlink neighbour message types.
  @rtm_newneigh 28
  @rtm_delneigh 29
  @rtm_getneigh 30

  @af_inet 2
  @af_inet6 10

  # NUD_PERMANENT — a manually-installed entry that never expires.
  @nud_permanent 0x80

  # RTN_UNICAST — the standard neighbour type.
  @rtn_unicast 1

  codec do
    # struct ndmsg — include/uapi/linux/neighbour.h.
    header do
      field(:family, :u8)
      pad(3)
      field(:ifindex, :s32)
      field(:state, :u16)
      field(:flags, :u8)
      field(:type, :u8)
    end

    # NDA_* — include/uapi/linux/neighbour.h.
    attr(1, :dst, Linx.IP)
    attr(2, :lladdr, Linx.MAC)
  end

  @doc "Lists every neighbour entry in the socket's network namespace."
  @spec list(Socket.t()) :: {:ok, [t()]} | {:error, term}
  def list(%Socket{} = socket) do
    case Request.talk(socket, @rtm_getneigh, nlm_f_dump(), encode(%__MODULE__{})) do
      {:ok, messages} -> {:ok, Enum.map(messages, &decode(&1.payload))}
      {:error, _} = error -> error
    end
  end

  @doc "Lists the neighbour entries on link `link_name`."
  @spec list(Socket.t(), binary) :: {:ok, [t()]} | {:error, term}
  def list(%Socket{} = socket, link_name) when is_binary(link_name) do
    with {:ok, %Link{index: index}} <- Link.get(socket, link_name),
         {:ok, all} <- list(socket) do
      {:ok, Enum.filter(all, &(&1.ifindex == index))}
    end
  end

  @doc """
  Adds a permanent neighbour entry — `ip` resolves to `mac` on `link_name`.

  `ip` may be a string or `Linx.IP`; `mac` may be a string or `Linx.MAC`.
  """
  @spec add(Socket.t(), binary, binary | IP.t(), binary | MAC.t()) :: :ok | {:error, term}
  def add(%Socket{} = socket, link_name, ip, mac) when is_binary(link_name) do
    with {:ok, %IP{family: family} = ip_struct} <- coerce_ip(ip),
         {:ok, %MAC{} = mac_struct} <- coerce_mac(mac),
         {:ok, %Link{index: index}} <- Link.get(socket, link_name) do
      message = %__MODULE__{
        family: family_int(family),
        ifindex: index,
        state: @nud_permanent,
        type: @rtn_unicast,
        dst: ip_struct,
        lladdr: mac_struct
      }

      flags = nlm_f_create() ||| nlm_f_excl() ||| nlm_f_ack()

      case Request.talk(socket, @rtm_newneigh, flags, encode(message)) do
        {:ok, _} -> :ok
        {:error, _} = error -> error
      end
    end
  end

  @doc "Removes the neighbour entry for `ip` on link `link_name`."
  @spec delete(Socket.t(), binary, binary | IP.t()) :: :ok | {:error, term}
  def delete(%Socket{} = socket, link_name, ip) when is_binary(link_name) do
    with {:ok, %IP{family: family} = ip_struct} <- coerce_ip(ip),
         {:ok, %Link{index: index}} <- Link.get(socket, link_name) do
      message = %__MODULE__{
        family: family_int(family),
        ifindex: index,
        dst: ip_struct
      }

      case Request.talk(socket, @rtm_delneigh, nlm_f_ack(), encode(message)) do
        {:ok, _} -> :ok
        {:error, _} = error -> error
      end
    end
  end

  defp coerce_ip(%IP{} = ip), do: {:ok, ip}
  defp coerce_ip(string) when is_binary(string), do: IP.parse(string)

  defp coerce_mac(%MAC{} = mac), do: {:ok, mac}
  defp coerce_mac(string) when is_binary(string), do: MAC.parse(string)

  defp family_int(:inet), do: @af_inet
  defp family_int(:inet6), do: @af_inet6

  defimpl Inspect do
    def inspect(%{dst: dst, lladdr: lladdr, ifindex: ifindex}, _opts) do
      dst_str = if dst, do: Linx.IP.to_string(dst), else: "?"
      ll_part = if lladdr, do: " -> #{Linx.MAC.to_string(lladdr)}", else: ""
      "#Linx.Netlink.Rtnl.Neighbour<#{dst_str}#{ll_part} ifindex=#{ifindex}>"
    end
  end
end
