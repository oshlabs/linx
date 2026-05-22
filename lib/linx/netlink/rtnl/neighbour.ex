defmodule Linx.Netlink.Rtnl.Neighbour do
  @moduledoc """
  rtnetlink neighbours — the kernel's ARP (IPv4) and NDP (IPv6) tables.

  A neighbour entry maps an IP address to a link-layer (MAC) address on a
  given interface. `list/1` and `list/2` read entries; `add/4` and `delete/3`
  install and remove them. IPv4 and IPv6 are both supported — the address
  family is detected from the IP string.

  The wire format — `struct ndmsg` and the `NDA_*` attributes
  (`include/uapi/linux/neighbour.h`) — is declared with the
  `Linx.Netlink.Codec` DSL.
  """

  use Linx.Netlink.Codec

  import Bitwise
  import Linx.Netlink.Constants

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
    attr(1, :dst, :binary)
    attr(2, :lladdr, :binary)
  end

  @doc """
  Lists every neighbour entry in the socket's network namespace.
  """
  @spec list(Socket.t()) :: {:ok, [t()]} | {:error, term}
  def list(%Socket{} = socket) do
    case Request.talk(socket, @rtm_getneigh, nlm_f_dump(), encode(%__MODULE__{})) do
      {:ok, messages} -> {:ok, Enum.map(messages, &decode(&1.payload))}
      {:error, _} = error -> error
    end
  end

  @doc """
  Lists the neighbour entries on link `link_name`.
  """
  @spec list(Socket.t(), binary) :: {:ok, [t()]} | {:error, term}
  def list(%Socket{} = socket, link_name) when is_binary(link_name) do
    with {:ok, %Link{index: index}} <- Link.get(socket, link_name),
         {:ok, all} <- list(socket) do
      {:ok, Enum.filter(all, &(&1.ifindex == index))}
    end
  end

  @doc """
  Adds a permanent neighbour entry — `ip` resolves to MAC `mac` on `link_name`.

  `mac` is a colon-separated hex string, e.g. `"aa:bb:cc:dd:ee:ff"`.
  """
  @spec add(Socket.t(), binary, binary, binary) :: :ok | {:error, term}
  def add(%Socket{} = socket, link_name, ip, mac)
      when is_binary(link_name) and is_binary(ip) and is_binary(mac) do
    with {:ok, {family, addr}} <- parse_address(ip),
         {:ok, lladdr} <- parse_mac(mac),
         {:ok, %Link{index: index}} <- Link.get(socket, link_name) do
      message = %__MODULE__{
        family: family,
        ifindex: index,
        state: @nud_permanent,
        type: @rtn_unicast,
        dst: addr,
        lladdr: lladdr
      }

      flags = nlm_f_create() ||| nlm_f_excl() ||| nlm_f_ack()

      case Request.talk(socket, @rtm_newneigh, flags, encode(message)) do
        {:ok, _} -> :ok
        {:error, _} = error -> error
      end
    end
  end

  @doc """
  Removes the neighbour entry for `ip` on link `link_name`.
  """
  @spec delete(Socket.t(), binary, binary) :: :ok | {:error, term}
  def delete(%Socket{} = socket, link_name, ip)
      when is_binary(link_name) and is_binary(ip) do
    with {:ok, {family, addr}} <- parse_address(ip),
         {:ok, %Link{index: index}} <- Link.get(socket, link_name) do
      message = %__MODULE__{family: family, ifindex: index, dst: addr}

      case Request.talk(socket, @rtm_delneigh, nlm_f_ack(), encode(message)) do
        {:ok, _} -> :ok
        {:error, _} = error -> error
      end
    end
  end

  defp parse_address(string) do
    case :inet.parse_address(String.to_charlist(string)) do
      {:ok, {a, b, c, d}} ->
        {:ok, {@af_inet, <<a, b, c, d>>}}

      {:ok, {a, b, c, d, e, f, g, h}} ->
        {:ok, {@af_inet6, <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>}}

      {:error, _} ->
        {:error, {:bad_address, string}}
    end
  end

  defp parse_mac(mac) do
    case String.split(mac, ":") do
      [_, _, _, _, _, _] = parts -> parse_hex_pairs(parts, <<>>, mac)
      _ -> {:error, {:bad_mac, mac}}
    end
  end

  defp parse_hex_pairs([], acc, _orig), do: {:ok, acc}

  defp parse_hex_pairs([h | t], acc, orig) do
    case Integer.parse(h, 16) do
      {n, ""} when n in 0..255 -> parse_hex_pairs(t, acc <> <<n>>, orig)
      _ -> {:error, {:bad_mac, orig}}
    end
  end
end
