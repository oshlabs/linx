defmodule Linx.Netlink.Rtnl.Address do
  @moduledoc """
  rtnetlink interface addresses — the `RTM_*ADDR` messages.

  `list/1` and `list/2` read addresses; `add/4` and `delete/4` assign and
  remove them. IPv4 and IPv6 are both supported — the address family is
  detected from the string passed in.

  The wire format — `struct ifaddrmsg` and the `IFA_*` attributes
  (`include/uapi/linux/if_addr.h`) — is declared with the
  `Linx.Netlink.Codec` DSL.
  """

  use Linx.Netlink.Codec

  import Bitwise
  import Linx.Netlink.Constants

  alias Linx.Netlink.{Request, Socket}
  alias Linx.Netlink.Rtnl.Link

  # rtnetlink address message types.
  @rtm_newaddr 20
  @rtm_deladdr 21
  @rtm_getaddr 22

  # AF_INET / AF_INET6 and RT_SCOPE_UNIVERSE — a globally-routable address.
  @af_inet 2
  @af_inet6 10
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
  Lists every address in the socket's network namespace.
  """
  @spec list(Socket.t()) :: {:ok, [t()]} | {:error, term}
  def list(%Socket{} = socket) do
    case Request.talk(socket, @rtm_getaddr, nlm_f_dump(), encode(%__MODULE__{})) do
      {:ok, messages} -> {:ok, Enum.map(messages, &decode(&1.payload))}
      {:error, _} = error -> error
    end
  end

  @doc """
  Lists the addresses on the link named `link_name`.
  """
  @spec list(Socket.t(), binary) :: {:ok, [t()]} | {:error, term}
  def list(%Socket{} = socket, link_name) when is_binary(link_name) do
    with {:ok, %Link{index: index}} <- Link.get(socket, link_name),
         {:ok, all} <- list(socket) do
      {:ok, Enum.filter(all, &(&1.index == index))}
    end
  end

  @doc """
  Adds address `ip` (a dotted-quad IPv4 string or an IPv6 string) with prefix
  length `prefix` to the link named `link_name`.
  """
  @spec add(Socket.t(), binary, binary, non_neg_integer) :: :ok | {:error, term}
  def add(%Socket{} = socket, link_name, ip, prefix)
      when is_binary(link_name) and is_binary(ip) and is_integer(prefix) do
    write(
      socket,
      link_name,
      ip,
      prefix,
      @rtm_newaddr,
      nlm_f_create() ||| nlm_f_excl() ||| nlm_f_ack()
    )
  end

  @doc """
  Removes address `ip`/`prefix` from the link named `link_name`.
  """
  @spec delete(Socket.t(), binary, binary, non_neg_integer) :: :ok | {:error, term}
  def delete(%Socket{} = socket, link_name, ip, prefix)
      when is_binary(link_name) and is_binary(ip) and is_integer(prefix) do
    write(socket, link_name, ip, prefix, @rtm_deladdr, nlm_f_ack())
  end

  defp write(socket, link_name, ip, prefix, rtm, flags) do
    with {:ok, {family, addr}} <- parse_address(ip),
         :ok <- check_prefix(family, prefix),
         {:ok, %Link{index: index}} <- Link.get(socket, link_name) do
      message = %__MODULE__{
        family: family,
        prefixlen: prefix,
        scope: @rt_scope_universe,
        index: index,
        # IFA_LOCAL is the interface's own address; IFA_ADDRESS equals it for
        # an ordinary (non-point-to-point) link.
        local: addr,
        address: addr
      }

      case Request.talk(socket, rtm, flags, encode(message)) do
        {:ok, _} -> :ok
        {:error, _} = error -> error
      end
    end
  end

  defp check_prefix(@af_inet, p) when p in 0..32, do: :ok
  defp check_prefix(@af_inet6, p) when p in 0..128, do: :ok
  defp check_prefix(_, p), do: {:error, {:bad_prefix, p}}

  # Parse a dotted-quad or colon-hex string into `{family, bytes}` — the wire
  # form an IFA_* address attribute carries (4 bytes for AF_INET, 16 for
  # AF_INET6).
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
end
