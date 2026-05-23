defmodule Linx.Netlink.Rtnl.Address do
  @moduledoc """
  rtnetlink interface addresses — the `RTM_*ADDR` messages.

  `list/1` and `list/2` read addresses; `add/4` and `delete/4` assign and
  remove them. IPv4 and IPv6 are both supported — the address family is
  detected from the IP value.

  Address fields (`:address`, `:local`) on a decoded `%Address{}` are
  `Linx.IP` structs, not raw bytes; they accept either an `Linx.IP` or a
  string at the verb's input.

  The wire format — `struct ifaddrmsg` and the `IFA_*` attributes
  (`include/uapi/linux/if_addr.h`) — is declared with the
  `Linx.Netlink.Codec` DSL.
  """

  use Linx.Netlink.Codec

  import Bitwise
  import Linx.Netlink.Constants

  alias Linx.IP
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

    # IFA_* attributes — include/uapi/linux/if_addr.h. The values are
    # `Linx.IP` structs; the codec engine handles the bytes-to-IP conversion.
    attr(1, :address, Linx.IP)
    attr(2, :local, Linx.IP)
  end

  @doc "Lists every address in the socket's network namespace."
  @spec list(Socket.t()) :: {:ok, [t()]} | {:error, term}
  def list(%Socket{} = socket) do
    case Request.talk(socket, @rtm_getaddr, nlm_f_dump(), encode(%__MODULE__{})) do
      {:ok, messages} -> {:ok, Enum.map(messages, &decode(&1.payload))}
      {:error, _} = error -> error
    end
  end

  @doc "Lists the addresses on the link named `link_name`."
  @spec list(Socket.t(), binary) :: {:ok, [t()]} | {:error, term}
  def list(%Socket{} = socket, link_name) when is_binary(link_name) do
    with {:ok, %Link{index: index}} <- Link.get(socket, link_name),
         {:ok, all} <- list(socket) do
      {:ok, Enum.filter(all, &(&1.index == index))}
    end
  end

  @doc """
  Adds address `ip` with prefix length `prefix` to link `link_name`.

  `ip` may be a string (`"10.0.0.5"`, `"fc00::1"`) or a `Linx.IP`. The
  address family is taken from the IP.
  """
  @spec add(Socket.t(), binary, binary | IP.t(), non_neg_integer) :: :ok | {:error, term}
  def add(%Socket{} = socket, link_name, ip, prefix)
      when is_binary(link_name) and is_integer(prefix) do
    write(
      socket,
      link_name,
      ip,
      prefix,
      @rtm_newaddr,
      nlm_f_create() ||| nlm_f_excl() ||| nlm_f_ack()
    )
  end

  @doc "Removes address `ip`/`prefix` from link `link_name`."
  @spec delete(Socket.t(), binary, binary | IP.t(), non_neg_integer) :: :ok | {:error, term}
  def delete(%Socket{} = socket, link_name, ip, prefix)
      when is_binary(link_name) and is_integer(prefix) do
    write(socket, link_name, ip, prefix, @rtm_deladdr, nlm_f_ack())
  end

  defp write(socket, link_name, ip, prefix, rtm, flags) do
    with {:ok, %IP{family: family} = ip_struct} <- coerce_ip(ip),
         :ok <- check_prefix(family, prefix),
         {:ok, %Link{index: index}} <- Link.get(socket, link_name) do
      message = %__MODULE__{
        family: family_int(family),
        prefixlen: prefix,
        scope: @rt_scope_universe,
        index: index,
        # IFA_LOCAL is the interface's own address; IFA_ADDRESS equals it for
        # an ordinary (non-point-to-point) link.
        local: ip_struct,
        address: ip_struct
      }

      case Request.talk(socket, rtm, flags, encode(message)) do
        {:ok, _} -> :ok
        {:error, _} = error -> error
      end
    end
  end

  defp coerce_ip(%IP{} = ip), do: {:ok, ip}
  defp coerce_ip(string) when is_binary(string), do: IP.parse(string)

  defp check_prefix(:inet, p) when p in 0..32, do: :ok
  defp check_prefix(:inet6, p) when p in 0..128, do: :ok
  defp check_prefix(_, p), do: {:error, {:bad_prefix, p}}

  defp family_int(:inet), do: @af_inet
  defp family_int(:inet6), do: @af_inet6

  defimpl Inspect do
    def inspect(%{address: address, prefixlen: prefix, index: index}, _opts) do
      ip_str = if address, do: Linx.IP.to_string(address), else: "?"
      "#Linx.Netlink.Rtnl.Address<#{ip_str}/#{prefix} ifindex=#{index}>"
    end
  end
end
