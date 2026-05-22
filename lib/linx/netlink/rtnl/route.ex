defmodule Linx.Netlink.Rtnl.Route do
  @moduledoc """
  rtnetlink routes — the `RTM_*ROUTE` messages.

  `list/1` reads routes; `add/4`, `add_default/2`, `delete/4` and
  `delete_default/2` install and remove them. IPv4 and IPv6 are both
  supported — the address family is detected from the destination and
  gateway strings (which must agree).

  The wire format — `struct rtmsg` and the `RTA_*` attributes
  (`include/uapi/linux/rtnetlink.h`) — is declared with the
  `Linx.Netlink.Codec` DSL.
  """

  use Linx.Netlink.Codec

  import Bitwise
  import Linx.Netlink.Constants

  alias Linx.Netlink.{Request, Socket}

  # rtnetlink route message types.
  @rtm_newroute 24
  @rtm_delroute 25
  @rtm_getroute 26

  # rtmsg field values — include/uapi/linux/rtnetlink.h.
  @af_inet 2
  @af_inet6 10
  @rt_table_main 254
  @rtprot_boot 3
  @rt_scope_universe 0
  # RT_SCOPE_NOWHERE — used on delete to match a route in any scope.
  @rt_scope_nowhere 255
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
    attr(1, :dst, :binary)
    attr(4, :oif, :u32)
    attr(5, :gateway, :binary)
  end

  @doc """
  Lists every route in the socket's network namespace.
  """
  @spec list(Socket.t()) :: {:ok, [t()]} | {:error, term}
  def list(%Socket{} = socket) do
    case Request.talk(socket, @rtm_getroute, nlm_f_dump(), encode(%__MODULE__{})) do
      {:ok, messages} -> {:ok, Enum.map(messages, &decode(&1.payload))}
      {:error, _} = error -> error
    end
  end

  @doc """
  Adds a route to `destination`/`prefix` via `gateway`.

  `destination` and `gateway` are dotted-quad IPv4 or IPv6 strings and must
  share an address family.
  """
  @spec add(Socket.t(), binary, non_neg_integer, binary) :: :ok | {:error, term}
  def add(%Socket{} = socket, destination, prefix, gateway)
      when is_binary(destination) and is_integer(prefix) and is_binary(gateway) do
    write(
      socket,
      destination,
      prefix,
      gateway,
      @rtm_newroute,
      @rt_scope_universe,
      nlm_f_create() ||| nlm_f_excl() ||| nlm_f_ack()
    )
  end

  @doc """
  Adds the default route (`0.0.0.0/0` for IPv4, `::/0` for IPv6) via
  `gateway`.
  """
  @spec add_default(Socket.t(), binary) :: :ok | {:error, term}
  def add_default(socket, gateway) when is_binary(gateway) do
    with {:ok, {family, _}} <- parse_address(gateway) do
      add(socket, default_destination(family), 0, gateway)
    end
  end

  @doc """
  Deletes the route to `destination`/`prefix` via `gateway`.
  """
  @spec delete(Socket.t(), binary, non_neg_integer, binary) :: :ok | {:error, term}
  def delete(%Socket{} = socket, destination, prefix, gateway)
      when is_binary(destination) and is_integer(prefix) and is_binary(gateway) do
    write(socket, destination, prefix, gateway, @rtm_delroute, @rt_scope_nowhere, nlm_f_ack())
  end

  @doc """
  Deletes the default route via `gateway`.
  """
  @spec delete_default(Socket.t(), binary) :: :ok | {:error, term}
  def delete_default(socket, gateway) when is_binary(gateway) do
    with {:ok, {family, _}} <- parse_address(gateway) do
      delete(socket, default_destination(family), 0, gateway)
    end
  end

  defp write(socket, destination, prefix, gateway, rtm, scope, flags) do
    with {:ok, {family, dst}} <- parse_address(destination),
         {:ok, {gw_family, gw}} <- parse_address(gateway),
         :ok <- check_families(family, gw_family),
         :ok <- check_prefix(family, prefix) do
      message = %__MODULE__{
        family: family,
        dst_len: prefix,
        table: @rt_table_main,
        protocol: @rtprot_boot,
        scope: scope,
        type: @rtn_unicast,
        dst: dst,
        gateway: gw
      }

      case Request.talk(socket, rtm, flags, encode(message)) do
        {:ok, _} -> :ok
        {:error, _} = error -> error
      end
    end
  end

  defp check_families(family, family), do: :ok
  defp check_families(_, _), do: {:error, :family_mismatch}

  defp check_prefix(@af_inet, p) when p in 0..32, do: :ok
  defp check_prefix(@af_inet6, p) when p in 0..128, do: :ok
  defp check_prefix(_, p), do: {:error, {:bad_prefix, p}}

  defp default_destination(@af_inet), do: "0.0.0.0"
  defp default_destination(@af_inet6), do: "::"

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
