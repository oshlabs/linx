defmodule Linx.Netlink.Rtnl.Link do
  @moduledoc """
  rtnetlink network links (interfaces) — the `RTM_*LINK` messages.

  A `%Link{}` is a decoded interface: its index, name, link-layer type, flags,
  MTU and parent. `list/1` and `get/2` read links; `create_macvlan/4`,
  `create_ipvlan/4`, `delete/2`, `set_up/2`, `set_down/2` and `move_to_netns/3`
  change them.

  The wire format — `struct ifinfomsg` (`include/uapi/linux/rtnetlink.h`) and
  the `IFLA_*` attributes (`include/uapi/linux/if_link.h`) — is declared with
  the `Linx.Netlink.Codec` DSL, which generates the `%Link{}` struct and its
  `encode/1` / `decode/1`. `IFLA_LINKINFO` is the one exception: its data is
  chosen by the link kind, so it is built by hand (see `linkinfo/2`).
  """

  use Linx.Netlink.Codec

  import Bitwise
  import Linx.Netlink.Constants

  alias Linx.Netlink.{Attr, Message, Request, Socket}

  # rtnetlink link message types.
  @rtm_newlink 16
  @rtm_dellink 17
  @rtm_getlink 18

  # net_device flags — include/uapi/linux/if.h. IFF_UP is the administrative
  # "interface enabled" bit.
  @iff_up 0x1

  # IFLA_LINKINFO and its sub-attributes — include/uapi/linux/if_link.h.
  @ifla_linkinfo 18
  @ifla_info_kind 1
  @ifla_info_data 2

  # macvlan and ipvlan each carry a single u32 "mode" at attribute 1 of
  # IFLA_INFO_DATA — include/uapi/linux/if_link.h.
  @info_data_mode 1
  @macvlan_mode_private 1
  @macvlan_mode_bridge 4
  @ipvlan_mode_l2 0
  @ipvlan_mode_l3 1

  codec do
    # struct ifinfomsg — the 16-byte rtnetlink link-message header.
    header do
      field(:family, :u8)
      pad(1)
      field(:type, :u16)
      field(:index, :s32)
      field(:flags, :u32)
      field(:change, :u32)
    end

    # IFLA_* attributes — include/uapi/linux/if_link.h.
    attr(3, :name, :string)
    attr(4, :mtu, :u32)
    attr(5, :link, :u32)
    attr(19, :net_ns_pid, :u32)
  end

  @doc """
  Lists every link in the socket's network namespace.
  """
  @spec list(Socket.t()) :: {:ok, [t()]} | {:error, term}
  def list(%Socket{} = socket) do
    case Request.talk(socket, @rtm_getlink, nlm_f_dump(), encode(%__MODULE__{})) do
      {:ok, messages} -> {:ok, Enum.map(messages, &decode(&1.payload))}
      {:error, _} = error -> error
    end
  end

  @doc """
  Gets the link named `name`.

  Returns `{:error, %Linx.Netlink.Error{errno: :enodev}}` if there is no such
  interface.
  """
  @spec get(Socket.t(), binary) :: {:ok, t()} | {:error, term}
  def get(%Socket{} = socket, name) when is_binary(name) do
    case Request.talk(socket, @rtm_getlink, 0, encode(%__MODULE__{name: name})) do
      {:ok, [%Message{payload: body} | _]} -> {:ok, decode(body)}
      {:ok, []} -> {:error, :no_reply}
      {:error, _} = error -> error
    end
  end

  @doc """
  Returns whether `link` is administratively up (has `IFF_UP` set).
  """
  @spec up?(t()) :: boolean
  def up?(%__MODULE__{flags: flags}), do: (flags &&& @iff_up) != 0

  @doc """
  Creates a `macvlan` link named `name` on parent interface `parent`.

  `mode` is `:bridge` (default — sibling macvlans on the same parent can reach
  each other) or `:private`.
  """
  @spec create_macvlan(Socket.t(), binary, binary, :bridge | :private) :: :ok | {:error, term}
  def create_macvlan(socket, name, parent, mode \\ :bridge),
    do: create(socket, name, parent, "macvlan", macvlan_mode(mode))

  @doc """
  Creates an `ipvlan` link named `name` on parent interface `parent`.

  `mode` is `:l3` (default — routed; works where macvlan cannot, e.g. on
  Wi-Fi) or `:l2`.
  """
  @spec create_ipvlan(Socket.t(), binary, binary, :l2 | :l3) :: :ok | {:error, term}
  def create_ipvlan(socket, name, parent, mode \\ :l3),
    do: create(socket, name, parent, "ipvlan", ipvlan_mode(mode))

  @doc """
  Deletes the link named `name`.
  """
  @spec delete(Socket.t(), binary) :: :ok | {:error, term}
  def delete(%Socket{} = socket, name) when is_binary(name) do
    with {:ok, %__MODULE__{index: index}} <- get(socket, name) do
      ack(Request.talk(socket, @rtm_dellink, nlm_f_ack(), encode(%__MODULE__{index: index})))
    end
  end

  @doc """
  Brings link `name` administratively up (sets `IFF_UP`).
  """
  @spec set_up(Socket.t(), binary) :: :ok | {:error, term}
  def set_up(socket, name), do: set_flags(socket, name, @iff_up)

  @doc """
  Brings link `name` administratively down (clears `IFF_UP`).
  """
  @spec set_down(Socket.t(), binary) :: :ok | {:error, term}
  def set_down(socket, name), do: set_flags(socket, name, 0)

  @doc """
  Moves link `name` into the network namespace of process `pid`.
  """
  @spec move_to_netns(Socket.t(), binary, pos_integer) :: :ok | {:error, term}
  def move_to_netns(%Socket{} = socket, name, pid)
      when is_binary(name) and is_integer(pid) and pid > 0 do
    with {:ok, %__MODULE__{index: index}} <- get(socket, name) do
      body = encode(%__MODULE__{index: index, net_ns_pid: pid})
      ack(Request.talk(socket, @rtm_newlink, nlm_f_ack(), body))
    end
  end

  # --- internals --------------------------------------------------------------

  defp create(%Socket{} = socket, name, parent, kind, mode_value)
       when is_binary(name) and is_binary(parent) do
    with {:ok, %__MODULE__{index: parent_index}} <- get(socket, parent) do
      payload =
        encode(%__MODULE__{name: name, link: parent_index}) <> linkinfo(kind, mode_value)

      flags = nlm_f_create() ||| nlm_f_excl() ||| nlm_f_ack()
      ack(Request.talk(socket, @rtm_newlink, flags, payload))
    end
  end

  defp set_flags(%Socket{} = socket, name, flags) when is_binary(name) do
    with {:ok, %__MODULE__{index: index}} <- get(socket, name) do
      # `change` masks which flag bits the kernel applies — IFF_UP only — so
      # set_down clears just that bit and leaves the rest of the flags alone.
      body = encode(%__MODULE__{index: index, flags: flags, change: @iff_up})
      ack(Request.talk(socket, @rtm_newlink, nlm_f_ack(), body))
    end
  end

  # IFLA_LINKINFO — a nested attribute set carrying the link kind and its
  # kind-specific data. macvlan and ipvlan each put a single u32 mode at
  # attribute 1 of IFLA_INFO_DATA. This is hand-written rather than declared
  # in the codec because IFLA_INFO_DATA's format is selected by the kind —
  # the explicit escape hatch for sub-message dispatch (see PLAN.md, M4).
  defp linkinfo(kind, mode_value) do
    info_data = Attr.encode([{@info_data_mode, <<mode_value::native-32>>}])

    Attr.encode([
      {@ifla_linkinfo,
       Attr.encode([{@ifla_info_kind, kind <> <<0>>}, {@ifla_info_data, info_data}])}
    ])
  end

  defp macvlan_mode(:bridge), do: @macvlan_mode_bridge
  defp macvlan_mode(:private), do: @macvlan_mode_private

  defp ipvlan_mode(:l3), do: @ipvlan_mode_l3
  defp ipvlan_mode(:l2), do: @ipvlan_mode_l2

  defp ack({:ok, _messages}), do: :ok
  defp ack({:error, _} = error), do: error
end
