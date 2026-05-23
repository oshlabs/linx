defmodule Linx.Netlink.Rtnl.Link do
  @moduledoc """
  rtnetlink network links (interfaces) — the `RTM_*LINK` messages.

  A `%Link{}` is a decoded interface: its index, name, link-layer type, flags,
  MTU, MAC address, parent, master and kind-specific information. Read verbs
  `list/1` / `get/2` retrieve interfaces; mutating verbs create, delete and
  configure them.

  ## Creating

  Several kinds of virtual link are supported, each by its own constructor:

      Link.create_macvlan(socket, name, parent, mode \\\\ :bridge)
      Link.create_ipvlan (socket, name, parent, mode \\\\ :l3)
      Link.create_veth   (socket, name, peer_name)
      Link.create_vlan   (socket, name, parent, vlan_id)
      Link.create_bridge (socket, name)
      Link.create_dummy  (socket, name)

  ## Configuring

  `set_up/2` / `set_down/2` toggle `IFF_UP`; `set_mtu/3`, `set_name/3`,
  `set_address/3` and `set_master/3` change the MTU, name, MAC and bridge /
  bond master respectively; `move_to_netns/3` hands the link to another
  network namespace.

  ## Wire format

  `struct ifinfomsg` (`include/uapi/linux/rtnetlink.h`) and the `IFLA_*`
  attributes (`include/uapi/linux/if_link.h`) — declared with the
  `Linx.Netlink.Codec` DSL. `IFLA_LINKINFO` is itself a sub-codec
  (`Linx.Netlink.Rtnl.LinkInfo`) whose `IFLA_INFO_DATA` is dispatched on the
  kind value, picking the right per-kind module (`LinkInfo.Macvlan`,
  `LinkInfo.Veth`, …).
  """

  use Linx.Netlink.Codec

  import Bitwise
  import Linx.Netlink.Constants

  alias Linx.MAC
  alias Linx.Netlink.{Error, Message, Request, Socket}
  alias Linx.Netlink.Rtnl.LinkInfo

  # rtnetlink link message types.
  @rtm_newlink 16
  @rtm_dellink 17
  @rtm_getlink 18

  # net_device flags — include/uapi/linux/if.h. IFF_UP is the administrative
  # "interface enabled" bit.
  @iff_up 0x1

  # macvlan / ipvlan modes — include/uapi/linux/if_link.h.
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
    attr(1, :address, Linx.MAC)
    attr(3, :name, :string)
    attr(4, :mtu, :u32)
    attr(5, :link, :u32)
    attr(10, :master, :u32)
    attr(18, :linkinfo, LinkInfo)
    attr(19, :net_ns_pid, :u32)
  end

  # --- reads -----------------------------------------------------------------

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
      {:ok, [%Message{payload: body} | _]} ->
        {:ok, decode(body)}

      {:ok, []} ->
        {:error, :no_reply}

      {:error, %Error{errno: :enodev, message: nil} = err} ->
        {:error, %{err | message: ~s|no such interface "#{name}"|}}

      {:error, _} = error ->
        error
    end
  end

  @doc """
  Returns whether `link` is administratively up (has `IFF_UP` set).
  """
  @spec up?(t()) :: boolean
  def up?(%__MODULE__{flags: flags}), do: (flags &&& @iff_up) != 0

  # --- create ----------------------------------------------------------------

  @doc """
  Creates a `macvlan` link named `name` on parent interface `parent`.

  `mode` is `:bridge` (default) or `:private`.
  """
  @spec create_macvlan(Socket.t(), binary, binary, :bridge | :private) :: :ok | {:error, term}
  def create_macvlan(socket, name, parent, mode \\ :bridge) do
    create_kinded(socket, name, parent, %LinkInfo{
      kind: "macvlan",
      info_data: %LinkInfo.Macvlan{mode: macvlan_mode(mode)}
    })
  end

  @doc """
  Creates an `ipvlan` link named `name` on parent interface `parent`.

  `mode` is `:l3` (default) or `:l2`.
  """
  @spec create_ipvlan(Socket.t(), binary, binary, :l2 | :l3) :: :ok | {:error, term}
  def create_ipvlan(socket, name, parent, mode \\ :l3) do
    create_kinded(socket, name, parent, %LinkInfo{
      kind: "ipvlan",
      info_data: %LinkInfo.Ipvlan{mode: ipvlan_mode(mode)}
    })
  end

  @doc """
  Creates an `vlan` sub-interface named `name` on parent `parent` carrying
  802.1Q VLAN tag `vlan_id` (1..4094).
  """
  @spec create_vlan(Socket.t(), binary, binary, 1..4094) :: :ok | {:error, term}
  def create_vlan(socket, name, parent, vlan_id) when vlan_id in 1..4094 do
    create_kinded(socket, name, parent, %LinkInfo{
      kind: "vlan",
      info_data: %LinkInfo.Vlan{id: vlan_id}
    })
  end

  @doc """
  Creates a `veth` pair — two interfaces named `name` and `peer_name`,
  connected back-to-back.
  """
  @spec create_veth(Socket.t(), binary, binary) :: :ok | {:error, term}
  def create_veth(%Socket{} = socket, name, peer_name)
      when is_binary(name) and is_binary(peer_name) do
    body =
      encode(%__MODULE__{
        name: name,
        linkinfo: %LinkInfo{
          kind: "veth",
          info_data: %LinkInfo.Veth{peer: %__MODULE__{name: peer_name}}
        }
      })

    create_request(socket, body)
  end

  @doc """
  Creates an empty Linux bridge named `name`.
  """
  @spec create_bridge(Socket.t(), binary) :: :ok | {:error, term}
  def create_bridge(%Socket{} = socket, name) when is_binary(name) do
    create_request(
      socket,
      encode(%__MODULE__{name: name, linkinfo: %LinkInfo{kind: "bridge"}})
    )
  end

  @doc """
  Creates a `dummy` interface named `name` — a loopback-like virtual link
  with no real packet path, useful as a stable address holder or a test
  fixture.
  """
  @spec create_dummy(Socket.t(), binary) :: :ok | {:error, term}
  def create_dummy(%Socket{} = socket, name) when is_binary(name) do
    create_request(
      socket,
      encode(%__MODULE__{name: name, linkinfo: %LinkInfo{kind: "dummy"}})
    )
  end

  # --- delete / config -------------------------------------------------------

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
  Sets link `name`'s MTU to `mtu`.
  """
  @spec set_mtu(Socket.t(), binary, pos_integer) :: :ok | {:error, term}
  def set_mtu(socket, name, mtu) when is_binary(name) and is_integer(mtu) and mtu > 0 do
    configure(socket, name, %{mtu: mtu})
  end

  @doc """
  Renames link `name` to `new_name`.
  """
  @spec set_name(Socket.t(), binary, binary) :: :ok | {:error, term}
  def set_name(socket, name, new_name) when is_binary(name) and is_binary(new_name) do
    configure(socket, name, %{name: new_name})
  end

  @doc """
  Sets link `name`'s MAC address to `mac` — a colon-separated hex string,
  e.g. `"aa:bb:cc:dd:ee:ff"`, or a `Linx.MAC`.
  """
  @spec set_address(Socket.t(), binary, binary | MAC.t()) :: :ok | {:error, term}
  def set_address(socket, name, mac) when is_binary(name) do
    with {:ok, mac_struct} <- coerce_mac(mac) do
      configure(socket, name, %{address: mac_struct})
    end
  end

  @doc """
  Enslaves link `name` to `master_name` — typically a bridge or bond.
  """
  @spec set_master(Socket.t(), binary, binary) :: :ok | {:error, term}
  def set_master(%Socket{} = socket, name, master_name)
      when is_binary(name) and is_binary(master_name) do
    with {:ok, %__MODULE__{index: master_index}} <- get(socket, master_name),
         {:ok, %__MODULE__{index: index}} <- get(socket, name) do
      body = encode(%__MODULE__{index: index, master: master_index})
      ack(Request.talk(socket, @rtm_newlink, nlm_f_ack(), body))
    end
  end

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

  # --- internals -------------------------------------------------------------

  defp create_kinded(%Socket{} = socket, name, parent, %LinkInfo{} = linkinfo)
       when is_binary(name) and is_binary(parent) do
    case get(socket, parent) do
      {:ok, %__MODULE__{index: parent_index}} ->
        body = encode(%__MODULE__{name: name, link: parent_index, linkinfo: linkinfo})
        create_request(socket, body)

      {:error, %Error{errno: :enodev} = err} ->
        {:error, %{err | message: ~s|no such parent interface "#{parent}"|}}

      {:error, _} = error ->
        error
    end
  end

  defp create_request(socket, body) do
    flags = nlm_f_create() ||| nlm_f_excl() ||| nlm_f_ack()
    ack(Request.talk(socket, @rtm_newlink, flags, body))
  end

  defp set_flags(%Socket{} = socket, name, flags) when is_binary(name) do
    with {:ok, %__MODULE__{index: index}} <- get(socket, name) do
      # `change` masks which flag bits the kernel applies — IFF_UP only — so
      # set_down clears just that bit and leaves the rest of the flags alone.
      body = encode(%__MODULE__{index: index, flags: flags, change: @iff_up})
      ack(Request.talk(socket, @rtm_newlink, nlm_f_ack(), body))
    end
  end

  # Resolve `name` to its index and send RTM_NEWLINK with a minimal message
  # carrying only :index plus the fields in `updates` — the request changes
  # those fields and leaves the rest alone.
  defp configure(%Socket{} = socket, name, updates) when is_map(updates) do
    with {:ok, %__MODULE__{index: index}} <- get(socket, name) do
      message = struct(__MODULE__, [{:index, index} | Map.to_list(updates)])
      ack(Request.talk(socket, @rtm_newlink, nlm_f_ack(), encode(message)))
    end
  end

  defp macvlan_mode(:bridge), do: @macvlan_mode_bridge
  defp macvlan_mode(:private), do: @macvlan_mode_private

  defp ipvlan_mode(:l3), do: @ipvlan_mode_l3
  defp ipvlan_mode(:l2), do: @ipvlan_mode_l2

  defp ack({:ok, _messages}), do: :ok
  defp ack({:error, _} = error), do: error

  defp coerce_mac(%MAC{} = mac), do: {:ok, mac}
  defp coerce_mac(string) when is_binary(string), do: MAC.parse(string)

  defimpl Inspect do
    def inspect(link, _opts) do
      import Bitwise

      parts =
        [
          link.name && ~s|"#{link.name}"|,
          "(#{link.index})",
          if((link.flags &&& 0x1) != 0, do: "UP", else: "DOWN"),
          link.mtu && "MTU=#{link.mtu}",
          link.linkinfo && link.linkinfo.kind && "kind=#{link.linkinfo.kind}"
        ]
        |> Enum.reject(&is_nil/1)
        |> Enum.join(" ")

      "#Linx.Netlink.Rtnl.Link<#{parts}>"
    end
  end
end
