defmodule Linx.Netlink.Rtnl.Link do
  @moduledoc """
  rtnetlink network links (interfaces) — the `RTM_*LINK` messages.

  A `%Link{}` is a decoded interface: its index, name, link-layer type, flags
  and MTU. `list/1` reads every link in a namespace; `get/2` fetches one by
  name.

  This module is written by hand — the explicit codec the plan's M2 calls for,
  and the reference from which the message DSL is later extracted. The wire
  layouts are `struct ifinfomsg` (`include/uapi/linux/rtnetlink.h`) and the
  `IFLA_*` attributes (`include/uapi/linux/if_link.h`).
  """

  import Bitwise
  import Linx.Netlink.Constants

  alias Linx.Netlink.{Attr, Message, Request, Socket}

  # RTM_GETLINK — request link information.
  @rtm_getlink 18

  # ifinfomsg.ifi_family — links are reported and requested with AF_UNSPEC.
  @af_unspec 0

  # IFLA_* attribute types — include/uapi/linux/if_link.h.
  @ifla_ifname 3
  @ifla_mtu 4

  # net_device flags — include/uapi/linux/if.h. IFF_UP is the administrative
  # "interface enabled" bit.
  @iff_up 0x1

  @enforce_keys [:index]
  defstruct [:index, :name, :type, :flags, :mtu]

  @type t :: %__MODULE__{
          index: pos_integer,
          name: binary | nil,
          type: non_neg_integer,
          flags: non_neg_integer,
          mtu: non_neg_integer | nil
        }

  @doc """
  Lists every link in the socket's network namespace.
  """
  @spec list(Socket.t()) :: {:ok, [t]} | {:error, term}
  def list(%Socket{} = socket) do
    case Request.talk(socket, @rtm_getlink, nlm_f_dump(), ifinfomsg(0, 0, 0)) do
      {:ok, messages} -> {:ok, Enum.map(messages, &decode(&1.payload))}
      {:error, _} = error -> error
    end
  end

  @doc """
  Gets the link named `name`.

  Returns `{:error, {:netlink, errno}}` if there is no such interface.
  """
  @spec get(Socket.t(), binary) :: {:ok, t} | {:error, term}
  def get(%Socket{} = socket, name) when is_binary(name) do
    payload = ifinfomsg(0, 0, 0) <> Attr.encode([{@ifla_ifname, cstr(name)}])

    case Request.talk(socket, @rtm_getlink, 0, payload) do
      {:ok, [%Message{payload: body} | _]} -> {:ok, decode(body)}
      {:ok, []} -> {:error, :no_reply}
      {:error, _} = error -> error
    end
  end

  @doc """
  Returns whether `link` is administratively up (has `IFF_UP` set).
  """
  @spec up?(t) :: boolean
  def up?(%__MODULE__{flags: flags}), do: (flags &&& @iff_up) != 0

  @doc """
  Decodes an `RTM_*LINK` message body — an `ifinfomsg` and its attributes —
  into a `%Link{}`.
  """
  @spec decode(binary) :: t
  def decode(
        <<_family::8, _pad::8, type::native-16, index::native-signed-32, flags::native-32,
          _change::native-32, attrs::binary>>
      ) do
    decoded = Attr.decode(attrs)

    %__MODULE__{
      index: index,
      type: type,
      flags: flags,
      name: attr_string(decoded, @ifla_ifname),
      mtu: attr_u32(decoded, @ifla_mtu)
    }
  end

  # struct ifinfomsg — the 16-byte rtnetlink link-message header.
  defp ifinfomsg(index, flags, change) do
    <<@af_unspec::8, 0::8, 0::native-16, index::native-signed-32, flags::native-32,
      change::native-32>>
  end

  # A NUL-terminated string, as netlink string attributes carry.
  defp cstr(string), do: string <> <<0>>

  defp attr_string(attrs, type) do
    case List.keyfind(attrs, type, 0) do
      {^type, value} -> String.trim_trailing(value, <<0>>)
      nil -> nil
    end
  end

  defp attr_u32(attrs, type) do
    case List.keyfind(attrs, type, 0) do
      {^type, <<value::native-32>>} -> value
      _ -> nil
    end
  end
end
