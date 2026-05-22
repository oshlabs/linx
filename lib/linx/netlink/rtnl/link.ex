defmodule Linx.Netlink.Rtnl.Link do
  @moduledoc """
  rtnetlink network links (interfaces) — the `RTM_*LINK` messages.

  A `%Link{}` is a decoded interface: its index, name, link-layer type, flags
  and MTU. `list/1` reads every link in a namespace; `get/2` fetches one by
  name.

  The wire format — `struct ifinfomsg` (`include/uapi/linux/rtnetlink.h`) and
  the `IFLA_*` attributes (`include/uapi/linux/if_link.h`) — is declared with
  the `Linx.Netlink.Codec` DSL, which generates the `%Link{}` struct and its
  `encode/1` / `decode/1`. This module was first written by hand (the plan's
  M2) and is now the codec the DSL was extracted from.
  """

  use Linx.Netlink.Codec

  import Bitwise
  import Linx.Netlink.Constants

  alias Linx.Netlink.{Message, Request, Socket}

  # RTM_GETLINK — request link information.
  @rtm_getlink 18

  # net_device flags — include/uapi/linux/if.h. IFF_UP is the administrative
  # "interface enabled" bit.
  @iff_up 0x1

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

  Returns `{:error, {:netlink, errno}}` if there is no such interface.
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
end
