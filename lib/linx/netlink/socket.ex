defmodule Linx.Netlink.Socket do
  @moduledoc """
  An `AF_NETLINK` socket, opened in a chosen network namespace.

  A netlink socket is bound for its whole life to the network namespace it was
  created in. `open/2` selects that namespace:

    * `:host` — the BEAM's own network namespace.
    * `{:pid, pid}` / `{:path, path}` — another network namespace. The BEAM
      cannot `setns` on a scheduler thread, so `Linx.Netlink.Socket.Native`
      does it on a throwaway thread and hands back the fd, which `:socket`
      adopts.

  `protocol` is the netlink protocol number — `NETLINK_ROUTE`,
  `NETLINK_GENERIC`, and so on — so one socket type serves every netlink
  family.

  The struct carries an `:atomics` sequence counter. Netlink echoes a
  request's sequence number back in its reply; `next_seq/1` hands out a fresh
  one per request so a stale or unsolicited message can't be mistaken for the
  current reply. The counter is mutable shared state, so a `%Socket{}` works
  correctly whether driven synchronously by one process or, later, owned by a
  connection process.

  Close every socket with `close/1` when done.
  """

  alias Linx.Netlink.Socket.Native

  # AF_NETLINK — the netlink address family. Stable kernel ABI; defined here
  # rather than via a constants module to keep this lowest layer self-contained.
  @af_netlink 16

  @enforce_keys [:socket, :netns, :protocol, :seq]
  defstruct [:socket, :netns, :protocol, :seq]

  @type netns :: :host | {:pid, pos_integer} | {:path, binary}

  @type t :: %__MODULE__{
          socket: :socket.socket(),
          netns: netns,
          protocol: non_neg_integer,
          seq: :atomics.atomics_ref()
        }

  @doc """
  Opens a netlink socket of `protocol` in network namespace `netns`.

  Returns `{:ok, socket}` or `{:error, reason}`. Pass the socket to the rest
  of `Linx.Netlink`, and `close/1` it when done.
  """
  @spec open(non_neg_integer, netns) :: {:ok, t} | {:error, term}
  def open(protocol, netns \\ :host)

  def open(protocol, :host) when is_integer(protocol) and protocol >= 0 do
    case :socket.open(@af_netlink, :raw, protocol) do
      {:ok, socket} -> {:ok, build(socket, :host, protocol)}
      {:error, reason} -> {:error, {:socket, reason}}
    end
  end

  def open(protocol, {:pid, pid})
      when is_integer(protocol) and protocol >= 0 and is_integer(pid) and pid > 0 do
    open(protocol, {:path, "/proc/#{pid}/ns/net"})
  end

  def open(protocol, {:path, path} = netns)
      when is_integer(protocol) and protocol >= 0 and is_binary(path) do
    with {:ok, fd} <- Native.open_in_netns(path, protocol) do
      case :socket.open(fd) do
        {:ok, socket} ->
          {:ok, build(socket, netns, protocol)}

        {:error, reason} ->
          # :socket declined the fd, so it is still ours — do not leak it.
          Native.close_fd(fd)
          {:error, {:socket, reason}}
      end
    end
  end

  @doc """
  Returns the next netlink sequence number for `socket`.

  Sequence numbers start at 1; 0 is reserved for unsolicited kernel messages,
  so a reply bearing seq 0 is never an answer to one of our requests.
  """
  @spec next_seq(t) :: pos_integer
  def next_seq(%__MODULE__{seq: seq}), do: :atomics.add_get(seq, 1, 1)

  @doc "Closes a socket from `open/2`."
  @spec close(t) :: :ok
  def close(%__MODULE__{socket: socket}), do: :socket.close(socket)

  defp build(socket, netns, protocol) do
    %__MODULE__{
      socket: socket,
      netns: netns,
      protocol: protocol,
      # :atomics start at 0, so the first add_get/3 in next_seq/1 yields 1.
      seq: :atomics.new(1, signed: false)
    }
  end
end
