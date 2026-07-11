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

  # SOL_NETLINK and NETLINK_EXT_ACK — set this option on the socket to ask
  # the kernel to include a human-readable string in NLMSG_ERROR replies
  # (parsed by Linx.Netlink.Request into Linx.Netlink.Error.message). Linux
  # >= 4.12.
  @sol_netlink 270
  @netlink_ext_ack 11
  @netlink_add_membership 1
  @netlink_drop_membership 2

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
      {:ok, socket} -> build(socket, :host, protocol)
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
          build(socket, netns, protocol)

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

  The wire field is 32 bits, so the 64-bit counter is masked here — the value
  handed out is always exactly what the kernel echoes back. (Unmasked, request
  2³²+1 would never match its echoed reply and `talk/4` would block forever.)
  The wrap skips 0 to keep the reservation above.
  """
  @spec next_seq(t) :: pos_integer
  def next_seq(%__MODULE__{seq: seq} = socket) do
    import Bitwise

    case :atomics.add_get(seq, 1, 1) &&& 0xFFFFFFFF do
      0 -> next_seq(socket)
      n -> n
    end
  end

  @doc "Closes a socket from `open/2`."
  @spec close(t) :: :ok
  def close(%__MODULE__{socket: socket}), do: :socket.close(socket)

  # One netlink datagram can far exceed OTP's default 8 KiB read length
  # (an RTM_GETLINK dump chunk on a host with SR-IOV VFs easily does).
  # 64 KiB is the ceiling the kernel itself uses for dump allocations.
  @recv_size 65_536

  @doc """
  Receives one datagram from `socket`.

  Reads up to 64 KiB per datagram — `:socket.recv/1`'s default read length
  is only 8 KiB, which silently truncates large netlink dump chunks. If the
  kernel still flags the read as truncated (`MSG_TRUNC` in the returned
  message flags), returns `{:error, :truncated}` instead of handing back a
  cut buffer that would decode into an incomplete message list.

  The second argument is either a read size in bytes or a keyword list:
  `:size` (default 64 KiB) and `:timeout` in ms (default `:infinity`;
  `{:error, :timeout}` when it elapses).
  """
  @spec recv_datagram(t, pos_integer | keyword) :: {:ok, binary} | {:error, term}
  def recv_datagram(socket, size_or_opts \\ [])

  def recv_datagram(%__MODULE__{} = socket, size) when is_integer(size),
    do: recv_datagram(socket, size: size)

  def recv_datagram(%__MODULE__{socket: socket}, opts) when is_list(opts) do
    size = Keyword.get(opts, :size, @recv_size)
    timeout = Keyword.get(opts, :timeout, :infinity)

    case :socket.recvmsg(socket, size, 0, [], timeout) do
      {:ok, %{flags: flags, iov: iov}} ->
        if :trunc in flags do
          {:error, :truncated}
        else
          {:ok, IO.iodata_to_binary(iov)}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Joins a netlink multicast group on `socket`.

  Subsequent reads will receive multicast events for `group` (a
  protocol-family-specific group number — `NFNLGRP_NFTABLES = 7`
  for nfnetlink ruleset events, `RTNLGRP_LINK = 1` for rtnetlink
  link events, etc.).
  """
  @spec add_membership(t(), pos_integer()) :: :ok | {:error, term()}
  def add_membership(%__MODULE__{socket: socket}, group)
      when is_integer(group) and group > 0 do
    :socket.setopt_native(
      socket,
      {@sol_netlink, @netlink_add_membership},
      <<group::native-32>>
    )
  end

  @doc "Leaves a multicast group joined via `add_membership/2`."
  @spec drop_membership(t(), pos_integer()) :: :ok | {:error, term()}
  def drop_membership(%__MODULE__{socket: socket}, group)
      when is_integer(group) and group > 0 do
    :socket.setopt_native(
      socket,
      {@sol_netlink, @netlink_drop_membership},
      <<group::native-32>>
    )
  end

  @doc """
  Sets the socket receive buffer size (`SO_RCVBUF`) in bytes.

  For multicast monitors that may face heavy churn, a larger
  buffer reduces the chance of `ENOBUFS` overflow. The kernel
  silently clamps to its `net.core.rmem_max` ceiling — use
  `SO_RCVBUFFORCE` (requires `CAP_NET_ADMIN`) to override.
  """
  @spec set_rcvbuf(t(), pos_integer()) :: :ok | {:error, term()}
  def set_rcvbuf(%__MODULE__{socket: socket}, bytes)
      when is_integer(bytes) and bytes > 0 do
    :socket.setopt(socket, {:socket, :rcvbuf}, bytes)
  end

  defp build(socket, netns, protocol) do
    # Best-effort: pre-4.12 kernels do not know NETLINK_EXT_ACK and return
    # EINVAL here. Ignore the result — without extended ack we just get plain
    # errno-only errors, which is still correct.
    _ = :socket.setopt_native(socket, {@sol_netlink, @netlink_ext_ack}, <<1::native-32>>)

    # Explicit bind with nl_pid=0 (kernel auto-assigns). Required for
    # multicast: an unbound netlink socket never receives broadcast
    # events even after NETLINK_ADD_MEMBERSHIP — so a bind failure is
    # NOT best-effort: swallowing it would hand back a socket whose
    # Monitor never sees an event, with no error anywhere. Erlang's
    # :socket.bind/2 doesn't speak netlink sockaddrs, so the bind goes
    # via the NIF.
    with {:ok, fd} <- :socket.getopt(socket, {:otp, :fd}),
         :ok <- Native.bind_netlink(fd, 0) do
      {:ok,
       %__MODULE__{
         socket: socket,
         netns: netns,
         protocol: protocol,
         # :atomics start at 0, so the first add_get/3 in next_seq/1 yields 1.
         seq: :atomics.new(1, signed: false)
       }}
    else
      {:error, reason} ->
        :socket.close(socket)
        {:error, {:bind, reason}}
    end
  end
end
