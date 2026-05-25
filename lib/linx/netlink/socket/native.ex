defmodule Linx.Netlink.Socket.Native do
  @moduledoc """
  The native half of `Linx.Netlink.Socket`: opens an `AF_NETLINK` socket
  *inside* a given network namespace.

  This is a NIF (`c_src/netlink_socket.c`), loaded into the BEAM. It exists
  because `Linx.Netlink` is otherwise pure Elixir: the BEAM can open and drive
  a netlink socket itself, but only in *its own* network namespace. Reaching
  another netns needs `setns(2)`, which acts per-thread — unsafe to run on a
  BEAM scheduler, where it would strand unrelated work in the wrong namespace.

  `open_in_netns/2` does the `setns` on a private, throwaway thread that opens
  the socket and then exits. A socket is permanently bound to the netns that
  was current when it was created, so the fd outlives the thread and is usable
  from any BEAM thread afterward.

  The result is a raw integer fd. The caller adopts it — typically with
  `:socket.open/1` — and is then responsible for closing it.
  """

  @on_load :load_nif

  @doc false
  def load_nif do
    :code.priv_dir(:linx)
    |> :filename.join(~c"netlink_socket")
    |> :erlang.load_nif(0)
  end

  @doc """
  Opens a netlink socket of `protocol` inside the network namespace named by
  `netns_path` and returns `{:ok, fd}` — a raw, netns-pinned file descriptor.

  `netns_path` names a network-namespace file: typically `/proc/<pid>/ns/net`,
  or `/proc/self/ns/net` for the BEAM's own (host) network namespace.
  `protocol` is the netlink protocol number passed to `socket(2)` — e.g.
  `NETLINK_ROUTE` (0) or `NETLINK_GENERIC` (16).

  On failure returns `{:error, {stage, errno}}`, where `stage` is `:open`,
  `:setns`, `:socket` or `:thread` and `errno` is the integer error number of
  the failing step.

  The returned fd belongs to the caller and is not closed by this module.
  """
  @spec open_in_netns(binary, non_neg_integer) ::
          {:ok, non_neg_integer} | {:error, {atom, integer}}
  def open_in_netns(_netns_path, _protocol), do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Closes a descriptor returned by `open_in_netns/2`.

  Needed only on the error path where `:socket.open/1` declines to adopt the
  fd, leaving it owned by Elixir rather than by a socket object. On the normal
  path the adopting socket owns the fd and closes it. Always returns `:ok`.
  """
  @spec close_fd(non_neg_integer) :: :ok
  def close_fd(_fd), do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Binds a netlink socket fd to `nl_pid = 0` (kernel-auto-assigned)
  with the given group-membership bitmask.

  Erlang's `:socket.bind/2` does not accept netlink `sockaddr_nl`,
  so the bind goes through this NIF. Use `groups = 0` for a plain
  bind (e.g. to enable multicast reception via
  `NETLINK_ADD_MEMBERSHIP` setsockopt later — the socket must be
  bound to receive multicast events at all).
  """
  @spec bind_netlink(non_neg_integer(), non_neg_integer()) ::
          :ok | {:error, integer()}
  def bind_netlink(_fd, _groups), do: :erlang.nif_error(:nif_not_loaded)
end
