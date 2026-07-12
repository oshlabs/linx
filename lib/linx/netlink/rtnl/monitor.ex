defmodule Linx.Netlink.Rtnl.Monitor do
  @moduledoc """
  A GenServer that owns a multicast rtnetlink socket, decodes each broadcast
  into a `Linx.Netlink.Rtnl.Monitor.Event`, and forwards it to an owner pid —
  the `ip monitor` equivalent.

  ## Lifecycle

      {:ok, mon} = Linx.Netlink.Rtnl.Monitor.subscribe()
      # → the owner receives:
      #   {:linx_rtnl, :event, %Linx.Netlink.Rtnl.Monitor.Event{...}}
      #   {:linx_rtnl, :resync_needed}    (on ENOBUFS)
      :ok = Linx.Netlink.Rtnl.Monitor.unsubscribe(mon)

  ## Events are wake-ups, not deltas

  Netlink multicast is lossy by design: on a busy system the kernel's send
  buffer fills, frames are dropped, and the next recv returns `ENOBUFS`. So the
  Monitor is a *latency* layer over reconcile, never a source of truth — a
  level-triggered consumer treats every event (and every `:resync_needed`) as
  "look now", then re-reads and re-diffs full state. It must not act on an
  event's `:resource` directly. `RTM_NEW*`/`RTM_DEL*` decode through the *same*
  codecs as `list/1`, so the structs are identical to what a re-read returns.

  Unlike `Linx.Netfilter.Monitor`, there is no generation counter or
  snapshot-then-tail handshake — rtnetlink has no transaction id. The
  level-triggered resync (re-`list`, diff, apply) is what makes a missed event
  harmless.

  ## Groups

  By default it joins links, neighbours, and IPv4/IPv6 addresses, routes, and
  rules. Override with `:groups` (a list of `RTNLGRP_*` numbers).

  ## ENOBUFS recovery

  On `ENOBUFS` the Monitor emits `{:linx_rtnl, :resync_needed}` and keeps
  reading; the owner re-syncs by reconciling. `SO_RCVBUF` defaults to 4 MiB to
  reduce overflow.
  """

  use GenServer

  alias Linx.Netlink.{Message, Rtnl, Socket}
  alias Linx.Netlink.Rtnl.{Address, Link, Neighbour, Route, Rule}
  alias Linx.Netlink.Rtnl.Monitor.Event

  # RTNLGRP_* multicast group numbers — enum rtnetlink_groups,
  # include/uapi/linux/rtnetlink.h.
  @rtnlgrp_link 1
  @rtnlgrp_neigh 3
  @rtnlgrp_ipv4_ifaddr 5
  @rtnlgrp_ipv4_route 7
  @rtnlgrp_ipv4_rule 8
  @rtnlgrp_ipv6_ifaddr 9
  @rtnlgrp_ipv6_route 11
  @rtnlgrp_ipv6_rule 19

  @default_groups [
    @rtnlgrp_link,
    @rtnlgrp_neigh,
    @rtnlgrp_ipv4_ifaddr,
    @rtnlgrp_ipv4_route,
    @rtnlgrp_ipv4_rule,
    @rtnlgrp_ipv6_ifaddr,
    @rtnlgrp_ipv6_route,
    @rtnlgrp_ipv6_rule
  ]

  # RTM_* message types — include/uapi/linux/rtnetlink.h.
  @rtm %{
    16 => {:new_link, Link},
    17 => {:del_link, Link},
    20 => {:new_addr, Address},
    21 => {:del_addr, Address},
    24 => {:new_route, Route},
    25 => {:del_route, Route},
    28 => {:new_neigh, Neighbour},
    29 => {:del_neigh, Neighbour},
    32 => {:new_rule, Rule},
    33 => {:del_rule, Rule}
  }

  # 4 MiB — absorbs most monitoring bursts without bumping net.core.rmem_max.
  @default_rcvbuf 4 * 1024 * 1024

  # Short-timeout polling loop (same rationale as Linx.Netfilter.Monitor:
  # :nowait select notifications proved flaky for netlink multicast).
  @recv_timeout_ms 50
  @recv_size 65_536

  @type opt ::
          {:owner, pid()}
          | {:netns, Socket.netns()}
          | {:groups, [pos_integer()]}
          | {:rcvbuf, pos_integer()}

  @doc """
  Starts a Monitor linked to the caller and subscribed to the rtnetlink
  multicast groups.

  Options:

    * `:owner` (required) — pid that receives `{:linx_rtnl, _}` messages.
    * `:netns` — namespace to monitor; defaults to `:host`.
    * `:groups` — `RTNLGRP_*` group numbers; defaults to links, neighbours,
      and IPv4/IPv6 addresses, routes, and rules.
    * `:rcvbuf` — `SO_RCVBUF` size in bytes; default 4 MiB.
  """
  @spec start_link([opt()]) :: GenServer.on_start()
  def start_link(opts) when is_list(opts), do: GenServer.start_link(__MODULE__, opts)

  @doc """
  Convenience: start a Monitor with `owner` (default the calling process) and
  the rest of `opts`. Returns `{:ok, monitor}`.
  """
  @spec subscribe(pid(), [opt()]) :: GenServer.on_start()
  def subscribe(owner \\ self(), opts \\ []) when is_pid(owner) and is_list(opts) do
    start_link(Keyword.put(opts, :owner, owner))
  end

  @doc "Stops the Monitor (closes its socket)."
  @spec stop(pid()) :: :ok
  def stop(monitor) when is_pid(monitor), do: GenServer.stop(monitor)

  @doc "Alias for `stop/1`."
  @spec unsubscribe(pid()) :: :ok
  def unsubscribe(monitor), do: stop(monitor)

  @doc false
  # Decodes a framed multicast message into an Event. Public for testing the
  # RTM-type dispatch without a live socket.
  @spec decode_event(Message.t()) :: Event.t()
  def decode_event(%Message{type: type, payload: payload}) do
    case Map.fetch(@rtm, type) do
      {:ok, {op, module}} -> %Event{op: op, resource: module.decode(payload)}
      :error -> %Event{op: {:unknown, type}, resource: nil}
    end
  end

  # === GenServer ============================================================

  @impl true
  def init(opts) do
    owner = Keyword.fetch!(opts, :owner)
    netns = Keyword.get(opts, :netns, :host)
    groups = Keyword.get(opts, :groups, @default_groups)
    rcvbuf = Keyword.get(opts, :rcvbuf, @default_rcvbuf)

    with {:ok, sock} <- Rtnl.open(netns),
         :ok <- Socket.close_on_error(sock, join_all(sock, groups)) do
      _ = Socket.set_rcvbuf(sock, rcvbuf)
      send(self(), :recv)
      {:ok, %{sock: sock, owner: owner}}
    end
  end

  @impl true
  def handle_info(:recv, state), do: do_recv(state)

  # Defensive: ignore any stray :socket select notifications.
  def handle_info({:"$socket", _sock, :select, _ref}, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, state) do
    if state[:sock], do: Socket.close(state.sock)
    :ok
  end

  # === Internals ============================================================

  defp join_all(sock, groups) do
    Enum.reduce_while(groups, :ok, fn group, :ok ->
      case Socket.add_membership(sock, group) do
        :ok -> {:cont, :ok}
        {:error, _} = error -> {:halt, error}
      end
    end)
  end

  defp do_recv(%{sock: sock} = state) do
    case :socket.recv(sock.socket, @recv_size, @recv_timeout_ms) do
      {:ok, data} ->
        for %Message{} = msg <- Message.decode(data) do
          send(state.owner, {:linx_rtnl, :event, decode_event(msg)})
        end

        send(self(), :recv)
        {:noreply, state}

      {:error, :timeout} ->
        send(self(), :recv)
        {:noreply, state}

      {:error, :enobufs} ->
        send(state.owner, {:linx_rtnl, :resync_needed})
        send(self(), :recv)
        {:noreply, state}

      {:error, :closed} ->
        {:stop, :normal, state}

      {:error, reason} ->
        {:stop, {:recv, reason}, state}
    end
  end
end
