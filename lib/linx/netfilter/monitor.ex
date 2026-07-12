defmodule Linx.Netfilter.Monitor do
  @moduledoc """
  A GenServer that owns a multicast nfnetlink socket subscribed to
  `NFNLGRP_NFTABLES`, decodes each broadcast message into a
  `%Linx.Netfilter.Event{}`, and forwards it to the owner pid.

  ## Lifecycle

      {:ok, monitor} = Linx.Netfilter.subscribe()
      # → caller process receives:
      #   {:linx_netfilter, :event, %Linx.Netfilter.Event{...}}
      #   {:linx_netfilter, :resync_needed}    (on ENOBUFS)
      :ok = Linx.Netfilter.unsubscribe(monitor)

  ## Event grouping

  The kernel broadcasts a commit's entity events first, then one
  closing `NEW_GEN` message naming the generation and the
  committing process. The Monitor buffers the entity events until
  that `NEW_GEN` arrives, stamps them with its `gen_id` /
  `proc_pid` / `proc_name`, and delivers them (entity events first,
  the `:new_gen` event last) — so each `%Event{}` carries full
  provenance.

  ## ENOBUFS recovery

  If the multicast traffic outpaces the consumer, the kernel
  drops messages and the next recv returns `:enobufs`. The
  Monitor emits `{:linx_netfilter, :resync_needed}` to the owner
  and continues reading; the owner is responsible for re-running
  `pull/1..2` to re-sync state.

  Default `SO_RCVBUF` is bumped to 4 MiB at start to reduce
  the likelihood of overflow.

  ## Snapshot+tail

  `subscribe/1` accepts a `:since_gen` option — events with
  `gen_id <= since_gen` are silently dropped. The canonical
  pattern (no race with the kernel):

      {:ok, m} = Linx.Netfilter.subscribe()
      {:ok, gen} = Linx.Netlink.Nfnl.Codec.get_gen(some_socket)
      Linx.Netfilter.Monitor.set_min_gen(m, gen.id)
      {:ok, snapshot} = Linx.Netfilter.pull(some_socket)
      # → all events with gen_id > gen.id flow to the owner
      #   (events already captured in the snapshot are filtered)

  `Linx.Netfilter.pull/1..2` exposes a `:subscribe_first` shortcut
  that does this whole dance in one call.
  """

  use GenServer

  alias Linx.Netfilter.{Decoder, Event}
  alias Linx.Netlink.{Message, Nfnl, Socket}

  # NFNLGRP_NFTABLES — multicast group id from `enum nfnetlink_groups`
  # in `include/uapi/linux/netfilter/nfnetlink.h` (group 7).
  @nfnlgrp_nftables 7

  # 4 MiB default — large enough to absorb most monitoring bursts
  # without bumping `net.core.rmem_max`.
  @default_rcvbuf 4 * 1024 * 1024

  @type opt ::
          {:owner, pid()}
          | {:netns, Socket.netns()}
          | {:since_gen, non_neg_integer()}
          | {:rcvbuf, pos_integer()}

  @doc """
  Starts a Monitor linked to the caller, subscribed to
  `NFNLGRP_NFTABLES`.

  Options:

    * `:owner` (required) — pid that receives `{:linx_netfilter, _}`
      messages.
    * `:netns` — namespace to monitor; defaults to `:host`.
    * `:since_gen` — initial floor; events with `gen_id <=`
      this value are dropped. Defaults to `0` (everything flows).
    * `:rcvbuf` — `SO_RCVBUF` size in bytes; default 4 MiB.
  """
  @spec start_link([opt()]) :: GenServer.on_start()
  def start_link(opts) when is_list(opts) do
    GenServer.start_link(__MODULE__, opts)
  end

  @doc """
  Stops the Monitor (closes its socket).
  """
  @spec stop(pid()) :: :ok
  def stop(monitor) when is_pid(monitor), do: GenServer.stop(monitor)

  @doc """
  Sets the minimum gen — subsequent events whose `gen_id` is
  greater than this value will be delivered; events at or below
  are filtered out. Used by `pull(..., subscribe_first: monitor)`
  to drop events already captured in the snapshot.
  """
  @spec set_min_gen(pid(), non_neg_integer()) :: :ok
  def set_min_gen(monitor, gen) when is_pid(monitor) and is_integer(gen) and gen >= 0 do
    GenServer.call(monitor, {:set_min_gen, gen})
  end

  # ===========================================================
  # GenServer callbacks
  # ===========================================================

  @impl true
  def init(opts) do
    owner = Keyword.fetch!(opts, :owner)
    netns = Keyword.get(opts, :netns, :host)
    since_gen = Keyword.get(opts, :since_gen, 0)
    rcvbuf = Keyword.get(opts, :rcvbuf, @default_rcvbuf)

    with {:ok, sock} <- Nfnl.open(netns) do
      case Socket.add_membership(sock, @nfnlgrp_nftables) do
        :ok ->
          _ = Socket.set_rcvbuf(sock, rcvbuf)

          state = %{
            sock: sock,
            owner: owner,
            gen_id: nil,
            proc_pid: nil,
            proc_name: nil,
            min_gen: since_gen,
            # Pending entity events buffered until the closing NEWGEN
            # tells us which gen they belong to. The kernel broadcasts
            # entity events FIRST, then the NEWGEN for the batch.
            pending: []
          }

          send(self(), :recv)
          {:ok, state}

        {:error, _reason} = error ->
          Socket.close(sock)
          error
      end
    end
  end

  @impl true
  def handle_call({:set_min_gen, gen}, _from, state) do
    {:reply, :ok, %{state | min_gen: gen}}
  end

  @impl true
  def handle_info(:recv, state), do: do_recv(state)

  @impl true
  def terminate(_reason, state) do
    if state.sock, do: Socket.close(state.sock)
    :ok
  end

  # ===========================================================
  # Internals
  # ===========================================================

  # Short-timeout polling loop. :nowait + {:"$socket", _, :select, _}
  # is the more efficient pattern but turned out to be flaky for
  # netlink multicast on some kernels — receive_msg sometimes
  # never raises the select notification. A 50 ms timeout adds a
  # tiny worst-case latency and zero infrastructure.
  @recv_timeout_ms 50

  # Max bytes to recv per call. nfnetlink datagrams are typically
  # well under 8 KiB, but burstable to ~32 KiB under heavy traffic.
  # 64 KiB is the safe upper bound (matches Linux kernel's NLMSG_GOODSIZE).
  @recv_size 65_536

  defp do_recv(%{sock: sock} = state) do
    case :socket.recv(sock.socket, @recv_size, @recv_timeout_ms) do
      {:ok, data} ->
        new_state = process_data(data, state)
        send(self(), :recv)
        {:noreply, new_state}

      {:error, :timeout} ->
        send(self(), :recv)
        {:noreply, state}

      {:error, :enobufs} ->
        send(state.owner, {:linx_netfilter, :resync_needed})
        send(self(), :recv)
        {:noreply, state}

      {:error, :closed} ->
        {:stop, :normal, state}

      {:error, reason} ->
        {:stop, {:recv, reason}, state}
    end
  end

  defp process_data(data, state) do
    data
    |> Message.decode()
    |> Enum.reduce(state, &process_message/2)
  end

  defp process_message(%Message{} = msg, state) do
    event = Decoder.event(msg)
    dispatch(event, state)
  end

  # The kernel broadcasts a commit's entity events FIRST, then the
  # NEW_GEN marker that names the gen / committer. So we buffer
  # entity events as they arrive, then on NEW_GEN drain them all —
  # stamped with the just-arrived gen — and the NEW_GEN itself.

  defp dispatch(%Event{op: :new_gen} = event, state) do
    new_state = %{
      state
      | gen_id: event.gen_id,
        proc_pid: event.proc_pid,
        proc_name: event.proc_name,
        pending: []
    }

    if event.gen_id > state.min_gen do
      # Drain buffered entity events with this gen's metadata, then
      # forward the NEW_GEN itself.
      for %Event{} = entity_event <- Enum.reverse(state.pending) do
        enriched = %Event{
          entity_event
          | gen_id: event.gen_id,
            proc_pid: event.proc_pid,
            proc_name: event.proc_name
        }

        send(state.owner, {:linx_netfilter, :event, enriched})
      end

      send(state.owner, {:linx_netfilter, :event, event})
    end

    new_state
  end

  defp dispatch(%Event{} = event, state) do
    # Buffer entity events; they'll be drained when NEW_GEN arrives.
    %{state | pending: [event | state.pending]}
  end
end
