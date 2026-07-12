defmodule Linx.Netlink.Nfnl do
  @moduledoc """
  nfnetlink (`NETLINK_NETFILTER`) — the kernel's netfilter-control
  interface: nf_tables (the modern firewall), conntrack, NFLOG, NFQUEUE.

  This is the second `Linx.Netlink` protocol family (after
  `Linx.Netlink.Rtnl`). nfnetlink multiplexes several sub-subsystems
  inside one netlink family — identified by the high byte of
  `nlmsghdr.type` (`subsys_id`). The map (`include/uapi/linux/netfilter/nfnetlink.h`):

  | subsys_id | Name | Linx module |
  |---|---|---|
  | 1  | CTNETLINK | `Linx.Netfilter.Conntrack` (future) |
  | 3  | QUEUE     | `Linx.Netfilter.Queue` (future) |
  | 4  | ULOG      | `Linx.Netfilter.Log` (NFLOG) |
  | 10 | NFTABLES  | `Linx.Netfilter` core |
  | 12 | HOOK      | (deferred) |

  Open a socket with `open/1` and pass it to the appropriate higher-level
  module (`Linx.Netfilter`, eventually `Linx.Netfilter.{Conntrack,Log,Queue}`).

  Codec helpers — `nfgenmsg` header encoding, subsys-id multiplexing on
  `nlmsghdr.type`, batched-transaction envelope (`NFNL_MSG_BATCH_BEGIN` /
  `NFNL_MSG_BATCH_END`), and the `NFT_MSG_GETGEN` / `NEWGEN` codec — live
  in `Linx.Netlink.Nfnl.Codec`. The `batch/2` request engine below
  drives nf_tables mutating transactions on top of those primitives.

  The NFTABLES sub-subsystem (id 10) is driven by `Linx.Netfilter`;
  CTNETLINK / QUEUE / HOOK are future families.
  """

  import Bitwise
  import Linx.Netlink.Constants

  alias Linx.Netlink.{Error, Message, Socket}
  alias Linx.Netlink.Nfnl.Codec

  # NETLINK_NETFILTER — the nfnetlink protocol number for socket(2).
  # `include/uapi/linux/netlink.h`.
  @netlink_netfilter 12

  # Per-datagram bound on batch ACK collection; matches the rationale (and
  # value) of Linx.Netlink.Request's default — the kernel ACKs a healthy
  # batch in microseconds, and a lost datagram must not block forever.
  @ack_timeout 5_000

  @doc """
  Opens an nfnetlink socket in network namespace `netns`.

  See `Linx.Netlink.Socket.open/2` for the `netns` forms (`:host`,
  `{:pid, n}`, `{:path, p}`). Close the socket with
  `Linx.Netlink.Socket.close/1`.
  """
  @spec open(Socket.netns()) :: {:ok, Socket.t()} | {:error, term}
  def open(netns \\ :host), do: Socket.open(@netlink_netfilter, netns)

  @doc """
  Sends a batched nf_tables transaction.

  Wraps `inner_messages` between a `NFNL_MSG_BATCH_BEGIN` envelope
  targeting `subsys` (default `:nftables`) and a `NFNL_MSG_BATCH_END`,
  assigns sequence numbers, ORs `NLM_F_REQUEST | NLM_F_ACK` onto every
  inner message, sends the whole batch in one `sendmsg(2)`, and
  collects per-message ACK / error responses until every inner
  message has been accounted for.

  Returns `:ok` if every inner message was accepted, or
  `{:error, {batch_seq, %Linx.Netlink.Error{}}}` for the first
  inner message the kernel rejected. `batch_seq` is the
  1-indexed position of the offending message within
  `inner_messages` (the BATCH_BEGIN envelope is position 0; not
  returned).

  The envelope messages do not themselves get ACKs from the kernel —
  BATCH_BEGIN merely opens the transaction, BATCH_END commits it.
  Per-inner-message validation errors are returned during the prep
  phase; commit-time failures (e.g. BATCH_GENID mismatch)
  surface here too, attributed to the inner message that triggered
  them.

  Each call allocates fresh sequence numbers from the socket's counter,
  so a stale or unrelated reply is never *misattributed* to this batch.
  That does not make one socket safe for **concurrent** callers: each
  reply datagram is delivered to exactly one `recv`-er, so caller A can
  consume (and discard as unsolicited) the ACK caller B is blocked on,
  leaving B waiting forever. Drive a given `%Socket{}` from one process
  at a time — open one socket per concurrent user, or serialise access
  through an owning process.
  """
  @spec batch(Socket.t(), [Message.t()], atom() | 0..255, keyword()) ::
          :ok | {:error, {non_neg_integer(), Error.t()} | term()}
  def batch(socket, inner_messages, subsys \\ :nftables, opts \\ [])

  def batch(%Socket{} = socket, inner_messages, subsys, opts)
      when is_list(inner_messages) and is_list(opts) do
    begin_msg = Codec.batch_begin(subsys, Keyword.take(opts, [:genid]))
    end_msg = Codec.batch_end(subsys)
    all = [begin_msg | inner_messages] ++ [end_msg]

    # Assign sequence numbers; ACK only the inner messages. BATCH_BEGIN
    # / BATCH_END are envelope markers, not request-reply pairs — the
    # kernel doesn't ACK them.
    total = length(all)

    with_seqs =
      Enum.with_index(all, fn %Message{} = msg, idx ->
        seq = Socket.next_seq(socket)

        flags =
          msg.flags ||| nlm_f_request() |||
            if envelope?(msg, idx, total), do: 0, else: nlm_f_ack()

        # batch_seq is the 1-indexed position of this inner message
        # within `inner_messages`. The BATCH_BEGIN at idx=0 maps to 0,
        # BATCH_END at idx=N+1 to nil — neither contributes errors.
        batch_seq =
          cond do
            idx == 0 -> 0
            idx == total - 1 -> nil
            true -> idx
          end

        {%Message{msg | flags: flags, seq: seq}, batch_seq}
      end)

    payload =
      with_seqs
      |> Enum.map(fn {msg, _} -> Message.encode(msg) end)
      |> IO.iodata_to_binary()

    case :socket.send(socket.socket, payload) do
      :ok ->
        # Track expected ACK seq numbers → their 1-indexed batch_seq.
        pending =
          for {msg, batch_seq} <- with_seqs,
              not is_nil(batch_seq) and batch_seq != 0 and msg.seq != 0,
              into: %{},
              do: {msg.seq, batch_seq}

        collect_batch_responses(socket, pending)

      {:error, reason} ->
        {:error, {:send, reason}}
    end
  end

  defp envelope?(_msg, 0, _last_idx), do: true
  defp envelope?(_msg, idx, total) when idx == total - 1, do: true
  defp envelope?(_msg, _idx, _total), do: false

  defp collect_batch_responses(_socket, pending) when pending == %{}, do: :ok

  defp collect_batch_responses(socket, pending) do
    # Explicit 64 KiB read — :socket.recv/1's 8 KiB default would silently
    # truncate a large response datagram (see Socket.recv_datagram/1).
    # Bounded per-datagram, like Linx.Netlink.Request: netlink is lossy
    # under ENOBUFS, and an ACK that never arrives must surface as
    # {:error, {:recv, :timeout}} instead of blocking the caller forever.
    case Socket.recv_datagram(socket, timeout: @ack_timeout) do
      {:ok, data} ->
        process_responses(Message.decode(data), socket, pending)

      {:error, reason} ->
        {:error, {:recv, reason}}
    end
  end

  defp process_responses([], socket, pending),
    do: collect_batch_responses(socket, pending)

  defp process_responses([%Message{seq: seq} = msg | rest], socket, pending) do
    case Map.fetch(pending, seq) do
      {:ok, batch_seq} ->
        case classify_batch_response(msg) do
          :ack ->
            process_responses(rest, socket, Map.delete(pending, seq))

          {:error, err} ->
            {:error, {batch_seq, err}}
        end

      :error ->
        # Unsolicited seq — either unrelated multicast / stale, or a
        # batch-envelope error (notably ERESTART on BATCH_END when
        # NFTA_BATCH_GENID doesn't match). For non-error messages
        # we ignore; for error messages we treat as fatal since the
        # kernel only sends NLMSG_ERROR in response to our send.
        case classify_batch_response(msg) do
          :ack -> process_responses(rest, socket, pending)
          {:error, err} -> {:error, {nil, err}}
        end
    end
  end

  defp classify_batch_response(%Message{type: type} = msg) do
    cond do
      type == nlmsg_error() -> classify_error(msg)
      true -> :ack
    end
  end

  defp classify_error(%Message{
         flags: flags,
         payload: <<errno::native-signed-32, rest::binary>>
       }) do
    if errno == 0 do
      :ack
    else
      {:error, Error.from_errno(-errno, Error.extack_message(flags, rest))}
    end
  end

  defp classify_error(%Message{}), do: {:error, %Error{errno: :malformed_error, code: nil}}
end
