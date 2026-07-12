defmodule Linx.Netlink.Request do
  @moduledoc """
  The synchronous request engine: send one netlink request and collect the
  kernel's reply.

  `talk/4` handles all three reply shapes uniformly:

    * an **acknowledgement** — a single `NLMSG_ERROR` with errno 0, returned by
      a request that carried `NLM_F_ACK`;
    * a **single reply** — one data message answering a non-dump request;
    * a **dump** — a multipart series of data messages (`NLM_F_MULTI`),
      terminated by `NLMSG_DONE`.

  It allocates a fresh sequence number per request from the socket's counter,
  and accepts only replies that echo it back — so a stale reply, or an
  unsolicited multicast notification, cannot be mistaken for the answer.

  Sequence numbers prevent *misattribution*, not *loss*: each datagram is
  delivered to exactly one `recv`-er, so two processes calling `talk/4` on
  the same `%Socket{}` can steal (and discard) each other's replies, leaving
  one blocked forever. Drive a given socket from one process at a time —
  open one socket per concurrent user, or serialise access through an
  owning process.

  The module is synchronous and holds no state of its own: a later connection
  process can reuse the same logic to drive a socket it owns.
  """

  import Bitwise
  import Linx.Netlink.Constants

  alias Linx.Netlink.{Error, Message, Socket}

  @doc """
  Sends a request and returns the kernel's reply.

  `type` and `payload` are the message type and body. `flags` are extra
  `nlmsghdr` flags — `NLM_F_ACK`, `NLM_F_DUMP`, and so on; `NLM_F_REQUEST` is
  added automatically.

  Returns `{:ok, messages}` with the data messages of the reply (an empty list
  for a bare acknowledgement), or `{:error, reason}`. A kernel error is
  `{:error, %Linx.Netlink.Error{}}`.

  Two dump-specific error shapes deserve mention:

    * `{:error, %Linx.Netlink.Error{}}` is also returned when the kernel
      aborted the dump partway — since Linux 4.x `NLMSG_DONE` carries a
      `dump_done_errno`, and a negative value means the preceding messages
      are an incomplete snapshot, not a success. This is surfaced
      immediately: the abort has a cause (`-ENOMEM`, `-EPERM`, …) that
      re-asking cannot fix.
    * `{:error, :dump_interrupted}` — the kernel set `NLM_F_DUMP_INTR`,
      meaning the object set changed mid-dump and the reply may contain
      duplicates or omissions.

  Interrupted dumps automatically retry twice, discarding the partial
  snapshot and allocating a fresh sequence number each time. A netlink
  socket runs one dump at a time — a new request while the abandoned dump
  is still generating would be refused with `EBUSY` — so the engine first
  reads the old dump through its terminating `NLMSG_DONE` before
  re-sending. Override the bound with `:dump_retries`; `0` surfaces the
  first `:dump_interrupted` immediately.
  """
  # A reply datagram that takes longer than this to arrive means the
  # request or its reply was lost (netlink is lossy under ENOBUFS) —
  # without a bound, the caller blocks forever. Generous: the kernel
  # answers healthy requests in microseconds, and the timeout is
  # per-datagram, so long dumps are unaffected as long as they flow.
  @default_timeout 5_000
  @default_dump_retries 2

  @spec talk(Socket.t(), 0..0xFFFF, non_neg_integer, iodata, keyword) ::
          {:ok, [Message.t()]} | {:error, term}
  def talk(%Socket{} = socket, type, flags, payload \\ <<>>, opts \\ []) do
    timeout = Keyword.get(opts, :timeout, @default_timeout)

    with {:ok, retries} <- dump_retries(flags, opts) do
      run_with_dump_retries(
        fn -> request_once(socket, type, flags, IO.iodata_to_binary(payload), timeout) end,
        retries
      )
    end
  end

  defp request_once(socket, type, flags, payload, timeout) do
    seq = Socket.next_seq(socket)

    message = %Message{
      type: type,
      flags: flags ||| nlm_f_request(),
      seq: seq,
      payload: payload
    }

    case :socket.send(socket.socket, Message.encode(message)) do
      :ok ->
        case receive_reply(socket, seq, [], timeout) do
          # NLM_F_DUMP_INTR arrived on the DONE: the dump has terminated
          # kernel-side and the socket is free for the retry.
          {:retry_dump, reason, :complete} ->
            {:retry_dump, reason}

          # NLM_F_DUMP_INTR arrived mid-stream: the kernel generates the
          # rest of the abandoned dump lazily as we read, and refuses a
          # new dump with EBUSY until the old one is read through its
          # DONE. Drain it before letting the retry send.
          {:retry_dump, reason, :mid_dump} ->
            case drain_dump(socket, seq, timeout) do
              :ok -> {:retry_dump, reason}
              {:error, _} = error -> error
            end

          result ->
            result
        end

      {:error, reason} ->
        {:error, {:send, reason}}
    end
  end

  # Read the abandoned dump to its terminating message (DONE, or an error),
  # discarding everything. Datagrams with other sequence numbers are
  # unrelated traffic and are discarded too, exactly as receive_reply does.
  defp drain_dump(socket, seq, timeout) do
    case Socket.recv_datagram(socket, timeout: timeout) do
      {:ok, data} ->
        if Enum.any?(Message.decode(data), &terminal?(&1, seq)) do
          :ok
        else
          drain_dump(socket, seq, timeout)
        end

      {:error, reason} ->
        {:error, {:recv, reason}}
    end
  end

  defp terminal?(%Message{seq: seq, type: type}, seq),
    do: type == nlmsg_done() or type == nlmsg_error()

  defp terminal?(%Message{}, _seq), do: false

  @doc false
  def run_with_dump_retries(attempt, retries_left)
      when is_function(attempt, 0) and is_integer(retries_left) and retries_left >= 0 do
    case attempt.() do
      {:retry_dump, _reason} when retries_left > 0 ->
        run_with_dump_retries(attempt, retries_left - 1)

      {:retry_dump, reason} ->
        {:error, reason}

      result ->
        result
    end
  end

  # Receive and decode datagrams until the reply terminates. The explicit
  # 64 KiB read in recv_datagram/1 matters: :socket.recv/1's default read
  # length is 8 KiB and silently truncates larger dump chunks.
  defp receive_reply(socket, seq, acc, timeout) do
    case Socket.recv_datagram(socket, timeout: timeout) do
      {:ok, data} ->
        case consume_reply(Message.decode(data), seq, acc) do
          {:cont, acc} -> receive_reply(socket, seq, acc, timeout)
          {:halt, result} -> result
        end

      {:error, reason} ->
        {:error, {:recv, reason}}
    end
  end

  # Fold the messages of one datagram into the accumulator, stopping at the
  # first terminal message. Public (but undocumented) so the terminal
  # classifications — DONE-with-errno, NLM_F_DUMP_INTR — are unit-testable
  # with synthesized messages; a real socket can't produce them on demand.
  @doc false
  def consume(messages, seq, acc) do
    case consume_reply(messages, seq, acc) do
      {:halt, {:retry_dump, reason, _stage}} -> {:halt, {:error, reason}}
      result -> result
    end
  end

  defp consume_reply([], _seq, acc), do: {:cont, acc}

  # A message that echoes our sequence number is part of this reply.
  defp consume_reply([%Message{seq: seq} = msg | rest], seq, acc) do
    case classify(msg) do
      {:data, :multi} -> consume_reply(rest, seq, [msg | acc])
      {:data, :single} -> {:halt, {:ok, Enum.reverse([msg | acc])}}
      :done -> {:halt, {:ok, Enum.reverse(acc)}}
      :ack -> {:halt, {:ok, Enum.reverse(acc)}}
      {:error, _} = error -> {:halt, error}
      :dump_intr -> {:halt, {:retry_dump, :dump_interrupted, intr_stage(msg)}}
      :skip -> consume_reply(rest, seq, acc)
    end
  end

  # Any other sequence number is not our reply — an unsolicited notification
  # or a stale message; ignore it.
  defp consume_reply([%Message{} | rest], seq, acc), do: consume_reply(rest, seq, acc)

  # Whether NLM_F_DUMP_INTR arrived on the terminating DONE (the dump is
  # over; the socket is free) or on a data message mid-stream (the abandoned
  # dump must be drained before another can start).
  defp intr_stage(%Message{type: type}) do
    if type == nlmsg_done(), do: :complete, else: :mid_dump
  end

  defp classify(%Message{type: type, flags: flags} = msg) do
    cond do
      type == nlmsg_error() ->
        classify_error(msg)

      # The kernel sets NLM_F_DUMP_INTR (on data messages and on the DONE)
      # when the object set changed mid-dump: the snapshot may hold
      # duplicates or omissions and must not be trusted.
      (flags &&& nlm_f_dump_intr()) != 0 ->
        :dump_intr

      type == nlmsg_done() ->
        classify_done(msg)

      type == nlmsg_noop() ->
        :skip

      true ->
        {:data, multipart(msg)}
    end
  end

  # Since Linux 4.x, NLMSG_DONE carries the dump's final status as a leading
  # signed 32-bit `dump_done_errno`; negative means the kernel aborted the
  # dump partway (e.g. -ENOMEM) and the collected messages are an incomplete
  # snapshot. Not retried: the abort has a cause re-asking cannot fix.
  # Old kernels may send an empty DONE — treat that as success.
  defp classify_done(%Message{payload: <<errno::native-signed-32, _::binary>>})
       when errno < 0 do
    {:error, Error.from_errno(-errno, nil)}
  end

  defp classify_done(%Message{}), do: :done

  # struct nlmsgerr begins with a signed errno; 0 means the request succeeded
  # and this is the acknowledgement, anything else is a kernel error. With
  # NETLINK_EXT_ACK enabled on the socket (Linx.Netlink.Socket does this) the
  # kernel attaches a human-readable string after the echoed nlmsghdr.
  defp classify_error(%Message{flags: flags, payload: <<errno::native-signed-32, rest::binary>>}) do
    if errno == 0 do
      :ack
    else
      {:error, Error.from_errno(-errno, Error.extack_message(flags, rest))}
    end
  end

  defp classify_error(%Message{}), do: {:error, %Error{errno: :malformed_error, code: nil}}

  # NLM_F_MULTI marks a message as one of a series ended by NLMSG_DONE; a
  # message without it is a complete single reply.
  defp multipart(%Message{flags: flags}) do
    if (flags &&& nlm_f_multi()) != 0, do: :multi, else: :single
  end

  defp dump?(flags), do: (flags &&& nlm_f_dump()) == nlm_f_dump()

  defp dump_retries(flags, opts) do
    retries =
      if dump?(flags), do: Keyword.get(opts, :dump_retries, @default_dump_retries), else: 0

    if is_integer(retries) and retries >= 0 do
      {:ok, retries}
    else
      {:error, {:bad_dump_retries, retries}}
    end
  end
end
