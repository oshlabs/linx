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

  alias Linx.Netlink.{Attr, Error, Message, Socket}

  # Flags carried in an NLMSG_ERROR's nlmsg_flags when extended-ack TLVs are
  # appended. NLM_F_CAPPED means the echoed original message was trimmed to
  # its 16-byte header; NLM_F_ACK_TLVS means the extended-ack attributes
  # follow it. See include/uapi/linux/netlink.h.
  @nlm_f_capped 0x100
  @nlm_f_ack_tlvs 0x200

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
      are an incomplete snapshot, not a success.
    * `{:error, :dump_interrupted}` — the kernel set `NLM_F_DUMP_INTR`,
      meaning the object set changed mid-dump and the reply may contain
      duplicates or omissions. Retry the dump.
  """
  @spec talk(Socket.t(), 0..0xFFFF, non_neg_integer, iodata) ::
          {:ok, [Message.t()]} | {:error, term}
  def talk(%Socket{} = socket, type, flags, payload \\ <<>>) do
    seq = Socket.next_seq(socket)

    message = %Message{
      type: type,
      flags: flags ||| nlm_f_request(),
      seq: seq,
      payload: IO.iodata_to_binary(payload)
    }

    case :socket.send(socket.socket, Message.encode(message)) do
      :ok -> receive_reply(socket, seq, [])
      {:error, reason} -> {:error, {:send, reason}}
    end
  end

  # Receive and decode datagrams until the reply terminates. The explicit
  # 64 KiB read in recv_datagram/1 matters: :socket.recv/1's default read
  # length is 8 KiB and silently truncates larger dump chunks.
  defp receive_reply(socket, seq, acc) do
    case Socket.recv_datagram(socket) do
      {:ok, data} ->
        case consume(Message.decode(data), seq, acc) do
          {:cont, acc} -> receive_reply(socket, seq, acc)
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
  def consume([], _seq, acc), do: {:cont, acc}

  # A message that echoes our sequence number is part of this reply.
  def consume([%Message{seq: seq} = msg | rest], seq, acc) do
    case classify(msg) do
      {:data, :multi} -> consume(rest, seq, [msg | acc])
      {:data, :single} -> {:halt, {:ok, Enum.reverse([msg | acc])}}
      :done -> {:halt, {:ok, Enum.reverse(acc)}}
      :ack -> {:halt, {:ok, Enum.reverse(acc)}}
      {:error, _} = error -> {:halt, error}
      :dump_intr -> {:halt, {:error, :dump_interrupted}}
      :skip -> consume(rest, seq, acc)
    end
  end

  # Any other sequence number is not our reply — an unsolicited notification
  # or a stale message; ignore it.
  def consume([%Message{} | rest], seq, acc), do: consume(rest, seq, acc)

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
  # snapshot. Old kernels may send an empty DONE — treat that as success.
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
      {:error, Error.from_errno(-errno, extack_message(flags, rest))}
    end
  end

  defp classify_error(%Message{}), do: {:error, %Error{errno: :malformed_error, code: nil}}

  # Extract NLMSGERR_ATTR_MSG from an error reply's payload, or nil if the
  # kernel did not include the extended-ack TLVs.
  defp extack_message(flags, rest) do
    if (flags &&& @nlm_f_ack_tlvs) != 0 do
      case skip_echoed(rest, (flags &&& @nlm_f_capped) != 0) do
        {:ok, tlvs} ->
          case List.keyfind(Attr.decode(tlvs), 1, 0) do
            # NLMSGERR_ATTR_MSG = 1 — a NUL-terminated string.
            {1, value} -> String.trim_trailing(value, <<0>>)
            nil -> nil
          end

        :error ->
          nil
      end
    end
  end

  # After the errno, the error reply contains the echoed nlmsghdr — just the
  # 16-byte header when NLM_F_CAPPED is set, the full original message
  # (rounded up to a 4-byte boundary) otherwise. The TLVs follow.
  defp skip_echoed(<<len::native-32, _::binary>> = bin, capped?) do
    consume = if capped?, do: 16, else: len + 3 &&& bnot(3)

    case bin do
      <<_::binary-size(consume), tlvs::binary>> -> {:ok, tlvs}
      _ -> :error
    end
  end

  defp skip_echoed(_, _), do: :error

  # NLM_F_MULTI marks a message as one of a series ended by NLMSG_DONE; a
  # message without it is a complete single reply.
  defp multipart(%Message{flags: flags}) do
    if (flags &&& nlm_f_multi()) != 0, do: :multi, else: :single
  end
end
