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

  The module is synchronous and holds no state of its own: a later connection
  process can reuse the same logic to drive a socket it owns.
  """

  import Bitwise
  import Linx.Netlink.Constants

  alias Linx.Netlink.{Message, Socket}

  @doc """
  Sends a request and returns the kernel's reply.

  `type` and `payload` are the message type and body. `flags` are extra
  `nlmsghdr` flags — `NLM_F_ACK`, `NLM_F_DUMP`, and so on; `NLM_F_REQUEST` is
  added automatically.

  Returns `{:ok, messages}` with the data messages of the reply (an empty list
  for a bare acknowledgement), or `{:error, reason}`. A kernel error is
  `{:error, {:netlink, errno}}`, with `errno` a positive error number.
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

  # Receive and decode datagrams until the reply terminates.
  defp receive_reply(socket, seq, acc) do
    case :socket.recv(socket.socket) do
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
  # first terminal message.
  defp consume([], _seq, acc), do: {:cont, acc}

  # A message that echoes our sequence number is part of this reply.
  defp consume([%Message{seq: seq} = msg | rest], seq, acc) do
    case classify(msg) do
      {:data, :multi} -> consume(rest, seq, [msg | acc])
      {:data, :single} -> {:halt, {:ok, Enum.reverse([msg | acc])}}
      :done -> {:halt, {:ok, Enum.reverse(acc)}}
      :ack -> {:halt, {:ok, Enum.reverse(acc)}}
      {:error, _} = error -> {:halt, error}
      :skip -> consume(rest, seq, acc)
    end
  end

  # Any other sequence number is not our reply — an unsolicited notification
  # or a stale message; ignore it.
  defp consume([%Message{} | rest], seq, acc), do: consume(rest, seq, acc)

  defp classify(%Message{type: type} = msg) do
    cond do
      type == nlmsg_error() -> classify_error(msg)
      type == nlmsg_done() -> :done
      type == nlmsg_noop() -> :skip
      true -> {:data, multipart(msg)}
    end
  end

  # struct nlmsgerr begins with a signed errno; 0 means the request succeeded
  # and this is the acknowledgement, anything else is a kernel error.
  defp classify_error(%Message{payload: <<errno::native-signed-32, _::binary>>}) do
    if errno == 0, do: :ack, else: {:error, {:netlink, -errno}}
  end

  defp classify_error(%Message{}), do: {:error, :malformed_error}

  # NLM_F_MULTI marks a message as one of a series ended by NLMSG_DONE; a
  # message without it is a complete single reply.
  defp multipart(%Message{flags: flags}) do
    if (flags &&& nlm_f_multi()) != 0, do: :multi, else: :single
  end
end
