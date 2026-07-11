defmodule Linx.Netlink.Error do
  @moduledoc """
  An error returned by the kernel in response to a netlink request.

  Built from an `NLMSG_ERROR` reply: `code` is the kernel's positive errno,
  `errno` is its POSIX name as an atom (`:enodev`, `:einval`, …), and
  `message` is the human-readable string the kernel attached via extended ack
  (`NLMSGERR_ATTR_MSG`) — `nil` if the kernel did not provide one. Extended
  ack is enabled per socket by `Linx.Netlink.Socket.open/2` (Linux ≥ 4.12).

  Returned in the error tuple by every netlink verb, e.g.

      {:error, %Linx.Netlink.Error{errno: :enodev}} = Link.get(socket, "nope0")

  ## No `:operation` field

  Unlike the filesystem/procfs-backed error structs (`Linx.Cgroup.Error`,
  `Linx.Mount.Error`, …), this struct carries no `:operation`. A netlink
  error returns straight from the verb the caller invoked, so the operation
  is already known at the call site — and the kernel's extended-ack
  `message` is a richer, self-describing diagnostic than a synthetic
  operation tag would be. `from_errno/2` is named for what it takes — a
  numeric wire errno, not a POSIX atom — which is why it differs from the
  `from_posix/_` constructors elsewhere in Linx.

  This module also implements `Exception` so an error can be `raise`d, or
  rendered with `Exception.message/1`.
  """

  @enforce_keys [:errno, :code]
  defexception [:errno, :code, :message]

  @type t :: %__MODULE__{
          errno: atom,
          code: pos_integer,
          message: binary | nil
        }

  @doc """
  Builds an error from a positive errno `code` and an optional kernel-supplied
  `message` (the `NLMSGERR_ATTR_MSG` string). The errno atom comes from the
  shared `Linx.Errno` table; an unmapped code falls through to `:unknown` and
  the integer is still kept in the `:code` field.
  """
  @spec from_errno(pos_integer, binary | nil) :: t
  def from_errno(code, message \\ nil) when is_integer(code) and code > 0 do
    %__MODULE__{errno: Linx.Errno.atom(code), code: code, message: message}
  end

  @impl Exception
  def message(%__MODULE__{errno: errno, code: code, message: nil}) do
    "netlink #{format_errno(errno, code)}"
  end

  def message(%__MODULE__{errno: errno, code: code, message: text}) do
    "netlink #{format_errno(errno, code)}: #{text}"
  end

  defp format_errno(:unknown, code), do: "errno #{code}"
  defp format_errno(errno, code), do: "#{errno |> Atom.to_string() |> String.upcase()} (#{code})"

  import Bitwise

  # Flags carried in an NLMSG_ERROR's nlmsg_flags when extended-ack TLVs
  # are appended. NLM_F_CAPPED means the echoed original message was
  # trimmed to its 16-byte header; NLM_F_ACK_TLVS means the extended-ack
  # attributes follow it. See include/uapi/linux/netlink.h.
  @nlm_f_capped 0x100
  @nlm_f_ack_tlvs 0x200

  @doc """
  Extracts the `NLMSGERR_ATTR_MSG` string from an error reply.

  `flags` is the `NLMSG_ERROR` message's `nlmsg_flags`; `rest` is its
  payload *after* the leading signed errno. Returns the human-readable
  extended-ack string, or `nil` if the kernel didn't include one.
  Shared by `Linx.Netlink.Request` and `Linx.Netlink.Nfnl`, which parse
  the same reply shape on different receive paths.
  """
  @spec extack_message(non_neg_integer, binary) :: String.t() | nil
  def extack_message(flags, rest) do
    if (flags &&& @nlm_f_ack_tlvs) != 0 do
      case skip_echoed(rest, (flags &&& @nlm_f_capped) != 0) do
        {:ok, tlvs} ->
          case List.keyfind(Linx.Netlink.Attr.decode(tlvs), 1, 0) do
            # NLMSGERR_ATTR_MSG = 1 — a NUL-terminated string.
            {1, value} -> String.trim_trailing(value, <<0>>)
            nil -> nil
          end

        :error ->
          nil
      end
    end
  end

  # After the errno, the error reply contains the echoed nlmsghdr — just
  # the 16-byte header when NLM_F_CAPPED is set, the full original
  # message (rounded up to a 4-byte boundary) otherwise. The TLVs follow.
  defp skip_echoed(<<len::native-32, _::binary>> = bin, capped?) do
    consume = if capped?, do: 16, else: len + 3 &&& bnot(3)

    case bin do
      <<_::binary-size(consume), tlvs::binary>> -> {:ok, tlvs}
      _ -> :error
    end
  end

  defp skip_echoed(_, _), do: :error
end
