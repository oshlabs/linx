defmodule Linx.Netlink.Constants do
  @moduledoc """
  Family-agnostic netlink constants — values from the core netlink ABI
  (`include/uapi/linux/netlink.h`) that every protocol family shares.

  Each constant is a zero-arity macro that expands to a literal integer, so it
  can be used anywhere a literal can: building messages, in guards, and in
  binary pattern matches. `import Linx.Netlink.Constants` to use the bare
  names.

  Protocol-family constants (`RTM_*`, `IFLA_*`, …) do not belong here; they
  live in their family's namespace, e.g. `Linx.Netlink.Rtnl`.
  """

  # nlmsghdr.nlmsg_flags — flags carried by every kind of request.
  @doc "`NLM_F_REQUEST` — the message is a request."
  defmacro nlm_f_request, do: 0x01
  @doc "`NLM_F_MULTI` — one of a multipart series, terminated by `NLMSG_DONE`."
  defmacro nlm_f_multi, do: 0x02
  @doc "`NLM_F_ACK` — request an acknowledgement (`NLMSG_ERROR` with errno 0)."
  defmacro nlm_f_ack, do: 0x04
  @doc "`NLM_F_ECHO` — echo this request back to the sender."
  defmacro nlm_f_echo, do: 0x08
  @doc "`NLM_F_DUMP_INTR` — a dump was interrupted by a change and is inconsistent."
  defmacro nlm_f_dump_intr, do: 0x10

  # nlmsghdr.nlmsg_flags — modifiers for a GET request.
  @doc "`NLM_F_ROOT` — return the whole table rather than a single entry."
  defmacro nlm_f_root, do: 0x100
  @doc "`NLM_F_MATCH` — return all entries matching the request criteria."
  defmacro nlm_f_match, do: 0x200
  @doc "`NLM_F_ATOMIC` — return an atomic snapshot of the table."
  defmacro nlm_f_atomic, do: 0x400
  @doc "`NLM_F_DUMP` — dump the table (`NLM_F_ROOT` ||| `NLM_F_MATCH`)."
  defmacro nlm_f_dump, do: 0x300

  # nlmsghdr.nlmsg_flags — modifiers for a NEW request. These reuse the same
  # bit values as the GET modifiers above; netlink reads them by request kind.
  @doc "`NLM_F_REPLACE` — replace an existing matching object."
  defmacro nlm_f_replace, do: 0x100
  @doc "`NLM_F_EXCL` — fail if the object already exists."
  defmacro nlm_f_excl, do: 0x200
  @doc "`NLM_F_CREATE` — create the object if it does not exist."
  defmacro nlm_f_create, do: 0x400
  @doc "`NLM_F_APPEND` — append to the end of the object list."
  defmacro nlm_f_append, do: 0x800

  # Standard control message types. Values below NLMSG_MIN_TYPE are reserved
  # by netlink itself; protocol families number their messages at or above it.
  @doc "`NLMSG_NOOP` — no-op; the message should be skipped."
  defmacro nlmsg_noop, do: 0x1
  @doc "`NLMSG_ERROR` — an error report, or (errno 0) an acknowledgement."
  defmacro nlmsg_error, do: 0x2
  @doc "`NLMSG_DONE` — terminates a multipart message series."
  defmacro nlmsg_done, do: 0x3
  @doc "`NLMSG_OVERRUN` — data was lost; the socket is out of sync."
  defmacro nlmsg_overrun, do: 0x4
  @doc "`NLMSG_MIN_TYPE` — the first message type available to protocol families."
  defmacro nlmsg_min_type, do: 0x10
end
