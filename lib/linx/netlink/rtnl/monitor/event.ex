defmodule Linx.Netlink.Rtnl.Monitor.Event do
  @moduledoc """
  A single rtnetlink multicast notification decoded by
  `Linx.Netlink.Rtnl.Monitor`.

    * `:op` — what happened, as `{new,del}_{link,addr,route,neigh,rule}`, or
      `{:unknown, type}` for an `RTM_*` type the Monitor doesn't decode.
    * `:resource` — the decoded struct (`%Link{}`, `%Address{}`, …) for a known
      op, or `nil` for `{:unknown, _}`.

  Events are **wake-up hints**, not authoritative deltas: the netlink multicast
  stream is lossy (see the Monitor's `:resync_needed`), so a level-triggered
  consumer re-reads and re-diffs full state on any event rather than acting on
  the event's contents. The decoded `:resource` is for observability and
  filtering.
  """

  @enforce_keys [:op, :resource]
  defstruct [:op, :resource]

  @type op ::
          :new_link
          | :del_link
          | :new_addr
          | :del_addr
          | :new_route
          | :del_route
          | :new_neigh
          | :del_neigh
          | :new_rule
          | :del_rule
          | {:unknown, non_neg_integer()}

  @type t :: %__MODULE__{op: op(), resource: struct() | nil}

  defimpl Inspect do
    def inspect(%Linx.Netlink.Rtnl.Monitor.Event{op: op, resource: resource}, opts) do
      op_str = if is_tuple(op), do: "unknown:#{elem(op, 1)}", else: Atom.to_string(op)
      res = if resource, do: " " <> Inspect.inspect(resource, opts), else: ""
      "#Linx.Netlink.Rtnl.Monitor.Event<#{op_str}#{res}>"
    end
  end
end
