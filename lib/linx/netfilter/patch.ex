defmodule Linx.Netfilter.Patch do
  @moduledoc """
  An ordered sequence of mutations that transforms one
  `%Linx.Netfilter.Ruleset{}` into another.

  Patches are produced by `Linx.Netfilter.diff/2` and consumed by
  `Linx.Netfilter.push/2` (mode `:reconcile`) — together they
  implement minimal-change updates: only the entities that actually
  differ between current and desired state hit the wire.

  ## Ops

  A patch is a list of `%Op{}` values. Op kinds:

    * `{:create_table, family, %Table{}}` — kernel doesn't have
      this table.
    * `{:delete_table, family, name}` — kernel has it, desired
      doesn't.
    * `{:create_chain, family, table_name, %Chain{}}`.
    * `{:delete_chain, family, table_name, chain_name}`.
    * `{:create_set, family, %Set{} | %Map{}}` — covers maps and
      vmaps too (dispatch on struct).
    * `{:delete_set, family, table_name, set_name}`.
    * `{:add_set_elements, family, table_name, set_name, [elem]}`.
    * `{:delete_set_elements, family, table_name, set_name, [elem]}`.
    * `{:create_rule, family, table_name, chain_name, %Rule{}, position}`
      — `position` is `:append` | `{:after, handle}` |
      `{:before, handle}` | `{:at_index, n}`.
    * `{:replace_rule, family, table_name, chain_name, handle, %Rule{}}`
      — in-place replace via `NLM_F_REPLACE`. Requires the
      kernel-assigned handle (carried by the rule pulled from
      the current ruleset).
    * `{:delete_rule, family, table_name, chain_name, handle}`.

  ## Ordering

  Patch ops are topologically sorted so creates of dependencies
  come before creates of dependents, and deletes happen in
  reverse:

      1. delete rules
      2. delete set elements
      3. delete chains   (no orphan-rule reference issue)
      4. delete sets
      5. delete tables
      6. create tables
      7. create sets / maps
      8. create chains
      9. add set elements   (chain may be jump target)
     10. replace rules     (chains+sets already exist)
     11. create rules

  This is the order `from_patch/1` emits inside one BATCH.

  ## Inspect

  Renders compactly:

      #Linx.Netfilter.Patch<7 ops: 2 creates, 4 replaces, 1 delete>
  """

  defstruct ops: []

  @type position ::
          :append
          | {:after, pos_integer()}
          | {:before, pos_integer()}
          | {:at_index, non_neg_integer()}

  @type op ::
          {:create_table, atom(), Linx.Netfilter.Table.t()}
          | {:delete_table, atom(), String.t()}
          | {:create_chain, atom(), String.t(), Linx.Netfilter.Chain.t()}
          | {:delete_chain, atom(), String.t(), String.t()}
          | {:create_set, atom(), Linx.Netfilter.Set.t() | Linx.Netfilter.Map.t()}
          | {:delete_set, atom(), String.t(), String.t()}
          | {:add_set_elements, atom(), String.t(), String.t(), [term()]}
          | {:delete_set_elements, atom(), String.t(), String.t(), [term()]}
          | {:create_rule, atom(), String.t(), String.t(), Linx.Netfilter.Rule.t(), position()}
          | {:replace_rule, atom(), String.t(), String.t(), pos_integer(),
             Linx.Netfilter.Rule.t()}
          | {:delete_rule, atom(), String.t(), String.t(), pos_integer()}

  @type t :: %__MODULE__{ops: [op()]}

  @doc "An empty patch — same value as `diff(r, r)`."
  @spec new([op()]) :: t()
  def new(ops \\ []), do: %__MODULE__{ops: ops}

  @doc "Returns `true` iff the patch contains no ops."
  @spec empty?(t()) :: boolean()
  def empty?(%__MODULE__{ops: []}), do: true
  def empty?(%__MODULE__{}), do: false

  @doc """
  Topologically sorts a patch's ops into the canonical create/
  delete order (see moduledoc). Idempotent — `sort/1` on an already-
  sorted patch is a no-op.
  """
  @spec sort(t()) :: t()
  def sort(%__MODULE__{ops: ops}) do
    %__MODULE__{ops: Enum.sort_by(ops, &op_order_key/1)}
  end

  # Lower number → earlier in the batch. Within a bucket, ops
  # preserve their input order (Enum.sort_by is stable).
  defp op_order_key({:delete_rule, _, _, _, _}), do: 1
  defp op_order_key({:delete_set_elements, _, _, _, _}), do: 2
  defp op_order_key({:delete_chain, _, _, _}), do: 3
  defp op_order_key({:delete_set, _, _, _}), do: 4
  defp op_order_key({:delete_table, _, _}), do: 5
  defp op_order_key({:create_table, _, _}), do: 6
  defp op_order_key({:create_set, _, _}), do: 7
  defp op_order_key({:create_chain, _, _, _}), do: 8
  defp op_order_key({:add_set_elements, _, _, _, _}), do: 9
  defp op_order_key({:replace_rule, _, _, _, _, _}), do: 10
  defp op_order_key({:create_rule, _, _, _, _, _}), do: 11

  defimpl Inspect do
    def inspect(%Linx.Netfilter.Patch{ops: ops}, _opts) do
      counts =
        Enum.reduce(ops, %{creates: 0, replaces: 0, deletes: 0, elems: 0}, fn op, acc ->
          case op do
            {:create_table, _, _} -> %{acc | creates: acc.creates + 1}
            {:create_chain, _, _, _} -> %{acc | creates: acc.creates + 1}
            {:create_set, _, _} -> %{acc | creates: acc.creates + 1}
            {:create_rule, _, _, _, _, _} -> %{acc | creates: acc.creates + 1}
            {:replace_rule, _, _, _, _, _} -> %{acc | replaces: acc.replaces + 1}
            {:delete_table, _, _} -> %{acc | deletes: acc.deletes + 1}
            {:delete_chain, _, _, _} -> %{acc | deletes: acc.deletes + 1}
            {:delete_set, _, _, _} -> %{acc | deletes: acc.deletes + 1}
            {:delete_rule, _, _, _, _} -> %{acc | deletes: acc.deletes + 1}
            {:add_set_elements, _, _, _, _} -> %{acc | elems: acc.elems + 1}
            {:delete_set_elements, _, _, _, _} -> %{acc | elems: acc.elems + 1}
          end
        end)

      parts =
        []
        |> append_if(counts.creates > 0, "#{counts.creates} create#{plural(counts.creates)}")
        |> append_if(counts.replaces > 0, "#{counts.replaces} replace#{plural(counts.replaces)}")
        |> append_if(counts.deletes > 0, "#{counts.deletes} delete#{plural(counts.deletes)}")
        |> append_if(counts.elems > 0, "#{counts.elems} element-op#{plural(counts.elems)}")

      total = length(ops)
      summary = if parts == [], do: "empty", else: Enum.join(parts, ", ")
      "#Linx.Netfilter.Patch<#{total} op#{plural(total)}: #{summary}>"
    end

    defp plural(1), do: ""
    defp plural(_), do: "s"

    defp append_if(list, true, item), do: list ++ [item]
    defp append_if(list, false, _item), do: list
  end
end
