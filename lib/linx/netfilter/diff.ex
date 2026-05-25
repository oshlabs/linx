defmodule Linx.Netfilter.Diff do
  @moduledoc """
  Structural diff between two `%Linx.Netfilter.Ruleset{}` values,
  producing a `%Linx.Netfilter.Patch{}` of the minimum mutations
  that turn one into the other.

  ## Identity rules

    * **Tables, chains, sets, maps**: identity is `name` (within
      family for tables, within table for everything else).
    * **Rules within a chain**: identity is `:tag` when set; for
      untagged rules the diff falls back to positional index.
    * **Set elements**: identity is the element value itself (set
      semantics — no "modified", just add and remove).

  ## In-place vs delete+recreate

  An entity attribute change is rendered as an in-place op when
  the kernel supports it, otherwise as a delete+create pair:

    * **Rules**: any structural change → `:replace_rule`
      (`NLM_F_REPLACE` over the kernel-assigned handle from the
      *current* state). Requires the rule to have a `:tag` (or
      stable positional position with no neighbour changes).
    * **Chains**: most attribute changes (type, hook, priority)
      can't be replaced — emit `:delete_chain` + `:create_chain`.
      For N5 we conservatively delete+create on any difference.
    * **Tables**: flags / use_count differences → no-op (the N5
      diff treats tables as opaque containers; their lifecycle is
      managed via the `:owner` flag).
    * **Sets / maps**: declaration changes (key_type, data_type,
      flags) → delete+create. Element changes → element-level
      add/remove ops.

  ## Untagged rules

  When a chain's rule list differs and any of its rules is
  untagged, the diff cannot use `:tag`-based identity. It falls
  back to: if the lists are identical → no-op; otherwise emit
  `:delete_rule` for every current rule and `:create_rule` for
  every desired rule (full chain rebuild). The `:reconcile` push
  mode rejects this case at its entry point — see
  `Linx.Netfilter.Diff.validate_for_reconcile/1`.
  """

  alias Linx.Netfilter.{Chain, Patch, Rule, Ruleset, Table}
  alias Linx.Netfilter.Map, as: NMap
  alias Linx.Netfilter.Set

  @doc """
  Returns the `%Patch{}` that transforms `from` into `to`. Both
  inputs are `%Ruleset{}` values — the same shape `pull/1` returns
  and `push/2` consumes.

  The patch is topologically sorted (deletes before creates of
  their dependencies). `Patch.empty?/1` is true iff the rulesets
  are structurally equal modulo handle / kernel-assigned values.
  """
  @spec diff(Ruleset.t(), Ruleset.t()) :: Patch.t()
  def diff(%Ruleset{} = from, %Ruleset{} = to) do
    ops = diff_tables(from.tables, to.tables)
    Patch.new(ops) |> Patch.sort()
  end

  @doc """
  Validates that `desired` is reconcile-safe: every chain with
  more than one rule has tags on all of its rules.

  Returns `:ok` or `{:error, {:tag_required, {family, table, chain}}}`.
  """
  @spec validate_for_reconcile(Ruleset.t()) ::
          :ok | {:error, {:tag_required, {atom(), String.t(), String.t()}}}
  def validate_for_reconcile(%Ruleset{tables: tables}) do
    result =
      Enum.find_value(tables, fn {{family, table_name}, %Table{} = t} ->
        Enum.find_value(t.chains, fn {chain_name, %Chain{} = c} ->
          if length(c.rules) > 1 and Enum.any?(c.rules, &is_nil(&1.tag)) do
            {:tag_required, {family, table_name, chain_name}}
          end
        end)
      end)

    case result do
      nil -> :ok
      tagged -> {:error, tagged}
    end
  end

  # ===========================================================
  # Per-entity diff
  # ===========================================================

  # The diff is **scoped to tables in `to`** — tables in `from`
  # that aren't in `to` are left alone, not deleted. This matches
  # `:replace`-mode push semantics (Linx only touches the tables
  # the caller named) and means a `Linx.Netfilter` application can
  # coexist with Docker, firewalld, and other ruleset writers in
  # the same netns without stomping on them.
  #
  # To explicitly remove a table, the caller drops it from the
  # desired ruleset and uses a future explicit delete API (or
  # closes the owning socket for `:owner`-flagged tables — the
  # kernel reaps them).
  defp diff_tables(from_map, to_map) do
    from_keys = Map.keys(from_map) |> MapSet.new()
    to_keys = Map.keys(to_map) |> MapSet.new()

    creates =
      to_keys
      |> MapSet.difference(from_keys)
      |> Enum.flat_map(fn {family, _name} = key ->
        table = Map.fetch!(to_map, key)
        [{:create_table, family, table}] ++ create_table_contents(family, table)
      end)

    updates =
      from_keys
      |> MapSet.intersection(to_keys)
      |> Enum.flat_map(fn {family, _name} = key ->
        diff_table(family, Map.fetch!(from_map, key), Map.fetch!(to_map, key))
      end)

    creates ++ updates
  end

  # When creating a whole table, emit all its contents too.
  defp create_table_contents(family, %Table{} = t) do
    set_creates = Enum.map(t.sets, fn {_, s} -> {:create_set, family, s} end)
    map_creates = Enum.map(t.maps, fn {_, m} -> {:create_set, family, m} end)

    set_elem_adds =
      (Enum.map(t.sets, fn {_, s} -> set_elements_op(family, s) end) ++
         Enum.map(t.maps, fn {_, m} -> set_elements_op(family, m) end))
      |> Enum.reject(&is_nil/1)

    chain_creates =
      Enum.map(t.chains, fn {_, c} -> {:create_chain, family, t.name, c} end)

    rule_creates =
      Enum.flat_map(t.chains, fn {_, %Chain{} = c} ->
        Enum.map(c.rules, fn rule ->
          {:create_rule, family, t.name, c.name, rule, :append}
        end)
      end)

    set_creates ++ map_creates ++ chain_creates ++ set_elem_adds ++ rule_creates
  end

  defp set_elements_op(_family, %{elements: []}), do: nil

  defp set_elements_op(family, %{elements: els} = set_or_map) do
    {:add_set_elements, family, entity_table(set_or_map), set_or_map.name, els}
  end

  defp entity_table(%Set{table: t}), do: t
  defp entity_table(%NMap{table: t}), do: t

  defp diff_table(family, %Table{} = from, %Table{} = to) do
    diff_sets(family, to.name, from.sets, to.sets, :set) ++
      diff_sets(family, to.name, from.maps, to.maps, :map) ++
      diff_chains(family, to.name, from.chains, to.chains)
  end

  # ===========================================================
  # Chains
  # ===========================================================

  defp diff_chains(family, table_name, from_map, to_map) do
    from_names = Map.keys(from_map) |> MapSet.new()
    to_names = Map.keys(to_map) |> MapSet.new()

    deletes =
      from_names
      |> MapSet.difference(to_names)
      |> Enum.map(&{:delete_chain, family, table_name, &1})

    creates =
      to_names
      |> MapSet.difference(from_names)
      |> Enum.flat_map(fn name ->
        chain = Map.fetch!(to_map, name)
        rule_creates =
          Enum.map(chain.rules, fn rule ->
            {:create_rule, family, table_name, name, rule, :append}
          end)

        [{:create_chain, family, table_name, chain}] ++ rule_creates
      end)

    updates =
      from_names
      |> MapSet.intersection(to_names)
      |> Enum.flat_map(fn name ->
        diff_chain(family, table_name, name, Map.fetch!(from_map, name), Map.fetch!(to_map, name))
      end)

    deletes ++ creates ++ updates
  end

  defp diff_chain(family, table_name, name, %Chain{} = from, %Chain{} = to) do
    cond do
      chain_structurally_different?(from, to) ->
        # Attribute change → delete + recreate. Rules of the
        # recreated chain come along.
        rule_creates =
          Enum.map(to.rules, fn rule ->
            {:create_rule, family, table_name, name, rule, :append}
          end)

        [
          {:delete_chain, family, table_name, name},
          {:create_chain, family, table_name, to}
        ] ++ rule_creates

      true ->
        diff_rules(family, table_name, name, from.rules, to.rules)
    end
  end

  # Two chains differ structurally if any of their declaration
  # attributes diverged. The kernel can't NLM_F_REPLACE chains in
  # place for these — they need delete+create.
  #
  # Policy is normalised: `nil` is treated as the kernel default
  # `:accept` so a user-built ruleset that doesn't specify policy
  # matches a kernel-pulled chain (which always reports a policy).
  defp chain_structurally_different?(%Chain{} = a, %Chain{} = b) do
    a.type != b.type or a.hook != b.hook or a.priority != b.priority or
      not policy_equivalent?(a.policy, b.policy) or
      a.device != b.device or a.flags != b.flags
  end

  defp policy_equivalent?(nil, :accept), do: true
  defp policy_equivalent?(:accept, nil), do: true
  defp policy_equivalent?(a, b), do: a == b

  # ===========================================================
  # Rules
  # ===========================================================

  defp diff_rules(family, table_name, chain_name, from_rules, to_rules) do
    cond do
      from_rules == to_rules ->
        []

      all_tagged?(to_rules) and all_tagged?(from_rules) ->
        tagged_diff_rules(family, table_name, chain_name, from_rules, to_rules)

      true ->
        # Untagged rules — fall back to full chain rebuild (delete
        # all, recreate all). The :reconcile entry-point validates
        # this case away with :tag_required; this branch is here
        # for :replace mode running through the same encoder.
        full_rebuild_rules(family, table_name, chain_name, from_rules, to_rules)
    end
  end

  defp all_tagged?(rules), do: Enum.all?(rules, &(not is_nil(&1.tag)))

  defp tagged_diff_rules(family, table_name, chain_name, from_rules, to_rules) do
    from_by_tag = Map.new(from_rules, &{&1.tag, &1})
    to_by_tag = Map.new(to_rules, &{&1.tag, &1})

    from_tags = MapSet.new(Map.keys(from_by_tag))
    to_tags = MapSet.new(Map.keys(to_by_tag))

    deletes =
      from_tags
      |> MapSet.difference(to_tags)
      |> Enum.map(fn tag ->
        from_rule = Map.fetch!(from_by_tag, tag)
        {:delete_rule, family, table_name, chain_name, from_rule.handle}
      end)

    creates =
      to_tags
      |> MapSet.difference(from_tags)
      |> Enum.map(fn tag ->
        to_rule = Map.fetch!(to_by_tag, tag)
        {:create_rule, family, table_name, chain_name, to_rule, :append}
      end)

    replaces =
      from_tags
      |> MapSet.intersection(to_tags)
      |> Enum.flat_map(fn tag ->
        %Rule{} = from_rule = Map.fetch!(from_by_tag, tag)
        %Rule{} = to_rule = Map.fetch!(to_by_tag, tag)

        if rules_equivalent?(from_rule, to_rule) do
          []
        else
          # Carry the kernel-assigned handle through.
          [
            {:replace_rule, family, table_name, chain_name, from_rule.handle,
             %Rule{to_rule | handle: from_rule.handle}}
          ]
        end
      end)

    deletes ++ creates ++ replaces
  end

  defp rules_equivalent?(%Rule{} = a, %Rule{} = b) do
    # Compare expressions + tag + comment. Handle is kernel-assigned;
    # chain is context.
    a.expressions == b.expressions and a.tag == b.tag and a.comment == b.comment
  end

  defp full_rebuild_rules(family, table_name, chain_name, from_rules, to_rules) do
    deletes =
      Enum.map(from_rules, fn r ->
        {:delete_rule, family, table_name, chain_name, r.handle}
      end)

    creates =
      Enum.map(to_rules, fn r ->
        {:create_rule, family, table_name, chain_name, r, :append}
      end)

    deletes ++ creates
  end

  # ===========================================================
  # Sets and maps
  # ===========================================================

  defp diff_sets(family, table_name, from_map, to_map, _kind) do
    from_names = Map.keys(from_map) |> MapSet.new()
    to_names = Map.keys(to_map) |> MapSet.new()

    deletes =
      from_names
      |> MapSet.difference(to_names)
      |> Enum.map(&{:delete_set, family, table_name, &1})

    creates =
      to_names
      |> MapSet.difference(from_names)
      |> Enum.flat_map(fn name ->
        set_or_map = Map.fetch!(to_map, name)

        elem_op =
          if set_or_map.elements == [] do
            []
          else
            [{:add_set_elements, family, table_name, name, set_or_map.elements}]
          end

        [{:create_set, family, set_or_map}] ++ elem_op
      end)

    updates =
      from_names
      |> MapSet.intersection(to_names)
      |> Enum.flat_map(fn name ->
        diff_set(family, table_name, name, Map.fetch!(from_map, name), Map.fetch!(to_map, name))
      end)

    deletes ++ creates ++ updates
  end

  defp diff_set(family, table_name, name, from, to) do
    cond do
      set_structurally_different?(from, to) ->
        # Declaration change → delete + recreate.
        elem_op =
          if to.elements == [] do
            []
          else
            [{:add_set_elements, family, table_name, name, to.elements}]
          end

        [
          {:delete_set, family, table_name, name},
          {:create_set, family, to}
        ] ++ elem_op

      true ->
        diff_set_elements(family, table_name, name, from.elements, to.elements)
    end
  end

  defp set_structurally_different?(a, b) do
    cond do
      a.__struct__ != b.__struct__ -> true
      a.key_type != b.key_type -> true
      a.flags != b.flags -> true
      Map.get(a, :data_type) != Map.get(b, :data_type) -> true
      true -> false
    end
  end

  defp diff_set_elements(family, table_name, name, from_elems, to_elems) do
    from_set = MapSet.new(from_elems)
    to_set = MapSet.new(to_elems)

    adds = to_set |> MapSet.difference(from_set) |> Enum.to_list()
    dels = from_set |> MapSet.difference(to_set) |> Enum.to_list()

    []
    |> append_op(adds != [], {:add_set_elements, family, table_name, name, adds})
    |> append_op(dels != [], {:delete_set_elements, family, table_name, name, dels})
  end

  defp append_op(ops, true, op), do: ops ++ [op]
  defp append_op(ops, false, _op), do: ops
end
