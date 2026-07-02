defmodule Linx.Netfilter.Encoder do
  @moduledoc """
  Converts `%Linx.Netfilter.*{}` value structs into the
  `%Linx.Netlink.Message{}` shapes that ride inside a
  `NFNL_MSG_BATCH_BEGIN` / `NFNL_MSG_BATCH_END` envelope.

  Each public function returns a single `%Message{}` (or a list,
  for entities that map to multiple wire messages). `to_batch/2`
  walks a full `%Ruleset{}` and produces the ordered message list
  for a `:replace`-mode push. `Linx.Netlink.Nfnl.batch/2` wraps the
  envelope and drives the transaction.

  ## Wire format quirks

    * Every nftables `NLA_U32` / `NLA_U64` is **big-endian** on the
      wire — opposite to rtnetlink. `Linx.Netfilter.Wire.u32_be/1`
      / `u64_be/1` do the conversion.
    * The `nfgenmsg.family` byte carries the family this message
      applies to (`NFPROTO_INET`, etc.); `res_id` is 0 for most
      ops, the batch target's subsys id only for BATCH_BEGIN/END.
    * Attribute IDs are netfilter-namespaced (NFTA_TABLE_*,
      NFTA_CHAIN_*, etc.) — the same numeric ID can mean different
      things in different attribute sets.

  ## References

    * [`nft_table.c`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/netfilter/nf_tables_api.c)
      — kernel-side parser; canonical authority on attribute order
      and required fields.
  """

  import Bitwise
  import Linx.Netfilter.Wire
  import Linx.Netlink.Constants

  alias Linx.Netfilter.{Chain, Expr, Patch, Rule, Set, Table, Verdict, Wire}
  alias Linx.Netfilter.Map, as: NMap
  alias Linx.Netlink.{Attr, Message}
  alias Linx.Netlink.Nfnl.Codec

  # ===========================================================
  # Tables
  # ===========================================================

  @doc """
  Builds a single-table NEWTABLE message. The result is a
  `%Message{}` ready to drop into a batch.

  Default flags: `NLM_F_CREATE` — creates the table if missing,
  updates flags otherwise. Pass `excl: true` for create-or-fail
  (`NLM_F_EXCL`).

  Attribute payload:

    * `NFTA_TABLE_NAME` (string)
    * `NFTA_TABLE_FLAGS` (u32 BE) — `:dormant` | `:owner` |
      `:persist` flags OR'd via `Wire.table_flags_int/1`. Omitted
      when zero (libnftnl convention).
    * `NFTA_TABLE_USERDATA` (binary) — omitted when nil.
  """
  @spec table(Table.t(), keyword()) :: Message.t()
  def table(%Table{} = table, opts \\ []) do
    excl? = Keyword.get(opts, :excl, false)
    create? = Keyword.get(opts, :create, true)
    flags_int = Wire.table_flags_int(table.flags)

    attrs =
      [{nfta_table_name(), [table.name, 0]}]
      |> maybe_add(flags_int != 0, fn ->
        {nfta_table_flags(), Wire.u32_be(flags_int)}
      end)

    payload =
      Codec.encode_nfgenmsg(table.family, 0) <>
        Attr.encode(attrs)

    type = Codec.nlmsg_type(Codec.subsys_nftables(), nft_msg_newtable())

    base_flags = 0
    base_flags = if create?, do: base_flags ||| nlm_f_create(), else: base_flags
    base_flags = if excl?, do: base_flags ||| nlm_f_excl(), else: base_flags

    %Message{type: type, flags: base_flags, payload: payload}
  end

  @doc """
  Builds a GETTABLE request — for fetching one table by
  `(family, name)` from the kernel.

  No `NLM_F_DUMP` — that's `gettable_dump/1` (for listing all
  tables in the netns).
  """
  @spec gettable(Table.family(), String.t()) :: Message.t()
  def gettable(family, name) when is_atom(family) and is_binary(name) do
    payload =
      Codec.encode_nfgenmsg(family, 0) <>
        Attr.encode([{nfta_table_name(), [name, 0]}])

    %Message{
      type: Codec.nlmsg_type(Codec.subsys_nftables(), nft_msg_gettable()),
      flags: 0,
      payload: payload
    }
  end

  @doc """
  Builds a GETTABLE dump request — returns every table in the
  netns. Filtering by family is optional (`:unspec` returns all
  families).
  """
  @spec gettable_dump(atom()) :: Message.t()
  def gettable_dump(family \\ :unspec) when is_atom(family) do
    payload = Codec.encode_nfgenmsg(family, 0)

    %Message{
      type: Codec.nlmsg_type(Codec.subsys_nftables(), nft_msg_gettable()),
      flags: nlm_f_dump(),
      payload: payload
    }
  end

  @doc """
  Builds a DELTABLE message for the given table.

  Returns `:enoent` from the kernel if the table doesn't exist —
  use `destroytable/2` for silent-if-missing semantics (6.3+).
  """
  @spec deltable(Table.family(), String.t()) :: Message.t()
  def deltable(family, name) when is_atom(family) and is_binary(name) do
    payload =
      Codec.encode_nfgenmsg(family, 0) <>
        Attr.encode([{nfta_table_name(), [name, 0]}])

    %Message{
      type: Codec.nlmsg_type(Codec.subsys_nftables(), nft_msg_deltable()),
      flags: 0,
      payload: payload
    }
  end

  @doc """
  Builds a DESTROYTABLE message — silently a no-op if the table
  doesn't exist. Used by `:replace`-mode push to clear pre-existing
  state before re-creating it.

  Requires kernel ≥ 6.3 (where DESTROY* messages were added).
  """
  @spec destroytable(Table.family(), String.t()) :: Message.t()
  def destroytable(family, name) when is_atom(family) and is_binary(name) do
    payload =
      Codec.encode_nfgenmsg(family, 0) <>
        Attr.encode([{nfta_table_name(), [name, 0]}])

    %Message{
      type: Codec.nlmsg_type(Codec.subsys_nftables(), nft_msg_destroytable()),
      flags: 0,
      payload: payload
    }
  end

  # ===========================================================
  # Whole-ruleset batch (:replace mode)
  # ===========================================================

  @doc """
  Builds the ordered message list for a `:replace`-mode push of
  `ruleset`.

  For each table in `ruleset`, the batch contains:

    1. `DESTROYTABLE` — silently destroys any existing table by the
       same `(family, name)`, ensuring fresh state.
    2. `NEWTABLE` — recreate with the desired flags.
    3. `NEWCHAIN` for each chain in the table (in map iteration
       order; the kernel doesn't care about chain order).
    4. `NEWRULE` for each rule in each chain, **in rule-list
       order** — rule ordering matters at runtime, the kernel
       preserves the batch order via `NLM_F_APPEND`.

  Named objects are emitted right after `NEWTABLE` (declarations
  before the rules that reference them). Flowtables are not yet
  emitted; the batch shape supports them by interleaving in
  step 3.

  This list is intended to drop straight into
  `Linx.Netlink.Nfnl.batch/2`; it does not include the
  `BATCH_BEGIN` / `BATCH_END` envelope (that's `batch/2`'s job).
  """
  @spec to_batch(Linx.Netfilter.Ruleset.t(), keyword()) :: [Message.t()]
  def to_batch(%Linx.Netfilter.Ruleset{} = ruleset, _opts \\ []) do
    Enum.flat_map(ruleset.tables, fn {{family, _name}, %Table{} = table} ->
      {rewritten_chains, anonymous_sets} = expand_anonymous_sets(table)

      sets_msgs = Enum.map(table.sets, fn {_, s} -> set(s, family) end)
      maps_msgs = Enum.map(table.maps, fn {_, m} -> set(m, family) end)
      anon_set_msgs = Enum.map(anonymous_sets, &set(&1, family))
      obj_msgs = Enum.map(table.objects, fn {_, o} -> object(o, family, table.name) end)

      set_elem_msgs =
        (Enum.map(table.sets, fn {_, s} -> set_elements(s, family) end) ++
           Enum.map(table.maps, fn {_, m} -> set_elements(m, family) end) ++
           Enum.map(anonymous_sets, &set_elements(&1, family)))
        |> Enum.reject(&is_nil/1)

      chain_msgs = Enum.map(rewritten_chains, fn {_, c} -> chain(c, family) end)

      rule_msgs =
        Enum.flat_map(rewritten_chains, fn {_, %Chain{} = chain} ->
          Enum.map(chain.rules, fn %Rule{} = rule ->
            rule(rule, family, table.name, chain.name)
          end)
        end)

      # Order matters: declarations before references.
      #   named objects + named/anonymous sets/maps → rules can
      #     reference them
      #   chains → vmap verdicts can reference them by name
      #   set/map elements → vmaps with jump/goto verdicts find chains
      #   rules → everything referenced exists
      [destroytable(family, table.name), table(table)] ++
        obj_msgs ++
        sets_msgs ++ maps_msgs ++ anon_set_msgs ++ chain_msgs ++ set_elem_msgs ++ rule_msgs
    end)
  end

  @doc """
  Builds a `NEWOBJ` message declaring a table-level named object
  (counter, quota, …). Only `:counter` has a data encoding so far;
  other kinds raise until their NFTA_OBJ_DATA shapes land.
  """
  @spec object(Linx.Netfilter.Object.t(), atom(), String.t()) :: Message.t()
  def object(%Linx.Netfilter.Object{} = obj, family, table_name) do
    data_attrs =
      case {obj.kind, obj.data} do
        {:counter, data} ->
          data = data || %{}

          [
            {nfta_counter_bytes(), Wire.u64_be(Map.get(data, :bytes, 0))},
            {nfta_counter_packets(), Wire.u64_be(Map.get(data, :packets, 0))}
          ]

        {kind, _} ->
          raise ArgumentError,
                "NEWOBJ encoding for #{inspect(kind)} objects is not implemented yet"
      end

    attrs = [
      {nfta_obj_table(), [table_name, 0]},
      {nfta_obj_name(), [obj.name, 0]},
      {nfta_obj_type(), Wire.u32_be(object_kind_int(obj.kind))},
      {nfta_obj_data(), Attr.encode(data_attrs)}
    ]

    %Message{
      type: Codec.nlmsg_type(Codec.subsys_nftables(), nft_msg_newobj()),
      flags: nlm_f_create(),
      payload: Codec.encode_nfgenmsg(family, 0) <> Attr.encode(attrs)
    }
  end

  defp object_kind_int(:counter), do: nft_object_counter()
  defp object_kind_int(:quota), do: nft_object_quota()
  defp object_kind_int(:ct_helper), do: nft_object_ct_helper()
  defp object_kind_int(:limit), do: nft_object_limit()
  defp object_kind_int(:connlimit), do: nft_object_connlimit()
  defp object_kind_int(:ct_timeout), do: nft_object_ct_timeout()
  defp object_kind_int(:secmark), do: nft_object_secmark()
  defp object_kind_int(:ct_expectation), do: nft_object_ct_expect()
  defp object_kind_int(:synproxy), do: nft_object_synproxy()

  # Walks all rules in `table`, replacing every `:__anon_set`
  # sentinel expression with a regular `lookup`. Returns the
  # rewritten chains map and the list of anonymous Set values
  # that must be emitted as NEWSET + NEWSETELEM before any rule
  # references them.
  defp expand_anonymous_sets(%Table{} = table) do
    {chains, anon_sets, _counter} =
      Enum.reduce(table.chains, {%{}, [], 0}, fn {chain_name, %Chain{} = chain},
                                                 {chains_acc, sets_acc, n} ->
        {rewritten_rules, new_sets, n2} =
          Enum.reduce(chain.rules, {[], sets_acc, n}, fn rule, {rules, sa, nn} ->
            {rewritten, sa2, nn2} = rewrite_rule_anon_sets(rule, table.name, sa, nn)
            {rules ++ [rewritten], sa2, nn2}
          end)

        new_chain = %Chain{chain | rules: rewritten_rules}
        {Map.put(chains_acc, chain_name, new_chain), new_sets, n2}
      end)

    {chains, anon_sets}
  end

  defp rewrite_rule_anon_sets(%Rule{expressions: exprs} = rule, table_name, sets_acc, counter) do
    {new_exprs, sets_acc2, counter2} =
      Enum.reduce(exprs, {[], sets_acc, counter}, fn
        %Expr{name: :__anon_set, data: data}, {acc, sa, n} ->
          name = "__set#{n}"

          {:ok, anon_set} =
            Linx.Netfilter.Set.new(name,
              key_type: data.key_type,
              flags: Enum.uniq([:anonymous | data.flags]),
              elements: data.values,
              table: table_name
            )

          lookup_expr = %Expr{
            name: :lookup,
            data: %{set: name, sreg: data.sreg, dreg: nil, flags: []}
          }

          {acc ++ [lookup_expr], sa ++ [anon_set], n + 1}

        # Anonymous verdict map — `tcp dport vmap { 22 : accept }`.
        # Same lifecycle as an anonymous set, but the lookup's
        # destination is the verdict register (0) so the map data
        # BECOMES the rule verdict.
        %Expr{name: :__anon_vmap, data: data}, {acc, sa, n} ->
          name = "__map#{n}"

          {:ok, anon_map} =
            Linx.Netfilter.Map.new(name,
              key_type: data.key_type,
              data_type: :verdict,
              flags: [:anonymous, :constant],
              elements: data.elements,
              table: table_name
            )

          lookup_expr = %Expr{
            name: :lookup,
            data: %{set: name, sreg: Map.get(data, :sreg, 1), dreg: 0, flags: []}
          }

          {acc ++ [lookup_expr], sa ++ [anon_map], n + 1}

        other, {acc, sa, n} ->
          {acc ++ [other], sa, n}
      end)

    {%Rule{rule | expressions: new_exprs}, sets_acc2, counter2}
  end

  # ===========================================================
  # Chains
  # ===========================================================

  @doc """
  Builds a `NEWCHAIN` message for `chain` within `family`.

  Required at construction:

    * `NFTA_CHAIN_TABLE` (string) — taken from `chain.table`.
    * `NFTA_CHAIN_NAME` (string).

  Base-chain attributes (set together when `chain` is a base chain):

    * `NFTA_CHAIN_HOOK` (nested) — `NFTA_HOOK_HOOKNUM` (u32 BE),
      `NFTA_HOOK_PRIORITY` (s32 BE), and `NFTA_HOOK_DEV` (string)
      for `:ingress`/`:egress`.
    * `NFTA_CHAIN_TYPE` (string: `"filter"` | `"nat"` | `"route"`).
    * `NFTA_CHAIN_POLICY` (u32 BE, NF_ACCEPT=1 / NF_DROP=0) — only
      when `chain.policy` is set.
    * `NFTA_CHAIN_FLAGS` (u32 BE) — when `chain.flags` is non-empty.

  Regular chains skip the HOOK / TYPE / POLICY attributes entirely.
  """
  @spec chain(Chain.t(), Table.family(), keyword()) :: Message.t()
  def chain(%Chain{} = chain, family, opts \\ []) when is_atom(family) and is_list(opts) do
    excl? = Keyword.get(opts, :excl, false)
    create? = Keyword.get(opts, :create, true)

    attrs =
      [
        {nfta_chain_table(), [chain.table, 0]},
        {nfta_chain_name(), [chain.name, 0]}
      ]
      |> maybe_add(Chain.base?(chain), fn ->
        {nfta_chain_hook(), encode_hook(chain, family)}
      end)
      |> maybe_add(Chain.base?(chain), fn ->
        {nfta_chain_type(), [Wire.chain_type_string(chain.type), 0]}
      end)
      |> maybe_add(not is_nil(chain.policy), fn ->
        {nfta_chain_policy(), Wire.u32_be(Wire.policy_int(chain.policy))}
      end)
      |> maybe_add(chain.flags != [], fn ->
        {nfta_chain_flags(), Wire.u32_be(Wire.chain_flags_int(chain.flags))}
      end)

    payload = Codec.encode_nfgenmsg(family, 0) <> Attr.encode(attrs)

    base_flags = 0
    base_flags = if create?, do: base_flags ||| nlm_f_create(), else: base_flags
    base_flags = if excl?, do: base_flags ||| nlm_f_excl(), else: base_flags

    %Message{
      type: Codec.nlmsg_type(Codec.subsys_nftables(), nft_msg_newchain()),
      flags: base_flags,
      payload: payload
    }
  end

  defp encode_hook(%Chain{hook: hook, priority: priority, device: device}, family) do
    hooknum = Wire.hook_num(family, hook)
    prio_int = Wire.priority_int(family, priority)

    inner =
      [
        {nfta_hook_hooknum(), Wire.u32_be(hooknum)},
        {nfta_hook_priority(), Wire.s32_be(prio_int)}
      ]
      |> maybe_add(not is_nil(device), fn ->
        {nfta_hook_dev(), [device, 0]}
      end)

    Attr.encode(inner)
  end

  # ===========================================================
  # Sets / maps
  # ===========================================================

  @doc """
  Builds a `NEWSET` message. Accepts either a `%Linx.Netfilter.Set{}`
  (plain set) or a `%Linx.Netfilter.Map{}` (typed map, including
  vmaps — `data_type: :verdict`).

  The encoder auto-derives the `NFT_SET_F_MAP` flag for maps and
  `NFT_SET_F_EVAL` for `:dynamic` sets; callers shouldn't include
  them in `:flags` directly (but `set_flags_int/1` accepts them
  for round-trip purposes).
  """
  @spec set(Set.t() | NMap.t(), Table.family(), keyword()) :: Message.t()
  def set(set_or_map, family, opts \\ []) when is_atom(family) and is_list(opts) do
    excl? = Keyword.get(opts, :excl, false)
    create? = Keyword.get(opts, :create, true)

    {table, name, key_type, data_type, flags, elements, timeout, gc_interval, size, _kind} =
      extract_set_fields(set_or_map)

    {key_id, key_len} = Wire.set_type_info(key_type)

    # Auto-set flags based on shape
    auto_flags =
      flags
      |> maybe_append_atom(data_type != nil, :map)

    flags_int = Wire.set_flags_int(auto_flags)

    # Transaction-local set ID. The kernel uses this to resolve
    # set references from rules created in the same batch (via
    # NFTA_LOOKUP_SET_ID). Even when rules reference by name,
    # libnftnl always sends it and recent kernels expect it on
    # NEWSET. Generate a stable-within-this-encode id from a
    # process counter.
    set_id = Keyword.get(opts, :set_id, next_set_id())

    base_attrs =
      [
        {nfta_set_table(), [table, 0]},
        {nfta_set_name(), [name, 0]},
        {nfta_set_flags(), Wire.u32_be(flags_int)},
        {nfta_set_key_type(), Wire.u32_be(key_id)},
        {nfta_set_key_len(), Wire.u32_be(key_len)},
        {nfta_set_id(), Wire.u32_be(set_id)}
      ]
      |> maybe_add(data_type != nil, fn ->
        {data_id, _data_len} = Wire.set_type_info(data_type)

        # NFTA_SET_DATA_TYPE for verdict maps must be 0xffffff00 sentinel
        # (NFT_DATA_VERDICT) when the kernel-side data is a verdict;
        # otherwise the libnftnl type id.
        data_type_int =
          case data_type do
            :verdict -> 0xFFFFFF00
            _ -> data_id
          end

        {nfta_set_data_type(), Wire.u32_be(data_type_int)}
      end)
      |> maybe_add(data_type != nil, fn ->
        {_data_id, data_len} = Wire.set_type_info(data_type)
        {nfta_set_data_len(), Wire.u32_be(data_len)}
      end)
      |> maybe_add(not is_nil(timeout), fn ->
        {nfta_set_timeout(), Wire.u64_be(timeout)}
      end)
      |> maybe_add(not is_nil(gc_interval), fn ->
        {nfta_set_gc_interval(), Wire.u32_be(gc_interval)}
      end)
      |> maybe_add(not is_nil(size), fn ->
        # Note on concatenated keys: nft sends NFTA_SET_DESC_CONCAT
        # (+ the NFT_SET_CONCAT flag) ONLY for interval concat sets
        # (evaluate.c:5300, pipapo ranges). A plain concat set is
        # just a hash set whose key length is the padded sum of the
        # fields — the kernel EINVALs a DESC_CONCAT without the
        # flag. We only support non-interval concats so far, so no
        # DESC_CONCAT is emitted; it lands together with pipapo
        # support.
        desc = Attr.encode([{nfta_set_desc_size(), Wire.u32_be(size)}])
        {nfta_set_desc(), desc}
      end)

    payload = Codec.encode_nfgenmsg(family, 0) <> Attr.encode(base_attrs)

    base_flags = 0
    base_flags = if create?, do: base_flags ||| nlm_f_create(), else: base_flags
    base_flags = if excl?, do: base_flags ||| nlm_f_excl(), else: base_flags

    _ = elements

    %Message{
      type: Codec.nlmsg_type(Codec.subsys_nftables(), nft_msg_newset()),
      flags: base_flags,
      payload: payload
    }
  end

  @doc """
  Builds a `NEWSETELEM` message — adds one or more elements to a
  named set.

  Elements is a list of either:

    * raw key terms (for plain sets) — `[{10,0,0,1}, "1.2.3.4", ...]`.
    * `{key, data}` tuples (for maps and vmaps) — `[{22, %Verdict{...}}, ...]`.

  The encoder normalises each into the wire form using
  `key_type` / `data_type` from the parent set.
  """
  @spec set_elements(Set.t() | NMap.t(), Table.family(), keyword()) :: Message.t() | nil
  def set_elements(set_or_map, family, opts \\ []) when is_atom(family) and is_list(opts) do
    {table, name, key_type, data_type, flags, elements, _, _, _, _} =
      extract_set_fields(set_or_map)

    case elements do
      [] ->
        nil

      _ ->
        elements_bin =
          encode_set_elements(elements, key_type, data_type, :interval in flags)

        attrs = [
          {nfta_set_elem_list_table(), [table, 0]},
          {nfta_set_elem_list_set(), [name, 0]},
          {nfta_set_elem_list_elements(), elements_bin}
        ]

        payload = Codec.encode_nfgenmsg(family, 0) <> Attr.encode(attrs)
        create? = Keyword.get(opts, :create, true)
        base_flags = if create?, do: nlm_f_create(), else: 0

        %Message{
          type: Codec.nlmsg_type(Codec.subsys_nftables(), nft_msg_newsetelem()),
          flags: base_flags,
          payload: payload
        }
    end
  end

  defp encode_set_elements(elements, key_type, data_type, interval?) do
    elements
    |> Enum.flat_map(fn elem -> encode_one_set_elem(elem, key_type, data_type, interval?) end)
    |> Attr.encode()
  end

  # One element term becomes one NFTA_LIST_ELEM entry — or, in an interval
  # set, two: the kernel's rbtree represents the interval [lo, hi] as a
  # start element keyed `lo` plus an element keyed `hi+1` flagged
  # NFT_SET_ELEM_INTERVAL_END (the encoding nft/libnftnl use for plain,
  # non-concatenated interval sets — it works on every kernel, unlike the
  # newer NFTA_SET_ELEM_KEY_END, which needs >= 5.6). A *scalar* member of
  # an interval set is the degenerate interval [v, v+1) and needs its end
  # marker too — a bare start key would otherwise match everything up to
  # the next element.
  defp encode_one_set_elem(elem, key_type, data_type, interval?) do
    {key_term, data_term} =
      case data_type do
        nil -> {elem, nil}
        _ -> elem
      end

    data_attrs =
      case data_type do
        nil -> []
        _ -> [{nfta_set_elem_data(), encode_set_elem_data(data_term, data_type)}]
      end

    case {normalize_key(key_term, key_type), interval?} do
      {{:scalar, key_bin}, false} ->
        [set_elem_entry(key_bin, data_attrs, false)]

      {{:scalar, key_bin}, true} ->
        [set_elem_entry(key_bin, data_attrs, false) | interval_end_entries(key_bin)]

      {{:range, lo_bin, hi_bin}, true} ->
        [set_elem_entry(lo_bin, data_attrs, false) | interval_end_entries(hi_bin)]

      {{:range, _, _}, false} ->
        raise ArgumentError,
              "range/CIDR set element #{inspect(key_term)} requires a set with the " <>
                ":interval flag"
    end
  end

  # The end-of-interval marker: key = hi + 1 (the end bound is exclusive on
  # the wire). When hi is the type's maximum the interval runs to the end of
  # the keyspace and no marker is needed (incrementing would wrap).
  defp interval_end_entries(hi_bin) do
    case increment_key(hi_bin) do
      :overflow -> []
      end_bin -> [set_elem_entry(end_bin, [], true)]
    end
  end

  defp set_elem_entry(key_bin, data_attrs, interval_end?) do
    # NFTA_SET_ELEM_KEY = nested NFTA_DATA_VALUE
    key_nla = Attr.encode([{nfta_data_value(), key_bin}])

    inner_attrs =
      [{nfta_set_elem_key(), key_nla}]
      |> Kernel.++(data_attrs)
      |> maybe_add(interval_end?, fn ->
        {nfta_set_elem_flags(), Wire.u32_be(nft_set_elem_interval_end())}
      end)

    {nfta_list_elem(), Attr.encode(inner_attrs)}
  end

  # Big-endian +1 over the full key width. All range-capable key types
  # (addresses, ports) are network-order, so this is also memcmp order —
  # the order the kernel's interval backends compare keys in.
  defp increment_key(bin) do
    size = byte_size(bin) * 8
    <<n::size(size)>> = bin

    if n == (1 <<< size) - 1 do
      :overflow
    else
      <<n + 1::size(size)>>
    end
  end

  defp encode_set_elem_data(%Verdict{} = v, :verdict) do
    # NFTA_SET_ELEM_DATA → nested NFTA_DATA_VERDICT
    Attr.encode(encode_data_verdict(v))
  end

  defp encode_set_elem_data(value, data_type) do
    bin = encode_key_value(value, data_type)
    Attr.encode([{nfta_data_value(), bin}])
  end

  # Classifies one key term as a scalar or a range and renders the wire
  # bytes for its bound(s). Range shapes: `{:range, lo, hi}` (the ~NFT
  # compiler's form), a bare `{lo, hi}` integer pair (accepted by
  # `Set.Element.check/2` for ports), and textual CIDR ("10.0.0.0/8").
  defp normalize_key({:range, lo, hi}, type),
    do: {:range, encode_key_value(lo, type), encode_key_value(hi, type)}

  defp normalize_key({lo, hi}, :inet_service) when is_integer(lo) and is_integer(hi),
    do: {:range, encode_key_value(lo, :inet_service), encode_key_value(hi, :inet_service)}

  defp normalize_key(value, type) when type in [:ipv4_addr, :ipv6_addr] and is_binary(value) do
    case String.contains?(value, "/") and Linx.IP.Subnet.parse(value) do
      {:ok, %Linx.IP.Subnet{} = subnet} ->
        {:range, subnet_first(subnet), subnet_last(subnet)}

      _ ->
        {:scalar, encode_key_value(value, type)}
    end
  end

  defp normalize_key(value, type), do: {:scalar, encode_key_value(value, type)}

  # First / last address covered by a CIDR prefix, as raw key bytes.
  defp subnet_first(%Linx.IP.Subnet{address: %Linx.IP{bytes: bytes}, prefix: prefix}) do
    size = byte_size(bytes) * 8
    <<n::size(size)>> = bytes
    mask = ((1 <<< prefix) - 1) <<< (size - prefix)
    <<n &&& mask::size(size)>>
  end

  defp subnet_last(%Linx.IP.Subnet{address: %Linx.IP{bytes: bytes}, prefix: prefix}) do
    size = byte_size(bytes) * 8
    <<n::size(size)>> = bytes
    mask = ((1 <<< prefix) - 1) <<< (size - prefix)
    host = (1 <<< (size - prefix)) - 1
    <<(n &&& mask) ||| host::size(size)>>
  end

  # Renders one scalar value as its wire bytes, directed by the set's
  # declared key/data type. Binaries of exactly the key width pass through
  # verbatim (the raw escape hatch); other strings are *parsed* — a textual
  # "1.2.3.4" must become 4 address bytes, never its 7 ASCII bytes.
  defp encode_key_value(value, type) do
    cond do
      # Concatenated key: one part per field, each encoded with its
      # field's type and padded to the 4-byte register boundary.
      match?({:concat, _}, type) and is_list(value) ->
        {:concat, types} = type

        if length(value) != length(types) do
          raise ArgumentError,
                "concat element #{inspect(value)} has #{length(value)} parts, " <>
                  "key type has #{length(types)}"
        end

        value
        |> Enum.zip(types)
        |> Enum.map(fn {part, t} -> pad_key4(encode_key_value(part, t)) end)
        |> IO.iodata_to_binary()

      type == :ipv4_addr and is_tuple(value) and tuple_size(value) == 4 ->
        {a, b, c, d} = value
        <<a, b, c, d>>

      type == :ipv6_addr and is_tuple(value) and tuple_size(value) == 8 ->
        {a, b, c, d, e, f, g, h} = value
        <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>

      type in [:ipv4_addr, :ipv6_addr] and is_binary(value) ->
        encode_addr_key(value, type)

      type == :ether_addr and is_tuple(value) and tuple_size(value) == 6 ->
        {a, b, c, d, e, f} = value
        <<a, b, c, d, e, f>>

      type == :inet_service and is_integer(value) ->
        <<value::big-16>>

      type == :inet_proto and is_integer(value) ->
        <<value>>

      # Marks (and the other fwmark-like u32s) live in host byte order in
      # the kernel: the lookup register is a raw native u32, so the key
      # bytes must be native too — big-endian keys would only match on
      # big-endian hosts.
      type == :mark and is_integer(value) ->
        <<value::native-32>>

      # ct state keys follow the big-endian u32 convention the rule
      # compiler already uses for ct state bitwise/cmp matching.
      type == :ct_state and is_integer(value) ->
        <<value::big-32>>

      # The declared key length for :ifname is IFNAMSIZ (16); the kernel
      # compares the full width, so pad with NULs like nft does.
      type == :ifname and is_binary(value) and byte_size(value) < 16 ->
        value <> :binary.copy(<<0>>, 16 - byte_size(value))

      is_binary(value) ->
        value

      true ->
        raise ArgumentError,
              "cannot encode set element #{inspect(value)} for type #{inspect(type)}"
    end
  end

  defp pad_key4(bin) when is_binary(bin) do
    case rem(byte_size(bin), 4) do
      0 -> bin
      r -> bin <> :binary.copy(<<0>>, 4 - r)
    end
  end

  # A binary key for an address type is either raw key bytes (exact width)
  # or a textual address. Parse first: no valid textual IPv4 is 4 bytes
  # long, and a 16-byte raw IPv6 key that also parses as a textual address
  # is practically impossible (use the tuple form to be explicit).
  defp encode_addr_key(value, type) do
    width = if type == :ipv4_addr, do: 4, else: 16

    case Linx.IP.parse(value) do
      {:ok, %Linx.IP{bytes: bytes}} when byte_size(bytes) == width ->
        bytes

      {:ok, %Linx.IP{}} ->
        raise ArgumentError,
              "address #{inspect(value)} does not match set key type #{inspect(type)}"

      {:error, _} when byte_size(value) == width ->
        value

      {:error, _} ->
        raise ArgumentError,
              "cannot encode set element #{inspect(value)} for type #{inspect(type)}: " <>
                "not a parseable address and not #{width} raw bytes"
    end
  end

  defp extract_set_fields(%Set{} = s) do
    {s.table, s.name, s.key_type, nil, s.flags, s.elements, s.timeout, s.gc_interval, s.size,
     :set}
  end

  defp extract_set_fields(%NMap{} = m) do
    {m.table, m.name, m.key_type, m.data_type, m.flags, m.elements, m.timeout, m.gc_interval,
     m.size, :map}
  end

  defp maybe_append_atom(flags, true, atom),
    do: if(atom in flags, do: flags, else: flags ++ [atom])

  defp maybe_append_atom(flags, false, _atom), do: flags

  # Process-local atomic counter for set IDs. The kernel only cares
  # that IDs within one batch are unique; we just give every set a
  # fresh value.
  defp next_set_id do
    counter =
      case :persistent_term.get({__MODULE__, :set_id_counter}, nil) do
        nil ->
          ref = :atomics.new(1, signed: false)
          :persistent_term.put({__MODULE__, :set_id_counter}, ref)
          ref

        ref ->
          ref
      end

    :atomics.add_get(counter, 1, 1)
  end

  @doc """
  Builds a `DELSET` message — removes a named set by `(family,
  table, name)`. Returns `:enoent` from the kernel if missing.
  """
  @spec delete_set(Table.family(), String.t(), String.t()) :: Message.t()
  def delete_set(family, table_name, set_name)
      when is_atom(family) and is_binary(table_name) and is_binary(set_name) do
    attrs =
      [
        {nfta_set_table(), [table_name, 0]},
        {nfta_set_name(), [set_name, 0]}
      ]

    %Message{
      type: Codec.nlmsg_type(Codec.subsys_nftables(), nft_msg_delset()),
      flags: 0,
      payload: Codec.encode_nfgenmsg(family, 0) <> Attr.encode(attrs)
    }
  end

  @doc """
  Builds a `DELSETELEM` message that removes the given elements
  from a set by raw element values.

  `interval?` must mirror the parent set's `:interval` flag so ranges (and
  scalar members of interval sets) delete the same start/end element pair
  they were added as.
  """
  @spec delete_set_elements(
          Table.family(),
          String.t(),
          String.t(),
          [term()],
          atom(),
          atom() | nil,
          boolean()
        ) :: Message.t()
  def delete_set_elements(
        family,
        table_name,
        set_name,
        elements,
        key_type,
        data_type,
        interval? \\ false
      )
      when is_atom(family) and is_binary(table_name) and is_binary(set_name) and
             is_list(elements) and is_atom(key_type) do
    elements_bin = encode_set_elements(elements, key_type, data_type, interval?)

    attrs = [
      {nfta_set_elem_list_table(), [table_name, 0]},
      {nfta_set_elem_list_set(), [set_name, 0]},
      {nfta_set_elem_list_elements(), elements_bin}
    ]

    %Message{
      type: Codec.nlmsg_type(Codec.subsys_nftables(), nft_msg_delsetelem()),
      flags: 0,
      payload: Codec.encode_nfgenmsg(family, 0) <> Attr.encode(attrs)
    }
  end

  # ===========================================================
  # Rules
  # ===========================================================

  @doc """
  Builds a `NEWRULE` message for `rule` inside the `(family, table, chain)`
  scope.

  Attribute payload:

    * `NFTA_RULE_TABLE` (string).
    * `NFTA_RULE_CHAIN` (string).
    * `NFTA_RULE_EXPRESSIONS` (nested list of `NFTA_LIST_ELEM`s)
      — each list element wraps `NFTA_EXPR_NAME` (string) plus
      `NFTA_EXPR_DATA` (nested, per-expression attribute set).

  Comment / tag round-trip via `NFTA_RULE_USERDATA`.
  """
  @spec rule(Rule.t(), Table.family(), String.t(), String.t(), keyword()) :: Message.t()
  def rule(%Rule{} = rule, family, table_name, chain_name, opts \\ []) do
    excl? = Keyword.get(opts, :excl, false)
    create? = Keyword.get(opts, :create, true)
    replace? = Keyword.get(opts, :replace, false)
    handle = Keyword.get(opts, :handle, rule.handle)
    position = Keyword.get(opts, :position)

    expressions_bin = encode_expressions(rule.expressions)
    userdata = encode_rule_userdata(rule.tag, rule.comment)

    attrs =
      [
        {nfta_rule_table(), [table_name, 0]},
        {nfta_rule_chain(), [chain_name, 0]},
        {nfta_rule_expressions(), expressions_bin}
      ]
      |> maybe_add(replace? and not is_nil(handle), fn ->
        {nfta_rule_handle(), Wire.u64_be(handle)}
      end)
      |> maybe_add_position(position)
      |> maybe_add(userdata != <<>>, fn ->
        {nfta_rule_userdata(), userdata}
      end)

    payload = Codec.encode_nfgenmsg(family, 0) <> Attr.encode(attrs)

    base_flags = 0
    base_flags = if create? and not replace?, do: base_flags ||| nlm_f_create(), else: base_flags
    base_flags = if excl?, do: base_flags ||| nlm_f_excl(), else: base_flags
    base_flags = if replace?, do: base_flags ||| nlm_f_replace(), else: base_flags
    # NLM_F_APPEND ensures the rule is appended (the kernel's
    # default with NEWRULE-without-position is to prepend).
    base_flags = if not replace?, do: base_flags ||| nlm_f_append(), else: base_flags

    %Message{
      type: Codec.nlmsg_type(Codec.subsys_nftables(), nft_msg_newrule()),
      flags: base_flags,
      payload: payload
    }
  end

  defp maybe_add_position(attrs, nil), do: attrs

  defp maybe_add_position(attrs, :append), do: attrs

  defp maybe_add_position(attrs, {:after, handle}) when is_integer(handle) and handle > 0 do
    attrs ++ [{nfta_rule_position(), Wire.u64_be(handle)}]
  end

  # NFTA_RULE_USERDATA is a binary slot. Linx packs a libnftnl-style
  # TLV stream into it so tag + comment round-trip across pull.
  #
  # libnftnl reserves UDATA type 0 for the comment string. Linx uses
  # type 16 (NFTNL_UDATA_RULE_LINX_TAG) — high enough that it
  # doesn't collide with libnftnl's own extensions (libnftnl's
  # rule-userdata types end at NFTNL_UDATA_RULE_COMMENT_NL_TYPE
  # which is well below 16 in the current source).
  @udata_rule_comment 0
  @udata_rule_linx_tag 16

  defp encode_rule_userdata(nil, nil), do: <<>>

  defp encode_rule_userdata(tag, comment) do
    parts =
      []
      |> maybe_add_tlv(@udata_rule_linx_tag, tag, &Atom.to_string/1)
      |> maybe_add_tlv(@udata_rule_comment, comment, & &1)

    IO.iodata_to_binary(parts)
  end

  defp maybe_add_tlv(list, _type, nil, _to_string), do: list

  defp maybe_add_tlv(list, type, value, to_string) do
    str = to_string.(value)
    # NUL-terminate (libnftnl convention) and pack type:1 + len:1 + bytes.
    payload = str <> <<0>>
    list ++ [<<type::8, byte_size(payload)::8>>, payload]
  end

  @doc """
  Builds a `DELRULE` message — removes a single rule by its
  kernel-assigned handle.
  """
  @spec delete_rule(Table.family(), String.t(), String.t(), pos_integer()) :: Message.t()
  def delete_rule(family, table_name, chain_name, handle)
      when is_atom(family) and is_binary(table_name) and is_binary(chain_name) and
             is_integer(handle) and handle > 0 do
    attrs = [
      {nfta_rule_table(), [table_name, 0]},
      {nfta_rule_chain(), [chain_name, 0]},
      {nfta_rule_handle(), Wire.u64_be(handle)}
    ]

    %Message{
      type: Codec.nlmsg_type(Codec.subsys_nftables(), nft_msg_delrule()),
      flags: 0,
      payload: Codec.encode_nfgenmsg(family, 0) <> Attr.encode(attrs)
    }
  end

  @doc """
  Builds a `DELCHAIN` message — removes a chain by name.
  """
  @spec delete_chain(Table.family(), String.t(), String.t()) :: Message.t()
  def delete_chain(family, table_name, chain_name)
      when is_atom(family) and is_binary(table_name) and is_binary(chain_name) do
    attrs = [
      {nfta_chain_table(), [table_name, 0]},
      {nfta_chain_name(), [chain_name, 0]}
    ]

    %Message{
      type: Codec.nlmsg_type(Codec.subsys_nftables(), nft_msg_delchain()),
      flags: 0,
      payload: Codec.encode_nfgenmsg(family, 0) <> Attr.encode(attrs)
    }
  end

  # ===========================================================
  # Patch → messages
  # ===========================================================

  @doc """
  Encodes a `%Linx.Netfilter.Patch{}` into the ordered list of
  `%Message{}`s to send inside a single BATCH transaction.

  Sets need their NFTA_SET_ID generated per-batch; this function
  assigns ids in patch order so element-add ops can later
  reference them by name (the kernel resolves by name regardless,
  but libnftnl convention is to also send the id).
  """
  @spec from_patch(Patch.t()) :: [Message.t()]
  def from_patch(%Patch{ops: ops}) do
    Enum.flat_map(ops, &op_to_messages/1)
  end

  defp op_to_messages({:create_table, _family, %Table{} = t}) do
    [table(t)]
  end

  defp op_to_messages({:delete_table, family, name}) do
    [destroytable(family, name)]
  end

  defp op_to_messages({:create_chain, family, _table_name, %Chain{} = c}) do
    [chain(c, family)]
  end

  defp op_to_messages({:delete_chain, family, table_name, chain_name}) do
    [delete_chain(family, table_name, chain_name)]
  end

  defp op_to_messages({:create_set, family, %Set{} = s}) do
    [set(s, family)]
  end

  defp op_to_messages({:create_set, family, %NMap{} = m}) do
    [set(m, family)]
  end

  defp op_to_messages({:delete_set, family, table_name, set_name}) do
    [delete_set(family, table_name, set_name)]
  end

  # Element ops carry the parent set's declared types (and interval flag)
  # in their sixth position — the diff layer has the set struct in hand and
  # threads them through, so the encoder never has to guess.
  defp op_to_messages(
         {:add_set_elements, family, table_name, set_name, elements,
          {key_type, data_type, interval?}}
       ) do
    [
      set_elements_message(
        family,
        table_name,
        set_name,
        elements,
        key_type,
        data_type,
        interval?
      )
    ]
  end

  defp op_to_messages(
         {:delete_set_elements, family, table_name, set_name, elements,
          {key_type, data_type, interval?}}
       ) do
    [
      delete_set_elements(
        family,
        table_name,
        set_name,
        elements,
        key_type,
        data_type,
        interval?
      )
    ]
  end

  # Legacy 5-tuple element ops (hand-built patches). Without declared
  # types the encoder must infer from value shape — ambiguous for
  # integers (a low port such as 22 is indistinguishable from a protocol
  # number), so prefer the 6-tuple form above.
  defp op_to_messages({:add_set_elements, family, table_name, set_name, elements}) do
    {key_type, data_type} = infer_types(elements)

    [
      set_elements_message(family, table_name, set_name, elements, key_type, data_type, false)
    ]
  end

  defp op_to_messages({:delete_set_elements, family, table_name, set_name, elements}) do
    {key_type, data_type} = infer_types(elements)
    [delete_set_elements(family, table_name, set_name, elements, key_type, data_type, false)]
  end

  defp op_to_messages({:create_rule, family, table_name, chain_name, %Rule{} = r, position}) do
    [rule(r, family, table_name, chain_name, position: position)]
  end

  defp op_to_messages({:replace_rule, family, table_name, chain_name, handle, %Rule{} = r}) do
    [rule(r, family, table_name, chain_name, replace: true, handle: handle)]
  end

  defp op_to_messages({:delete_rule, family, table_name, chain_name, handle}) do
    [delete_rule(family, table_name, chain_name, handle)]
  end

  defp set_elements_message(
         family,
         table_name,
         set_name,
         elements,
         key_type,
         data_type,
         interval?
       ) do
    elements_bin = encode_set_elements(elements, key_type, data_type, interval?)

    attrs = [
      {nfta_set_elem_list_table(), [table_name, 0]},
      {nfta_set_elem_list_set(), [set_name, 0]},
      {nfta_set_elem_list_elements(), elements_bin}
    ]

    %Message{
      type: Codec.nlmsg_type(Codec.subsys_nftables(), nft_msg_newsetelem()),
      flags: nlm_f_create(),
      payload: Codec.encode_nfgenmsg(family, 0) <> Attr.encode(attrs)
    }
  end

  # Best-effort type inference for set elements when the patch op
  # only carries raw values (without the parent set's declared
  # type). Works for the common cases; explicit type passing will
  # be added when the patch encoding needs it.
  defp infer_types([{k, %Verdict{}} | _]), do: {infer_key_type(k), :verdict}
  defp infer_types([{k, v} | _]), do: {infer_key_type(k), infer_key_type(v)}
  defp infer_types([k | _]), do: {infer_key_type(k), nil}
  defp infer_types([]), do: {:inet_service, nil}

  defp infer_key_type(b) when is_binary(b) and byte_size(b) == 4, do: :ipv4_addr
  defp infer_key_type(b) when is_binary(b) and byte_size(b) == 16, do: :ipv6_addr
  defp infer_key_type({_, _, _, _}), do: :ipv4_addr
  defp infer_key_type({_, _, _, _, _, _, _, _}), do: :ipv6_addr
  defp infer_key_type({_, _, _, _, _, _}), do: :ether_addr
  defp infer_key_type(n) when is_integer(n) and n < 256, do: :inet_proto
  defp infer_key_type(n) when is_integer(n), do: :inet_service
  defp infer_key_type(s) when is_binary(s), do: :ifname

  # ===========================================================
  # Expressions
  # ===========================================================

  defp encode_expressions(expressions) when is_list(expressions) do
    expressions
    |> Enum.map(&encode_expression_elem/1)
    |> Attr.encode()
  end

  defp encode_expression_elem(%Expr{name: name, data: data}) do
    inner =
      [
        {nfta_expr_name(), [Atom.to_string(name), 0]},
        {nfta_expr_data(), Attr.encode(encode_expr_data(name, data))}
      ]

    {nfta_list_elem(), Attr.encode(inner)}
  end

  # A single nested expression (NFTA_DYNSET_EXPR and friends) —
  # same NFTA_EXPR_NAME/DATA shape, without the LIST_ELEM wrapper.
  defp encode_nested_expr(%Expr{name: name, data: data}) do
    Attr.encode([
      {nfta_expr_name(), [Atom.to_string(name), 0]},
      {nfta_expr_data(), Attr.encode(encode_expr_data(name, data))}
    ])
  end

  # immediate-verdict (or constant-into-register)
  defp encode_expr_data(:immediate, %Verdict{} = v) do
    [
      {nfta_immediate_dreg(), Wire.u32_be(0)},
      {nfta_immediate_data(), Attr.encode(encode_data_verdict(v))}
    ]
  end

  defp encode_expr_data(:immediate, %{value: %Verdict{} = v, dreg: dreg}) do
    [
      {nfta_immediate_dreg(), Wire.u32_be(dreg)},
      {nfta_immediate_data(), Attr.encode(encode_data_verdict(v))}
    ]
  end

  defp encode_expr_data(:immediate, %{value: bin, dreg: dreg}) when is_binary(bin) do
    [
      {nfta_immediate_dreg(), Wire.u32_be(dreg)},
      {nfta_immediate_data(), Attr.encode([{nfta_data_value(), bin}])}
    ]
  end

  defp encode_expr_data(:cmp, %{sreg: sreg, op: op, value: bin}) do
    [
      {nfta_cmp_sreg(), Wire.u32_be(sreg)},
      {nfta_cmp_op(), Wire.u32_be(Wire.cmp_op_int(op))},
      {nfta_cmp_data(), Attr.encode([{nfta_data_value(), bin}])}
    ]
  end

  defp encode_expr_data(:payload, %{base: base, offset: offset, len: len, dreg: dreg}) do
    [
      {nfta_payload_dreg(), Wire.u32_be(dreg)},
      {nfta_payload_base(), Wire.u32_be(Wire.payload_base_int(base))},
      {nfta_payload_offset(), Wire.u32_be(offset)},
      {nfta_payload_len(), Wire.u32_be(len)}
    ]
  end

  defp encode_expr_data(:meta, %{key: key, dreg: dreg}) do
    [
      {nfta_meta_dreg(), Wire.u32_be(dreg)},
      {nfta_meta_key(), Wire.u32_be(Wire.meta_key_int(key))}
    ]
  end

  defp encode_expr_data(:bitwise, %{sreg: sreg, dreg: dreg, len: len, mask: mask, xor: xor}) do
    [
      {nfta_bitwise_sreg(), Wire.u32_be(sreg)},
      {nfta_bitwise_dreg(), Wire.u32_be(dreg)},
      {nfta_bitwise_len(), Wire.u32_be(len)},
      {nfta_bitwise_mask(), Attr.encode([{nfta_data_value(), mask}])},
      {nfta_bitwise_xor(), Attr.encode([{nfta_data_value(), xor}])}
    ]
  end

  defp encode_expr_data(:ct, %{key: key, dreg: dreg}) do
    [
      {nfta_ct_dreg(), Wire.u32_be(dreg)},
      {nfta_ct_key(), Wire.u32_be(Wire.ct_key_int(key))}
    ]
  end

  defp encode_expr_data(:lookup, %{set: set_name, sreg: sreg, dreg: dreg, flags: flags}) do
    attrs =
      [
        {nfta_lookup_set(), [set_name, 0]},
        {nfta_lookup_sreg(), Wire.u32_be(sreg)}
      ]
      |> maybe_add(not is_nil(dreg), fn ->
        {nfta_lookup_dreg(), Wire.u32_be(dreg)}
      end)
      |> maybe_add(Wire.lookup_flags_int(flags) != 0, fn ->
        {nfta_lookup_flags(), Wire.u32_be(Wire.lookup_flags_int(flags))}
      end)

    attrs
  end

  defp encode_expr_data(:reject, %{type: type, code: code}) do
    # ICMP / ICMPX reject types REQUIRE the code attribute — the
    # kernel returns EINVAL without it. Default to NFT_REJECT_ICMPX_PORT_UNREACH
    # (3), matching `nft add rule ... reject` with no explicit code.
    effective_code = code || default_reject_code(type)

    [
      {nfta_reject_type(), Wire.u32_be(Wire.reject_type_int(type))}
    ]
    |> maybe_add(not is_nil(effective_code), fn ->
      {nfta_reject_icmp_code(), <<effective_code::8>>}
    end)
  end

  defp encode_expr_data(:dynset, %{set: set, op: op, sreg_key: sreg_key} = data) do
    op_int =
      case op do
        :add -> nft_dynset_op_add()
        :update -> nft_dynset_op_update()
        :delete -> nft_dynset_op_delete()
      end

    timeout = Map.get(data, :timeout)
    exprs = Map.get(data, :exprs, [])

    base = [
      {nfta_dynset_set_name(), [set, 0]},
      {nfta_dynset_op(), Wire.u32_be(op_int)},
      {nfta_dynset_sreg_key(), Wire.u32_be(sreg_key)}
    ]

    base
    |> maybe_add(not is_nil(timeout), fn ->
      {nfta_dynset_timeout(), Wire.u64_be(timeout)}
    end)
    |> Kernel.++(
      case exprs do
        [] ->
          []

        [single] ->
          [{nfta_dynset_expr(), encode_nested_expr(single)}]

        many ->
          [{nfta_dynset_expressions(), Attr.encode(Enum.map(many, &encode_expression_elem/1))}]
      end
    )
  end

  defp encode_expr_data(:objref, %{name: name, kind: kind}) do
    [
      {nfta_objref_imm_type(), Wire.u32_be(object_kind_int(kind))},
      {nfta_objref_imm_name(), [name, 0]}
    ]
  end

  defp encode_expr_data(:limit, %{rate: rate, per: per, burst: burst, type: type, over: over}) do
    type_int =
      case type do
        :packets -> nft_limit_pkts()
        :bytes -> nft_limit_pkt_bytes()
      end

    [
      {nfta_limit_rate(), Wire.u64_be(rate)},
      {nfta_limit_unit(), Wire.u64_be(per)},
      {nfta_limit_burst(), Wire.u32_be(burst)},
      {nfta_limit_type(), Wire.u32_be(type_int)}
    ]
    |> maybe_add(over, fn ->
      {nfta_limit_flags(), Wire.u32_be(nft_limit_f_inv())}
    end)
  end

  defp encode_expr_data(:counter, %{packets: packets, bytes: bytes}) do
    [
      {nfta_counter_bytes(), Wire.u64_be(bytes)},
      {nfta_counter_packets(), Wire.u64_be(packets)}
    ]
  end

  defp encode_expr_data(:nat, %{
         type: type,
         family: family,
         reg_addr_min: reg_addr_min,
         reg_addr_max: reg_addr_max,
         reg_proto_min: reg_proto_min,
         reg_proto_max: reg_proto_max,
         flags: flags
       }) do
    type_int =
      case type do
        :snat -> nft_nat_snat()
        :dnat -> nft_nat_dnat()
      end

    family_int = Wire.family_num(family)

    # Auto-set the convention flags: MAP_IPS when address regs are
    # set, PROTO_SPECIFIED when port regs are set. The kernel
    # actually decides what to remap based on which REG attrs are
    # present, but libnftnl always sets these flags too — so we
    # match for compatibility.
    auto_flags =
      flags
      |> maybe_append(reg_addr_min != nil, :map_ips)
      |> maybe_append(reg_proto_min != nil, :proto_specified)

    flags_int = Wire.nat_flags_int(auto_flags)

    [
      {nfta_nat_type(), Wire.u32_be(type_int)},
      {nfta_nat_family(), Wire.u32_be(family_int)}
    ]
    |> maybe_add(not is_nil(reg_addr_min), fn ->
      {nfta_nat_reg_addr_min(), Wire.u32_be(reg_addr_min)}
    end)
    |> maybe_add(not is_nil(reg_addr_max), fn ->
      {nfta_nat_reg_addr_max(), Wire.u32_be(reg_addr_max)}
    end)
    |> maybe_add(not is_nil(reg_proto_min), fn ->
      {nfta_nat_reg_proto_min(), Wire.u32_be(reg_proto_min)}
    end)
    |> maybe_add(not is_nil(reg_proto_max), fn ->
      {nfta_nat_reg_proto_max(), Wire.u32_be(reg_proto_max)}
    end)
    |> maybe_add(flags_int != 0, fn ->
      {nfta_nat_flags(), Wire.u32_be(flags_int)}
    end)
  end

  defp encode_expr_data(:masq, %{
         flags: flags,
         reg_proto_min: reg_proto_min,
         reg_proto_max: reg_proto_max
       }) do
    auto_flags = maybe_append(flags, reg_proto_min != nil, :proto_specified)
    flags_int = Wire.nat_flags_int(auto_flags)

    []
    |> maybe_add(flags_int != 0, fn ->
      {nfta_masq_flags(), Wire.u32_be(flags_int)}
    end)
    |> maybe_add(not is_nil(reg_proto_min), fn ->
      {nfta_masq_reg_proto_min(), Wire.u32_be(reg_proto_min)}
    end)
    |> maybe_add(not is_nil(reg_proto_max), fn ->
      {nfta_masq_reg_proto_max(), Wire.u32_be(reg_proto_max)}
    end)
  end

  defp encode_expr_data(:log, %{
         group: group,
         prefix: prefix,
         snaplen: snaplen,
         qthreshold: qthreshold,
         flags: flags
       }) do
    []
    |> maybe_add(not is_nil(group), fn ->
      {nfta_log_group(), <<group::big-unsigned-16>>}
    end)
    |> maybe_add(not is_nil(prefix), fn ->
      {nfta_log_prefix(), [prefix, 0]}
    end)
    |> maybe_add(not is_nil(snaplen), fn ->
      {nfta_log_snaplen(), Wire.u32_be(snaplen)}
    end)
    |> maybe_add(not is_nil(qthreshold), fn ->
      {nfta_log_qthreshold(), <<qthreshold::big-unsigned-16>>}
    end)
    |> maybe_add(flags != [] and flags != nil, fn ->
      {nfta_log_flags(), Wire.u32_be(encode_log_flags(flags))}
    end)
  end

  defp encode_expr_data(:redir, %{
         flags: flags,
         reg_proto_min: reg_proto_min,
         reg_proto_max: reg_proto_max
       }) do
    auto_flags = maybe_append(flags, reg_proto_min != nil, :proto_specified)
    flags_int = Wire.nat_flags_int(auto_flags)

    []
    |> maybe_add(not is_nil(reg_proto_min), fn ->
      {nfta_redir_reg_proto_min(), Wire.u32_be(reg_proto_min)}
    end)
    |> maybe_add(not is_nil(reg_proto_max), fn ->
      {nfta_redir_reg_proto_max(), Wire.u32_be(reg_proto_max)}
    end)
    |> maybe_add(flags_int != 0, fn ->
      {nfta_redir_flags(), Wire.u32_be(flags_int)}
    end)
  end

  # Unknown expression — emit empty data; kernel will reject.
  defp encode_expr_data(_name, _data), do: []

  defp encode_log_flags(flags) do
    import Bitwise

    Enum.reduce(flags, 0, fn
      :tcp_seq, acc -> acc ||| 0x01
      :tcp_opt, acc -> acc ||| 0x02
      :ip_opt, acc -> acc ||| 0x04
      :uid, acc -> acc ||| 0x08
      :macdecode, acc -> acc ||| 0x20
      _, acc -> acc
    end)
  end

  defp maybe_append(list, true, item), do: list ++ [item]
  defp maybe_append(list, false, _item), do: list

  defp default_reject_code(:tcp_reset), do: nil
  defp default_reject_code(_), do: 3

  defp encode_data_verdict(%Verdict{kind: kind, target: target}) do
    code_int = Wire.verdict_code(kind)

    # NF_QUEUE carries its queue number in the high 16 bits of the
    # verdict code (the kernel's NF_QUEUE_NR(n) = (n << 16) | NF_QUEUE);
    # a bare NF_QUEUE silently queues to 0.
    code_int =
      case {kind, target} do
        {:queue, num} when is_integer(num) -> num <<< 16 ||| code_int
        _ -> code_int
      end

    inner =
      [{nfta_verdict_code(), Wire.s32_be(code_int)}]
      |> maybe_add(kind in [:jump, :goto] and is_binary(target), fn ->
        {nfta_verdict_chain(), [target, 0]}
      end)

    [{nfta_data_verdict(), Attr.encode(inner)}]
  end

  # ===========================================================
  # Helpers
  # ===========================================================

  defp maybe_add(attrs, true, fun), do: attrs ++ [fun.()]
  defp maybe_add(attrs, false, _fun), do: attrs
end
