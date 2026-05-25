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

  N2 covers tables and (Encoder.table/1 plus the wiring for
  `Linx.Netfilter.create_table/3`). Chains, rules and expressions
  arrive in N2's later passes.

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

  alias Linx.Netfilter.{Chain, Expr, Rule, Table, Verdict, Wire}
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

  Sets / maps / objects / flowtables are not yet emitted (their
  encoders land with N4 — set elements need their own message
  type). The batch shape supports them by interleaving in step 3,
  but for N2 they're skipped.

  This list is intended to drop straight into
  `Linx.Netlink.Nfnl.batch/2`; it does not include the
  `BATCH_BEGIN` / `BATCH_END` envelope (that's `batch/2`'s job).
  """
  @spec to_batch(Linx.Netfilter.Ruleset.t(), keyword()) :: [Message.t()]
  def to_batch(%Linx.Netfilter.Ruleset{} = ruleset, _opts \\ []) do
    Enum.flat_map(ruleset.tables, fn {{family, _name}, %Table{} = table} ->
      [destroytable(family, table.name), table(table)] ++
        Enum.map(table.chains, fn {_, %Chain{} = chain} -> chain(chain, family) end) ++
        Enum.flat_map(table.chains, fn {_, %Chain{} = chain} ->
          Enum.map(chain.rules, fn %Rule{} = rule ->
            rule(rule, family, table.name, chain.name)
          end)
        end)
    end)
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

  Comment / tag round-trip via `NFTA_RULE_USERDATA` lands with
  N5 (`:reconcile` mode needs it). For N2 we encode just enough
  for the rule to function.
  """
  @spec rule(Rule.t(), Table.family(), String.t(), String.t(), keyword()) :: Message.t()
  def rule(%Rule{} = rule, family, table_name, chain_name, opts \\ []) do
    excl? = Keyword.get(opts, :excl, false)
    create? = Keyword.get(opts, :create, true)

    expressions_bin = encode_expressions(rule.expressions)

    attrs =
      [
        {nfta_rule_table(), [table_name, 0]},
        {nfta_rule_chain(), [chain_name, 0]},
        {nfta_rule_expressions(), expressions_bin}
      ]

    payload = Codec.encode_nfgenmsg(family, 0) <> Attr.encode(attrs)

    base_flags = 0
    base_flags = if create?, do: base_flags ||| nlm_f_create(), else: base_flags
    base_flags = if excl?, do: base_flags ||| nlm_f_excl(), else: base_flags
    # NLM_F_APPEND ensures the rule is appended (the kernel's
    # default with NEWRULE-without-position is to prepend).
    base_flags = base_flags ||| nlm_f_append()

    %Message{
      type: Codec.nlmsg_type(Codec.subsys_nftables(), nft_msg_newrule()),
      flags: base_flags,
      payload: payload
    }
  end

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
      {nfta_immediate_data(),
       Attr.encode([{nfta_data_value(), bin}])}
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

  defp encode_expr_data(:counter, %{packets: packets, bytes: bytes}) do
    [
      {nfta_counter_bytes(), Wire.u64_be(bytes)},
      {nfta_counter_packets(), Wire.u64_be(packets)}
    ]
  end

  # Unknown expression — emit empty data; kernel will reject.
  defp encode_expr_data(_name, _data), do: []

  defp default_reject_code(:tcp_reset), do: nil
  defp default_reject_code(_), do: 3

  defp encode_data_verdict(%Verdict{kind: kind, target: target}) do
    code_int = Wire.verdict_code(kind)

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
