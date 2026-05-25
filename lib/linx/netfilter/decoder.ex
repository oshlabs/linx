defmodule Linx.Netfilter.Decoder do
  @moduledoc """
  Converts kernel-side `%Linx.Netlink.Message{}` payloads back into
  `%Linx.Netfilter.*{}` value structs.

  The shape mirrors `Linx.Netfilter.Encoder` — one decode function
  per entity. `from_msgs/3` groups a stream of decoded entities
  into a `%Ruleset{}` (N2's later passes).

  N2 first cut: tables only. Chains / rules / expressions land in
  N2's later passes as their encoders land.

  ## Wire format quirks

  Same as `Linx.Netfilter.Encoder`: nftables NLA_U32 / NLA_U64 are
  **big-endian**, attribute IDs are namespaced.
  """

  import Linx.Netfilter.Wire

  alias Linx.Netfilter.{Chain, Expr, Rule, Ruleset, Table, Verdict, Wire}
  alias Linx.Netlink.Attr
  alias Linx.Netlink.Nfnl.Codec

  # ===========================================================
  # Tables
  # ===========================================================

  @doc """
  Decodes a `NEWTABLE` message body into a `%Linx.Netfilter.Table{}`.

  `body` is `%Message{payload: body}`'s payload — `nfgenmsg` header
  followed by NLAs.
  """
  @spec table(binary()) :: Table.t()
  def table(body) when is_binary(body) do
    {family_int, _ver, _res_id, attrs_bin} = Codec.decode_nfgenmsg(body)
    attrs = Attr.decode(attrs_bin)
    family = Wire.family_atom(family_int)

    name = get_string(attrs, nfta_table_name())
    flags_int = get_u32_be(attrs, nfta_table_flags(), 0)
    use_count = get_u32_be(attrs, nfta_table_use(), nil)
    handle = get_u64_be(attrs, nfta_table_handle(), nil)
    userdata = get_binary(attrs, nfta_table_userdata())

    %Table{
      family: family,
      name: name,
      flags: Wire.table_flags_atoms(flags_int),
      use_count: use_count,
      handle: handle,
      # N2's chain/set/object/flowtable decoders attach these by
      # name later when the full ruleset is assembled.
      chains: %{},
      sets: %{},
      maps: %{},
      objects: %{},
      flowtables: %{}
    }
    |> maybe_attach_userdata(userdata)
  end

  # ===========================================================
  # Chains
  # ===========================================================

  @doc """
  Decodes a `NEWCHAIN` message body into a `%Linx.Netfilter.Chain{}`.

  The chain's `:family` comes from the nfgenmsg header in the same
  message; it isn't stored on the Chain struct (it lives on the
  enclosing Table) but is needed here to map the wire hook number
  back to the family-specific hook atom.

  Returns `{family, chain}` so the caller (typically `from_msgs/3`)
  can attach the chain to the right table.
  """
  @spec chain(binary()) :: {Table.family(), Chain.t()}
  def chain(body) when is_binary(body) do
    {family_int, _ver, _res_id, attrs_bin} = Codec.decode_nfgenmsg(body)
    attrs = Attr.decode(attrs_bin)
    family = Wire.family_atom(family_int)

    name = get_string(attrs, nfta_chain_name())
    table = get_string(attrs, nfta_chain_table())
    type_str = get_string(attrs, nfta_chain_type())
    type = if type_str, do: Wire.chain_type_atom(type_str), else: nil
    policy_int = get_u32_be(attrs, nfta_chain_policy(), nil)
    policy = if policy_int, do: Wire.policy_atom(policy_int), else: nil
    flags_int = get_u32_be(attrs, nfta_chain_flags(), 0)
    handle = get_u64_be(attrs, nfta_chain_handle(), nil)

    {hook, priority, device} = decode_hook_attrs(attrs, family)

    chain =
      %Chain{
        name: name,
        table: table,
        type: type,
        hook: hook,
        priority: priority,
        policy: policy,
        device: device,
        flags: Wire.chain_flags_atoms(flags_int),
        handle: handle,
        rules: []
      }

    {family, chain}
  end

  defp decode_hook_attrs(attrs, family) do
    case List.keyfind(attrs, nfta_chain_hook(), 0) do
      {_, hook_bin} ->
        hook_attrs = Attr.decode(hook_bin)
        hooknum = get_u32_be(hook_attrs, nfta_hook_hooknum(), nil)
        priority = get_s32_be(hook_attrs, nfta_hook_priority(), nil)
        device = get_string(hook_attrs, nfta_hook_dev())
        hook = if hooknum, do: Wire.hook_atom(family, hooknum), else: nil
        {hook, priority, device}

      nil ->
        {nil, nil, nil}
    end
  end

  # ===========================================================
  # Rules
  # ===========================================================

  @doc """
  Decodes a `NEWRULE` message body into a `%Linx.Netfilter.Rule{}`.

  Returns `{family, table_name, chain_name, rule}` so the caller
  can attach to the right table+chain.
  """
  @spec rule(binary()) :: {Table.family(), String.t(), String.t(), Rule.t()}
  def rule(body) when is_binary(body) do
    {family_int, _ver, _res_id, attrs_bin} = Codec.decode_nfgenmsg(body)
    family = Wire.family_atom(family_int)
    attrs = Attr.decode(attrs_bin)

    table_name = get_string(attrs, nfta_rule_table())
    chain_name = get_string(attrs, nfta_rule_chain())
    handle = get_u64_be(attrs, nfta_rule_handle(), nil)

    expressions =
      case List.keyfind(attrs, nfta_rule_expressions(), 0) do
        {_, list_bin} -> decode_expressions(list_bin)
        nil -> []
      end

    rule = %Rule{
      expressions: expressions,
      chain: chain_name,
      handle: handle,
      tag: nil,
      comment: nil
    }

    {family, table_name, chain_name, rule}
  end

  defp decode_expressions(binary) do
    binary
    |> Attr.decode()
    |> Enum.flat_map(fn
      {tag, payload} when tag == nfta_list_elem() -> [decode_expression(payload)]
      _ -> []
    end)
  end

  defp decode_expression(elem_bin) do
    attrs = Attr.decode(elem_bin)
    name_str = get_string(attrs, nfta_expr_name())
    data_bin = get_binary(attrs, nfta_expr_data())
    name_atom = expr_name_atom(name_str)

    %Expr{
      name: name_atom,
      data: decode_expr_data(name_atom, data_bin)
    }
  end

  defp expr_name_atom("immediate"), do: :immediate
  defp expr_name_atom("cmp"), do: :cmp
  defp expr_name_atom("payload"), do: :payload
  defp expr_name_atom("meta"), do: :meta
  defp expr_name_atom("bitwise"), do: :bitwise
  defp expr_name_atom("ct"), do: :ct
  defp expr_name_atom("lookup"), do: :lookup
  defp expr_name_atom("reject"), do: :reject
  defp expr_name_atom("counter"), do: :counter
  defp expr_name_atom("nat"), do: :nat
  defp expr_name_atom("masq"), do: :masq
  defp expr_name_atom("redir"), do: :redir
  defp expr_name_atom(other) when is_binary(other), do: other

  defp decode_expr_data(_name, nil), do: nil

  defp decode_expr_data(:immediate, bin) do
    attrs = Attr.decode(bin)
    dreg = get_u32_be(attrs, nfta_immediate_dreg(), 0)
    data_bin = get_binary(attrs, nfta_immediate_data())

    case decode_immediate_data(data_bin) do
      %Verdict{} = v ->
        if dreg == 0, do: v, else: %{dreg: dreg, value: v}

      other ->
        %{dreg: dreg, value: other}
    end
  end

  defp decode_expr_data(:cmp, bin) do
    attrs = Attr.decode(bin)
    sreg = get_u32_be(attrs, nfta_cmp_sreg(), 1)
    op_int = get_u32_be(attrs, nfta_cmp_op(), 0)
    op = Wire.cmp_op_atom(op_int)
    data_bin = get_binary(attrs, nfta_cmp_data())
    value = decode_data_value(data_bin)
    %{sreg: sreg, op: op, value: value}
  end

  defp decode_expr_data(:payload, bin) do
    attrs = Attr.decode(bin)
    dreg = get_u32_be(attrs, nfta_payload_dreg(), 1)
    base_int = get_u32_be(attrs, nfta_payload_base(), 0)
    base = Wire.payload_base_atom(base_int)
    offset = get_u32_be(attrs, nfta_payload_offset(), 0)
    len = get_u32_be(attrs, nfta_payload_len(), 0)
    %{base: base, offset: offset, len: len, dreg: dreg}
  end

  defp decode_expr_data(:meta, bin) do
    attrs = Attr.decode(bin)
    dreg = get_u32_be(attrs, nfta_meta_dreg(), 1)
    key_int = get_u32_be(attrs, nfta_meta_key(), 0)
    %{key: Wire.meta_key_atom(key_int), dreg: dreg}
  end

  defp decode_expr_data(:bitwise, bin) do
    attrs = Attr.decode(bin)
    sreg = get_u32_be(attrs, nfta_bitwise_sreg(), 1)
    dreg = get_u32_be(attrs, nfta_bitwise_dreg(), 1)
    len = get_u32_be(attrs, nfta_bitwise_len(), 0)
    mask = decode_data_value(get_binary(attrs, nfta_bitwise_mask())) || <<>>
    xor = decode_data_value(get_binary(attrs, nfta_bitwise_xor())) || <<>>
    %{sreg: sreg, dreg: dreg, len: len, mask: mask, xor: xor}
  end

  defp decode_expr_data(:ct, bin) do
    attrs = Attr.decode(bin)
    dreg = get_u32_be(attrs, nfta_ct_dreg(), 1)
    key_int = get_u32_be(attrs, nfta_ct_key(), 0)
    %{key: Wire.ct_key_atom(key_int), dreg: dreg}
  end

  defp decode_expr_data(:lookup, bin) do
    attrs = Attr.decode(bin)

    %{
      set: get_string(attrs, nfta_lookup_set()),
      sreg: get_u32_be(attrs, nfta_lookup_sreg(), 1),
      dreg: get_u32_be(attrs, nfta_lookup_dreg(), nil),
      flags: decode_lookup_flags(get_u32_be(attrs, nfta_lookup_flags(), 0))
    }
  end

  defp decode_expr_data(:reject, bin) do
    attrs = Attr.decode(bin)
    type_int = get_u32_be(attrs, nfta_reject_type(), 0)
    code = get_u8(attrs, nfta_reject_icmp_code(), nil)
    %{type: Wire.reject_type_atom(type_int), code: code}
  end

  defp decode_expr_data(:counter, bin) do
    attrs = Attr.decode(bin)
    bytes = get_u64_be(attrs, nfta_counter_bytes(), 0)
    packets = get_u64_be(attrs, nfta_counter_packets(), 0)
    %{packets: packets, bytes: bytes}
  end

  defp decode_expr_data(:nat, bin) do
    attrs = Attr.decode(bin)
    type_int = get_u32_be(attrs, nfta_nat_type(), 0)
    family_int = get_u32_be(attrs, nfta_nat_family(), 0)
    flags_int = get_u32_be(attrs, nfta_nat_flags(), 0)

    type = if type_int == nft_nat_dnat(), do: :dnat, else: :snat

    %{
      type: type,
      family: Wire.family_atom(family_int),
      reg_addr_min: get_u32_be(attrs, nfta_nat_reg_addr_min(), nil),
      reg_addr_max: get_u32_be(attrs, nfta_nat_reg_addr_max(), nil),
      reg_proto_min: get_u32_be(attrs, nfta_nat_reg_proto_min(), nil),
      reg_proto_max: get_u32_be(attrs, nfta_nat_reg_proto_max(), nil),
      flags: Wire.nat_flags_atoms(flags_int)
    }
  end

  defp decode_expr_data(:masq, bin) do
    attrs = Attr.decode(bin)
    flags_int = get_u32_be(attrs, nfta_masq_flags(), 0)

    %{
      flags: Wire.nat_flags_atoms(flags_int),
      reg_proto_min: get_u32_be(attrs, nfta_masq_reg_proto_min(), nil),
      reg_proto_max: get_u32_be(attrs, nfta_masq_reg_proto_max(), nil)
    }
  end

  defp decode_expr_data(:redir, bin) do
    attrs = Attr.decode(bin)
    flags_int = get_u32_be(attrs, nfta_redir_flags(), 0)

    %{
      flags: Wire.nat_flags_atoms(flags_int),
      reg_proto_min: get_u32_be(attrs, nfta_redir_reg_proto_min(), nil),
      reg_proto_max: get_u32_be(attrs, nfta_redir_reg_proto_max(), nil)
    }
  end

  defp decode_expr_data(_name, bin), do: bin

  defp decode_immediate_data(nil), do: nil

  defp decode_immediate_data(bin) do
    attrs = Attr.decode(bin)

    case List.keyfind(attrs, nfta_data_verdict(), 0) do
      {_, verdict_bin} ->
        decode_verdict(verdict_bin)

      nil ->
        # Non-verdict value (e.g. constant load into a register)
        get_binary(attrs, nfta_data_value())
    end
  end

  defp decode_data_value(nil), do: nil

  defp decode_data_value(bin) do
    attrs = Attr.decode(bin)
    get_binary(attrs, nfta_data_value())
  end

  defp decode_verdict(bin) do
    attrs = Attr.decode(bin)
    code = get_s32_be(attrs, nfta_verdict_code(), 0)
    chain = get_string(attrs, nfta_verdict_chain())
    kind = Wire.verdict_atom(code)
    target = if kind in [:jump, :goto], do: chain, else: nil
    %Verdict{kind: kind, target: target}
  end

  defp decode_lookup_flags(0), do: []

  defp decode_lookup_flags(int) do
    import Bitwise
    if (int &&& 1) != 0, do: [:inv], else: []
  end

  # ===========================================================
  # Assembly
  # ===========================================================

  @doc """
  Builds a `%Ruleset{}` from separate lists of decoded table,
  chain, and rule entries.

    * `tables` — `[%Table{}]` from a `NFT_MSG_GETTABLE` dump.
    * `chains` — `[{family, %Chain{}}]` from a `NFT_MSG_GETCHAIN` dump.
    * `rules` — `[{family, table_name, chain_name, %Rule{}}]` from
      a `NFT_MSG_GETRULE` dump.

  Chains are attached to their table by `(family, table_name)`;
  rules are appended to their chain in the order received (which
  matches the kernel's traversal order — rule position is
  preserved on dump).

  Entities that reference a missing parent (e.g. a chain whose
  table isn't in `tables`) are silently dropped — this happens if
  the dumps weren't atomic and a table was created/destroyed
  between them.
  """
  @spec from_msgs([Table.t()], [{Table.family(), Chain.t()}], [
          {Table.family(), String.t(), String.t(), Rule.t()}
        ]) :: Ruleset.t()
  def from_msgs(tables, chains, rules) do
    tables_map =
      Enum.reduce(tables, %{}, fn %Table{family: f, name: n} = t, acc ->
        Map.put(acc, {f, n}, t)
      end)

    tables_map = attach_chains(tables_map, chains)
    tables_map = attach_rules(tables_map, rules)

    %Ruleset{tables: tables_map}
  end

  defp attach_chains(tables_map, chains) do
    Enum.reduce(chains, tables_map, fn {family, %Chain{} = chain}, acc ->
      key = {family, chain.table}

      case Map.fetch(acc, key) do
        {:ok, %Table{} = t} ->
          Map.put(acc, key, %Table{t | chains: Map.put(t.chains, chain.name, chain)})

        :error ->
          acc
      end
    end)
  end

  defp attach_rules(tables_map, rules) do
    Enum.reduce(rules, tables_map, fn {family, table_name, chain_name, %Rule{} = rule}, acc ->
      key = {family, table_name}

      with {:ok, %Table{} = t} <- Map.fetch(acc, key),
           {:ok, %Chain{} = c} <- Map.fetch(t.chains, chain_name) do
        updated_chain = %Chain{c | rules: c.rules ++ [rule]}
        updated_table = %Table{t | chains: Map.put(t.chains, chain_name, updated_chain)}
        Map.put(acc, key, updated_table)
      else
        _ -> acc
      end
    end)
  end

  # ===========================================================
  # Attribute lookup helpers
  # ===========================================================

  defp get_string(attrs, tag) do
    case List.keyfind(attrs, tag, 0) do
      {^tag, value} -> String.trim_trailing(value, <<0>>)
      nil -> nil
    end
  end

  defp get_binary(attrs, tag) do
    case List.keyfind(attrs, tag, 0) do
      {^tag, value} -> value
      nil -> nil
    end
  end

  defp get_u32_be(attrs, tag, default) do
    case List.keyfind(attrs, tag, 0) do
      {^tag, <<v::big-unsigned-32>>} -> v
      _ -> default
    end
  end

  defp get_u64_be(attrs, tag, default) do
    case List.keyfind(attrs, tag, 0) do
      {^tag, <<v::big-unsigned-64>>} -> v
      _ -> default
    end
  end

  defp get_s32_be(attrs, tag, default) do
    case List.keyfind(attrs, tag, 0) do
      {^tag, <<v::big-signed-32>>} -> v
      _ -> default
    end
  end

  defp get_u8(attrs, tag, default) do
    case List.keyfind(attrs, tag, 0) do
      {^tag, <<v::unsigned-8>>} -> v
      _ -> default
    end
  end

  # Userdata is opaque on the wire; the Table struct doesn't have a
  # dedicated slot for it yet (N2 ships table userdata round-trip
  # only when N5's :reconcile needs it). For now, silently swallow.
  defp maybe_attach_userdata(table, nil), do: table
  defp maybe_attach_userdata(table, _bin), do: table
end
