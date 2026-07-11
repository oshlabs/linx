defmodule Linx.Netfilter.Wire do
  @moduledoc """
  Kernel-side numeric constants for `Linx.Netfilter`'s wire codec —
  message opcodes, attribute IDs, hook numbers, flag bitmasks,
  named priorities.

  All values come from `include/uapi/linux/netfilter/nf_tables.h` and
  `include/uapi/linux/netfilter.h`. Kept in one module so the
  Encoder/Decoder can `import Linx.Netfilter.Wire` and use them by
  name without a long alias chain.

  ## Byte order

  nftables uses **big-endian** on the wire for its `NLA_U16` /
  `NLA_U32` / `NLA_U64` integers — opposite to rtnetlink (which uses
  native byte order). The helpers `u32_be/1` and `u64_be/1` here
  produce the right payload form; `u32_be!/1` / `u64_be!/1` decode.
  String / binary attributes are byte-order agnostic.

  ## References

    * [`include/uapi/linux/netfilter/nf_tables.h`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/netfilter/nf_tables.h)
    * [`include/uapi/linux/netfilter.h`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/netfilter.h)
  """

  # ===========================================================
  # NFT_MSG_* — nf_tables operation opcodes (low byte of nlmsghdr.type)
  # ===========================================================

  # The dense block of NEW/GET/DEL triples, from `enum nf_tables_msg_types`:
  defmacro nft_msg_newtable, do: 0
  defmacro nft_msg_gettable, do: 1
  defmacro nft_msg_deltable, do: 2
  defmacro nft_msg_newchain, do: 3
  defmacro nft_msg_getchain, do: 4
  defmacro nft_msg_delchain, do: 5
  defmacro nft_msg_newrule, do: 6
  defmacro nft_msg_getrule, do: 7
  defmacro nft_msg_delrule, do: 8
  defmacro nft_msg_newset, do: 9
  defmacro nft_msg_getset, do: 10
  defmacro nft_msg_delset, do: 11
  defmacro nft_msg_newsetelem, do: 12
  defmacro nft_msg_getsetelem, do: 13
  defmacro nft_msg_delsetelem, do: 14
  defmacro nft_msg_newgen, do: 15
  defmacro nft_msg_getgen, do: 16
  defmacro nft_msg_trace, do: 17
  defmacro nft_msg_newobj, do: 18
  defmacro nft_msg_getobj, do: 19
  defmacro nft_msg_delobj, do: 20
  defmacro nft_msg_getobj_reset, do: 21
  defmacro nft_msg_newflowtable, do: 22
  defmacro nft_msg_getflowtable, do: 23
  defmacro nft_msg_delflowtable, do: 24
  defmacro nft_msg_getrule_reset, do: 25
  # DESTROY* — kernel 6.3+, "no error if missing" semantics.
  defmacro nft_msg_destroytable, do: 26
  defmacro nft_msg_destroychain, do: 27
  defmacro nft_msg_destroyrule, do: 28
  defmacro nft_msg_destroyset, do: 29
  defmacro nft_msg_destroysetelem, do: 30
  defmacro nft_msg_destroyobj, do: 31
  defmacro nft_msg_destroyflowtable, do: 32

  # ===========================================================
  # NFTA_TABLE_* — table attributes
  # ===========================================================

  defmacro nfta_table_name, do: 1
  defmacro nfta_table_flags, do: 2
  defmacro nfta_table_use, do: 3
  defmacro nfta_table_handle, do: 4
  defmacro nfta_table_pad, do: 5
  defmacro nfta_table_userdata, do: 6
  defmacro nfta_table_owner, do: 7

  # NFT_TABLE_F_* — table flag bitmask values.
  defmacro nft_table_f_dormant, do: 0x1
  defmacro nft_table_f_owner, do: 0x2
  defmacro nft_table_f_persist, do: 0x4

  # ===========================================================
  # NFTA_CHAIN_* — chain attributes
  # ===========================================================

  defmacro nfta_chain_table, do: 1
  defmacro nfta_chain_handle, do: 2
  defmacro nfta_chain_name, do: 3
  defmacro nfta_chain_hook, do: 4
  defmacro nfta_chain_policy, do: 5
  defmacro nfta_chain_use, do: 6
  defmacro nfta_chain_type, do: 7
  defmacro nfta_chain_counters, do: 8
  defmacro nfta_chain_pad, do: 9
  defmacro nfta_chain_flags, do: 10
  defmacro nfta_chain_id, do: 11
  defmacro nfta_chain_userdata, do: 12

  # NFT_CHAIN_F_* — chain flag bitmask values.
  defmacro nft_chain_f_base, do: 0x1
  defmacro nft_chain_f_hw_offload, do: 0x2
  defmacro nft_chain_f_binding, do: 0x4

  # ===========================================================
  # NFTA_HOOK_* — nested under NFTA_CHAIN_HOOK
  # ===========================================================

  defmacro nfta_hook_hooknum, do: 1
  defmacro nfta_hook_priority, do: 2
  defmacro nfta_hook_dev, do: 3
  defmacro nfta_hook_devs, do: 4

  # ===========================================================
  # NFTA_RULE_* — rule attributes
  # ===========================================================

  defmacro nfta_rule_table, do: 1
  defmacro nfta_rule_chain, do: 2
  defmacro nfta_rule_handle, do: 3
  defmacro nfta_rule_expressions, do: 4
  defmacro nfta_rule_compat, do: 5
  defmacro nfta_rule_position, do: 6
  defmacro nfta_rule_userdata, do: 7
  defmacro nfta_rule_pad, do: 8
  defmacro nfta_rule_id, do: 9
  defmacro nfta_rule_position_id, do: 10
  defmacro nfta_rule_chain_id, do: 11

  # ===========================================================
  # NFTA_LIST_* — generic list element wrapping
  # ===========================================================

  defmacro nfta_list_elem, do: 1

  # ===========================================================
  # NFTA_EXPR_* — expression header
  # ===========================================================

  defmacro nfta_expr_name, do: 1
  defmacro nfta_expr_data, do: 2

  # ===========================================================
  # NFTA_DATA_* — values carried in registers (NFTA_IMMEDIATE_DATA, etc.)
  # ===========================================================

  defmacro nfta_data_value, do: 1
  defmacro nfta_data_verdict, do: 2

  # ===========================================================
  # NFTA_VERDICT_* — nested under NFTA_DATA_VERDICT
  # ===========================================================

  defmacro nfta_verdict_code, do: 1
  defmacro nfta_verdict_chain, do: 2
  defmacro nfta_verdict_chain_id, do: 3

  # ===========================================================
  # Per-expression attribute sets
  # ===========================================================

  # NFTA_IMMEDIATE_*
  defmacro nfta_immediate_dreg, do: 1
  defmacro nfta_immediate_data, do: 2

  # NFTA_CMP_*
  defmacro nfta_cmp_sreg, do: 1
  defmacro nfta_cmp_op, do: 2
  defmacro nfta_cmp_data, do: 3

  # NFTA_PAYLOAD_*
  defmacro nfta_payload_dreg, do: 1
  defmacro nfta_payload_base, do: 2
  defmacro nfta_payload_offset, do: 3
  defmacro nfta_payload_len, do: 4
  defmacro nfta_payload_sreg, do: 5
  defmacro nfta_payload_csum_type, do: 6
  defmacro nfta_payload_csum_offset, do: 7
  defmacro nfta_payload_csum_flags, do: 8

  # NFTA_META_*
  defmacro nfta_meta_dreg, do: 1
  defmacro nfta_meta_key, do: 2
  defmacro nfta_meta_sreg, do: 3

  # NFTA_BITWISE_*
  defmacro nfta_bitwise_sreg, do: 1
  defmacro nfta_bitwise_dreg, do: 2
  defmacro nfta_bitwise_len, do: 3
  defmacro nfta_bitwise_mask, do: 4
  defmacro nfta_bitwise_xor, do: 5
  defmacro nfta_bitwise_op, do: 6
  defmacro nfta_bitwise_data, do: 7

  # NFTA_CT_*
  defmacro nfta_ct_dreg, do: 1
  defmacro nfta_ct_key, do: 2
  defmacro nfta_ct_direction, do: 3
  defmacro nfta_ct_sreg, do: 4

  # NFTA_LOOKUP_*
  defmacro nfta_lookup_set, do: 1
  defmacro nfta_lookup_sreg, do: 2
  defmacro nfta_lookup_dreg, do: 3
  defmacro nfta_lookup_flags, do: 4
  defmacro nfta_lookup_set_id, do: 5

  # NFTA_REJECT_*
  defmacro nfta_reject_type, do: 1
  defmacro nfta_reject_icmp_code, do: 2

  # NFTA_COUNTER_*
  defmacro nfta_counter_bytes, do: 1
  defmacro nfta_counter_packets, do: 2
  defmacro nfta_counter_pad, do: 3

  # NFTA_OBJ_* (named-object messages)
  defmacro nfta_obj_table, do: 1
  defmacro nfta_obj_name, do: 2
  defmacro nfta_obj_type, do: 3
  defmacro nfta_obj_data, do: 4
  defmacro nfta_obj_use, do: 5
  defmacro nfta_obj_handle, do: 6

  # NFTA_FLOWTABLE_* (flowtable messages)
  defmacro nfta_flowtable_table, do: 1
  defmacro nfta_flowtable_name, do: 2
  defmacro nfta_flowtable_hook, do: 3
  defmacro nfta_flowtable_use, do: 4
  defmacro nfta_flowtable_handle, do: 5
  defmacro nfta_flowtable_flags, do: 7

  # NFTA_FLOWTABLE_HOOK_* (nested under NFTA_FLOWTABLE_HOOK; note the
  # numbering differs from the chain-hook NFTA_HOOK_* set)
  defmacro nfta_flowtable_hook_num, do: 1
  defmacro nfta_flowtable_hook_priority, do: 2
  defmacro nfta_flowtable_hook_devs, do: 3

  # NFTA_DEVICE_* (device entries inside HOOK_DEVS)
  defmacro nfta_device_name, do: 1

  # NFT_FLOWTABLE_* flag bits
  defmacro nft_flowtable_hw_offload, do: 0x1
  defmacro nft_flowtable_counter, do: 0x2

  # NFTA_OBJREF_* (nft_objref expression)
  defmacro nfta_objref_imm_type, do: 1
  defmacro nfta_objref_imm_name, do: 2

  # NFT_OBJECT_* — named-object kinds
  defmacro nft_object_counter, do: 1
  defmacro nft_object_quota, do: 2
  defmacro nft_object_ct_helper, do: 3
  defmacro nft_object_limit, do: 4
  defmacro nft_object_connlimit, do: 5
  defmacro nft_object_ct_timeout, do: 7
  defmacro nft_object_secmark, do: 8
  defmacro nft_object_ct_expect, do: 9
  defmacro nft_object_synproxy, do: 10

  # NFTA_QUOTA_* (nft_quota expression / quota objects)
  defmacro nfta_quota_bytes, do: 1
  defmacro nfta_quota_flags, do: 2
  defmacro nfta_quota_consumed, do: 4

  # NFT_QUOTA_F_*
  defmacro nft_quota_f_inv, do: 1

  # NFTA_DYNSET_* (nft_dynset expression — runtime set updates)
  defmacro nfta_dynset_set_name, do: 1
  defmacro nfta_dynset_set_id, do: 2
  defmacro nfta_dynset_op, do: 3
  defmacro nfta_dynset_sreg_key, do: 4
  defmacro nfta_dynset_sreg_data, do: 5
  defmacro nfta_dynset_timeout, do: 6
  defmacro nfta_dynset_expr, do: 7
  defmacro nfta_dynset_flags, do: 9
  defmacro nfta_dynset_expressions, do: 10

  # NFT_DYNSET_OP_*
  defmacro nft_dynset_op_add, do: 0
  defmacro nft_dynset_op_update, do: 1
  defmacro nft_dynset_op_delete, do: 2

  # NFTA_LIMIT_* (nft_limit expression)
  defmacro nfta_limit_rate, do: 1
  defmacro nfta_limit_unit, do: 2
  defmacro nfta_limit_burst, do: 3
  defmacro nfta_limit_type, do: 4
  defmacro nfta_limit_flags, do: 5

  # NFT_LIMIT_* — limit type
  defmacro nft_limit_pkts, do: 0
  defmacro nft_limit_pkt_bytes, do: 1

  # NFT_LIMIT_F_*
  defmacro nft_limit_f_inv, do: 1

  # NFTA_NAT_* (nft_nat expression)
  defmacro nfta_nat_type, do: 1
  defmacro nfta_nat_family, do: 2
  defmacro nfta_nat_reg_addr_min, do: 3
  defmacro nfta_nat_reg_addr_max, do: 4
  defmacro nfta_nat_reg_proto_min, do: 5
  defmacro nfta_nat_reg_proto_max, do: 6
  defmacro nfta_nat_flags, do: 7

  # NFT_NAT_* — NAT direction
  defmacro nft_nat_snat, do: 0
  defmacro nft_nat_dnat, do: 1

  # NFTA_MASQ_* (nft_masq expression)
  defmacro nfta_masq_flags, do: 1
  defmacro nfta_masq_reg_proto_min, do: 2
  defmacro nfta_masq_reg_proto_max, do: 3

  # NFTA_REDIR_* (nft_redir expression)
  defmacro nfta_redir_reg_proto_min, do: 1
  defmacro nfta_redir_reg_proto_max, do: 2
  defmacro nfta_redir_flags, do: 3

  # NF_NAT_RANGE_* — flag bitmask for NAT/masquerade/redirect
  defmacro nf_nat_range_map_ips, do: 0x01
  defmacro nf_nat_range_proto_specified, do: 0x02
  defmacro nf_nat_range_proto_random, do: 0x04
  defmacro nf_nat_range_persistent, do: 0x08
  defmacro nf_nat_range_proto_random_fully, do: 0x10
  defmacro nf_nat_range_proto_offset, do: 0x20
  defmacro nf_nat_range_netmap, do: 0x40

  # NFTA_SET_* — set attributes (`enum nft_set_attributes`)
  defmacro nfta_set_table, do: 1
  defmacro nfta_set_name, do: 2
  defmacro nfta_set_flags, do: 3
  defmacro nfta_set_key_type, do: 4
  defmacro nfta_set_key_len, do: 5
  defmacro nfta_set_data_type, do: 6
  defmacro nfta_set_data_len, do: 7
  defmacro nfta_set_policy, do: 8
  defmacro nfta_set_desc, do: 9
  defmacro nfta_set_id, do: 10
  defmacro nfta_set_timeout, do: 11
  defmacro nfta_set_gc_interval, do: 12
  defmacro nfta_set_userdata, do: 13
  defmacro nfta_set_pad, do: 14
  defmacro nfta_set_obj_type, do: 15
  defmacro nfta_set_handle, do: 16
  defmacro nfta_set_expr, do: 17
  defmacro nfta_set_expressions, do: 18

  # NFT_SET_F_* — set flag bitmask values (`enum nft_set_flags`)
  defmacro nft_set_anonymous, do: 0x1
  defmacro nft_set_constant, do: 0x2
  defmacro nft_set_interval, do: 0x4
  defmacro nft_set_map, do: 0x8
  defmacro nft_set_timeout_flag, do: 0x10
  defmacro nft_set_eval, do: 0x20
  defmacro nft_set_object_flag, do: 0x40
  defmacro nft_set_concat, do: 0x80
  defmacro nft_set_expr_flag, do: 0x100

  # NFTA_SET_ELEM_* — set element attributes
  defmacro nfta_set_elem_key, do: 1
  defmacro nfta_set_elem_data, do: 2
  defmacro nfta_set_elem_flags, do: 3
  defmacro nfta_set_elem_timeout, do: 4
  defmacro nfta_set_elem_expiration, do: 5
  defmacro nfta_set_elem_userdata, do: 6
  defmacro nfta_set_elem_expr, do: 7
  defmacro nfta_set_elem_pad, do: 8
  defmacro nfta_set_elem_objref, do: 9
  defmacro nfta_set_elem_key_end, do: 10
  defmacro nfta_set_elem_expressions, do: 11

  # NFT_SET_ELEM_F_* — set element flag values
  defmacro nft_set_elem_interval_end, do: 0x1
  defmacro nft_set_elem_catchall, do: 0x2

  # NFTA_SET_ELEM_LIST_* — set element list attributes (NEWSETELEM body)
  defmacro nfta_set_elem_list_table, do: 1
  defmacro nfta_set_elem_list_set, do: 2
  defmacro nfta_set_elem_list_elements, do: 3
  defmacro nfta_set_elem_list_set_id, do: 4

  # NFTA_SET_DESC_* — set descriptor (size, concat fields)
  defmacro nfta_set_desc_size, do: 1
  defmacro nfta_set_desc_concat, do: 2

  # NFTA_SET_FIELD_* (inside NFTA_SET_DESC_CONCAT list elements)
  defmacro nfta_set_field_len, do: 1

  # ===========================================================
  # libnftnl key/data type IDs
  #
  # The kernel's NFTA_SET_KEY_TYPE / NFTA_SET_DATA_TYPE attributes
  # carry an integer that is opaque to the kernel itself — it's
  # interpreted by userspace (libnftnl / `nft list ruleset`) for
  # display purposes. The values come from libnftnl's data_reg.h.
  # ===========================================================

  defmacro nftnl_type_invalid, do: 0
  defmacro nftnl_type_verdict, do: 1
  defmacro nftnl_type_nf_proto, do: 2
  defmacro nftnl_type_bitmask, do: 3
  defmacro nftnl_type_integer, do: 4
  defmacro nftnl_type_string, do: 5
  defmacro nftnl_type_lladdr, do: 6
  defmacro nftnl_type_ipaddr, do: 7
  defmacro nftnl_type_ip6addr, do: 8
  defmacro nftnl_type_etheraddr, do: 9
  defmacro nftnl_type_ethertype, do: 10
  defmacro nftnl_type_inet_protocol, do: 12
  defmacro nftnl_type_inet_service, do: 13
  defmacro nftnl_type_mark, do: 19
  defmacro nftnl_type_ifname, do: 41

  @doc """
  Maps a Linx key-type atom to its `(libnftnl_type_id, byte_len)`
  pair for `NFTA_SET_KEY_TYPE` / `NFTA_SET_KEY_LEN`.
  """
  @spec set_type_info(atom() | {:concat, [atom()]}) :: {non_neg_integer(), pos_integer()}

  # Concatenated key: nft packs the subtype ids 6 bits each
  # (TYPE_BITS) into one type id, and each field's key bytes are
  # padded to the 4-byte register size — the total key length is
  # the sum of the padded field widths.
  def set_type_info({:concat, types}) when is_list(types) and types != [] do
    import Bitwise

    Enum.reduce(types, {0, 0}, fn t, {id, len} ->
      {tid, tlen} = set_type_info(t)
      {bor(bsl(id, 6), tid), len + pad4(tlen)}
    end)
  end

  def set_type_info(:ipv4_addr), do: {7, 4}
  def set_type_info(:ipv6_addr), do: {8, 16}
  def set_type_info(:ether_addr), do: {9, 6}
  def set_type_info(:inet_proto), do: {12, 1}
  def set_type_info(:inet_service), do: {13, 2}
  def set_type_info(:mark), do: {19, 4}
  def set_type_info(:ct_state), do: {26, 4}
  def set_type_info(:ifname), do: {41, 16}
  def set_type_info(:verdict), do: {1, 16}

  @doc """
  Inverse: maps a libnftnl type id + length back to a key-type
  atom — including packed concatenation ids (6 bits per field,
  the inverse of `set_type_info({:concat, _})`). Returns
  `{:unknown_type, id, len}` for unrecognised pairs.
  """
  @spec set_type_atom(non_neg_integer(), pos_integer()) ::
          atom() | {:concat, [atom()]} | tuple()
  def set_type_atom(7, 4), do: :ipv4_addr
  def set_type_atom(8, 16), do: :ipv6_addr
  def set_type_atom(9, 6), do: :ether_addr
  def set_type_atom(12, 1), do: :inet_proto
  def set_type_atom(13, 2), do: :inet_service
  def set_type_atom(19, 4), do: :mark
  def set_type_atom(26, 4), do: :ct_state
  def set_type_atom(41, 16), do: :ifname
  def set_type_atom(1, _), do: :verdict

  # A multi-field id (≥ 64 means more than one 6-bit chunk). Unpack the
  # chunks low-to-high — the low chunk is the LAST field — and accept
  # only if every chunk is a known single type and the padded field
  # widths sum to the declared key length.
  def set_type_atom(id, len) when id >= 64 do
    with {:ok, types} <- unpack_concat_ids(id, []),
         {_id, ^len} <- set_type_info({:concat, types}) do
      {:concat, types}
    else
      _ -> {:unknown_type, id, len}
    end
  end

  def set_type_atom(id, len), do: {:unknown_type, id, len}

  defp unpack_concat_ids(0, acc) when acc != [], do: {:ok, acc}

  defp unpack_concat_ids(id, acc) when id > 0 do
    import Bitwise

    case concat_subtype(band(id, 0x3F)) do
      nil -> :error
      atom -> unpack_concat_ids(bsr(id, 6), [atom | acc])
    end
  end

  defp unpack_concat_ids(_, _), do: :error

  defp concat_subtype(7), do: :ipv4_addr
  defp concat_subtype(8), do: :ipv6_addr
  defp concat_subtype(9), do: :ether_addr
  defp concat_subtype(12), do: :inet_proto
  defp concat_subtype(13), do: :inet_service
  defp concat_subtype(19), do: :mark
  defp concat_subtype(26), do: :ct_state
  defp concat_subtype(41), do: :ifname
  defp concat_subtype(_), do: nil

  @doc """
  The unpadded per-field byte lengths of a concatenated key type —
  what `NFTA_SET_DESC_CONCAT` carries so the kernel knows the
  field boundaries.
  """
  @spec concat_field_lens({:concat, [atom()]}) :: [pos_integer()]
  def concat_field_lens({:concat, types}) do
    Enum.map(types, fn t ->
      {_id, len} = set_type_info(t)
      len
    end)
  end

  defp pad4(n), do: div(n + 3, 4) * 4

  @doc """
  Maps a set-flags atom list to the u32 bitmask. The encoder may
  add `:map` / `:eval` automatically based on the set's
  `:data_type` / `:dynamic` shape.

  `:eval` is an accepted alias for `:dynamic` — both name the same
  kernel bit (`NFT_SET_EVAL`, `0x20`; the uapi header keeps the old
  `EVAL` name, the nft language calls it `dynamic`). Round-trips
  normalise to `:dynamic`: `set_flags_atoms/1` never emits `:eval`,
  so pull a set pushed with `:eval` and you'll read `:dynamic` back.
  """
  @spec set_flags_int([atom()]) :: non_neg_integer()
  def set_flags_int(flags) when is_list(flags) do
    import Bitwise

    Enum.reduce(flags, 0, fn
      :anonymous, acc -> acc ||| 0x1
      :constant, acc -> acc ||| 0x2
      :interval, acc -> acc ||| 0x4
      :map, acc -> acc ||| 0x8
      :timeout, acc -> acc ||| 0x10
      :dynamic, acc -> acc ||| 0x20
      :eval, acc -> acc ||| 0x20
      :object, acc -> acc ||| 0x40
      :concat, acc -> acc ||| 0x80
      :expr, acc -> acc ||| 0x100
      :auto_merge, acc -> acc
      _, acc -> acc
    end)
  end

  @doc "Inverse: u32 bitmask → list of flag atoms."
  @spec set_flags_atoms(non_neg_integer()) :: [atom()]
  def set_flags_atoms(flags) when is_integer(flags) do
    import Bitwise

    []
    |> append_if((flags &&& 0x1) != 0, :anonymous)
    |> append_if((flags &&& 0x2) != 0, :constant)
    |> append_if((flags &&& 0x4) != 0, :interval)
    |> append_if((flags &&& 0x8) != 0, :map)
    |> append_if((flags &&& 0x10) != 0, :timeout)
    |> append_if((flags &&& 0x20) != 0, :dynamic)
    |> append_if((flags &&& 0x40) != 0, :object)
    |> append_if((flags &&& 0x80) != 0, :concat)
    |> append_if((flags &&& 0x100) != 0, :expr)
  end

  # ===========================================================
  # Mapping helpers (atom → integer / vice versa)
  # ===========================================================

  @doc """
  NFPROTO_* — kernel address-family numbers used in `nfgen_family`
  and in `NF_INET_HOOKS` indexing.
  """
  @spec family_num(atom()) :: 0..255
  def family_num(:unspec), do: 0
  def family_num(:inet), do: 1
  def family_num(:ipv4), do: 2
  def family_num(:ip), do: 2
  def family_num(:arp), do: 3
  def family_num(:netdev), do: 5
  def family_num(:bridge), do: 7
  def family_num(:ipv6), do: 10
  def family_num(:ip6), do: 10

  @doc "Inverse of `family_num/1`. Returns `:unknown` for unrecognised numbers."
  @spec family_atom(0..255) :: atom()
  def family_atom(0), do: :unspec
  def family_atom(1), do: :inet
  def family_atom(2), do: :ip
  def family_atom(3), do: :arp
  def family_atom(5), do: :netdev
  def family_atom(7), do: :bridge
  def family_atom(10), do: :ip6
  def family_atom(_), do: :unknown

  @doc """
  Maps `(family, hook)` to the kernel's per-family hook number.

  The same atom (`:input`) corresponds to different integers
  depending on family — `NF_INET_LOCAL_IN = 1` for ip/ip6/inet,
  `NF_ARP_IN = 0` for arp, `NF_BR_LOCAL_IN = 1` for bridge.
  """
  @spec hook_num(atom(), atom()) :: 0..255
  # NF_INET_* — used by ip/ip6/inet families
  def hook_num(family, :prerouting) when family in [:ip, :ip6, :inet, :bridge], do: 0
  def hook_num(family, :input) when family in [:ip, :ip6, :inet, :bridge], do: 1
  def hook_num(family, :forward) when family in [:ip, :ip6, :inet, :bridge], do: 2
  def hook_num(family, :output) when family in [:ip, :ip6, :inet, :bridge], do: 3
  def hook_num(family, :postrouting) when family in [:ip, :ip6, :inet, :bridge], do: 4
  def hook_num(family, :ingress) when family in [:ip, :ip6, :inet], do: 5

  # NF_ARP_*
  def hook_num(:arp, :input), do: 0
  def hook_num(:arp, :output), do: 1

  # NF_NETDEV_*
  def hook_num(:netdev, :ingress), do: 0
  def hook_num(:netdev, :egress), do: 1

  @doc """
  Inverse of `hook_num/2`. Decoded hook numbers are family-dependent.
  """
  @spec hook_atom(atom(), 0..255) :: atom()
  def hook_atom(family, 0) when family in [:ip, :ip6, :inet, :bridge], do: :prerouting
  def hook_atom(family, 1) when family in [:ip, :ip6, :inet, :bridge], do: :input
  def hook_atom(family, 2) when family in [:ip, :ip6, :inet, :bridge], do: :forward
  def hook_atom(family, 3) when family in [:ip, :ip6, :inet, :bridge], do: :output
  def hook_atom(family, 4) when family in [:ip, :ip6, :inet, :bridge], do: :postrouting
  def hook_atom(family, 5) when family in [:ip, :ip6, :inet], do: :ingress
  def hook_atom(:arp, 0), do: :input
  def hook_atom(:arp, 1), do: :output
  def hook_atom(:netdev, 0), do: :ingress
  def hook_atom(:netdev, 1), do: :egress
  def hook_atom(_, n), do: {:unknown_hook, n}

  @doc """
  Resolves a chain priority — integer, named atom, or
  `{atom, offset}` — to a signed 32-bit integer per `family`.

  Standard nft names map to standard integer priorities. Bridge
  family has its own table (with `:filter` = -200 vs ip's `:filter`
  = 0); netdev / arp have effectively just `:filter` = 0.
  """
  @spec priority_int(atom(), integer() | atom() | {atom(), integer()}) :: integer()
  def priority_int(_family, n) when is_integer(n), do: n

  def priority_int(family, {name, offset}) when is_atom(name) and is_integer(offset),
    do: priority_int(family, name) + offset

  # ip / ip6 / inet — NF_IP_PRI_*
  def priority_int(family, :raw) when family in [:ip, :ip6, :inet], do: -300
  def priority_int(family, :mangle) when family in [:ip, :ip6, :inet], do: -150
  def priority_int(family, :dstnat) when family in [:ip, :ip6, :inet], do: -100
  def priority_int(family, :filter) when family in [:ip, :ip6, :inet], do: 0
  def priority_int(family, :security) when family in [:ip, :ip6, :inet], do: 50
  def priority_int(family, :srcnat) when family in [:ip, :ip6, :inet], do: 100

  # bridge — NF_BR_PRI_*
  def priority_int(:bridge, :dstnat), do: -300
  def priority_int(:bridge, :filter), do: -200
  def priority_int(:bridge, :out), do: 100
  def priority_int(:bridge, :srcnat), do: 300

  # netdev / arp — only filter is meaningful
  def priority_int(family, :filter) when family in [:netdev, :arp], do: 0

  @doc """
  Maps a chain type atom to the kernel's string form for
  `NFTA_CHAIN_TYPE`.
  """
  @spec chain_type_string(atom()) :: String.t()
  def chain_type_string(:filter), do: "filter"
  def chain_type_string(:nat), do: "nat"
  def chain_type_string(:route), do: "route"

  @doc "Inverse of `chain_type_string/1`."
  @spec chain_type_atom(binary()) :: atom()
  def chain_type_atom("filter"), do: :filter
  def chain_type_atom("nat"), do: :nat
  def chain_type_atom("route"), do: :route
  def chain_type_atom(other), do: {:unknown_type, other}

  @doc """
  Maps a table-flags list to the OR'd integer for `NFTA_TABLE_FLAGS`.
  """
  @spec table_flags_int([atom()]) :: non_neg_integer()
  def table_flags_int(flags) when is_list(flags) do
    import Bitwise

    Enum.reduce(flags, 0, fn
      :dormant, acc -> acc ||| 0x1
      :owner, acc -> acc ||| 0x2
      :persist, acc -> acc ||| 0x4
    end)
  end

  @doc "Decodes a table-flags integer into a list of atoms."
  @spec table_flags_atoms(non_neg_integer()) :: [atom()]
  def table_flags_atoms(flags) when is_integer(flags) do
    import Bitwise

    []
    |> append_if((flags &&& 0x1) != 0, :dormant)
    |> append_if((flags &&& 0x2) != 0, :owner)
    |> append_if((flags &&& 0x4) != 0, :persist)
  end

  @doc "Maps a chain-flags list to the OR'd integer for `NFTA_CHAIN_FLAGS`."
  @spec chain_flags_int([atom()]) :: non_neg_integer()
  def chain_flags_int(flags) when is_list(flags) do
    import Bitwise

    Enum.reduce(flags, 0, fn
      :hw_offload, acc -> acc ||| 0x2
      :binding, acc -> acc ||| 0x4
      _, acc -> acc
    end)
  end

  @doc "Decodes a chain-flags integer into a list of atoms."
  @spec chain_flags_atoms(non_neg_integer()) :: [atom()]
  def chain_flags_atoms(flags) when is_integer(flags) do
    import Bitwise

    []
    |> append_if((flags &&& 0x2) != 0, :hw_offload)
    |> append_if((flags &&& 0x4) != 0, :binding)
  end

  @doc """
  Maps a chain policy atom to the kernel's u32 verdict integer
  (NF_DROP = 0, NF_ACCEPT = 1).
  """
  @spec policy_int(atom()) :: 0 | 1
  def policy_int(:drop), do: 0
  def policy_int(:accept), do: 1

  @doc "Inverse of `policy_int/1`."
  @spec policy_atom(0 | 1) :: atom()
  def policy_atom(0), do: :drop
  def policy_atom(1), do: :accept

  # ===========================================================
  # Register IDs (per net/netfilter/nft_*.c usage)
  # ===========================================================

  defmacro nft_reg_verdict, do: 0
  defmacro nft_reg_1, do: 1
  defmacro nft_reg_2, do: 2
  defmacro nft_reg_3, do: 3
  defmacro nft_reg_4, do: 4
  defmacro nft_reg32_00, do: 8

  # ===========================================================
  # Verdict integers (NF_* / NFT_*)
  # ===========================================================

  defmacro nf_drop, do: 0
  defmacro nf_accept, do: 1
  defmacro nf_queue, do: 3
  defmacro nf_stop, do: 5
  defmacro nft_continue, do: -1
  defmacro nft_break, do: -2
  defmacro nft_jump, do: -3
  defmacro nft_goto, do: -4
  defmacro nft_return, do: -5

  @doc """
  Maps a `%Linx.Netfilter.Verdict{}` to its kernel verdict-code integer
  (signed; some are negative).
  """
  @spec verdict_code(atom()) :: integer()
  def verdict_code(:accept), do: 1
  def verdict_code(:drop), do: 0
  def verdict_code(:continue), do: -1
  def verdict_code(:return), do: -5
  def verdict_code(:jump), do: -3
  def verdict_code(:goto), do: -4
  def verdict_code(:queue), do: 3

  @doc "Inverse of `verdict_code/1`."
  @spec verdict_atom(integer()) :: atom()
  def verdict_atom(0), do: :drop
  def verdict_atom(1), do: :accept
  def verdict_atom(-1), do: :continue
  def verdict_atom(-5), do: :return
  def verdict_atom(-3), do: :jump
  def verdict_atom(-4), do: :goto
  def verdict_atom(3), do: :queue

  # ===========================================================
  # Cmp ops (enum nft_cmp_ops)
  # ===========================================================

  @spec cmp_op_int(atom()) :: 0..5
  def cmp_op_int(:eq), do: 0
  def cmp_op_int(:neq), do: 1
  def cmp_op_int(:lt), do: 2
  def cmp_op_int(:lte), do: 3
  def cmp_op_int(:gt), do: 4
  def cmp_op_int(:gte), do: 5

  @spec cmp_op_atom(0..5) :: atom()
  def cmp_op_atom(0), do: :eq
  def cmp_op_atom(1), do: :neq
  def cmp_op_atom(2), do: :lt
  def cmp_op_atom(3), do: :lte
  def cmp_op_atom(4), do: :gt
  def cmp_op_atom(5), do: :gte

  # ===========================================================
  # Payload bases (enum nft_payload_bases)
  # ===========================================================

  @spec payload_base_int(atom()) :: 0..3
  def payload_base_int(:link), do: 0
  def payload_base_int(:ll_header), do: 0
  def payload_base_int(:network), do: 1
  def payload_base_int(:network_header), do: 1
  def payload_base_int(:transport), do: 2
  def payload_base_int(:transport_header), do: 2
  def payload_base_int(:inner), do: 3
  def payload_base_int(:inner_header), do: 3

  @spec payload_base_atom(0..3) :: atom()
  def payload_base_atom(0), do: :link
  def payload_base_atom(1), do: :network
  def payload_base_atom(2), do: :transport
  def payload_base_atom(3), do: :inner

  # ===========================================================
  # Meta keys (subset — enum nft_meta_keys)
  # ===========================================================

  @spec meta_key_int(atom()) :: non_neg_integer()
  def meta_key_int(:len), do: 0
  def meta_key_int(:protocol), do: 1
  def meta_key_int(:priority), do: 2
  def meta_key_int(:mark), do: 3
  def meta_key_int(:iif), do: 4
  def meta_key_int(:oif), do: 5
  def meta_key_int(:iifname), do: 6
  def meta_key_int(:oifname), do: 7
  def meta_key_int(:iiftype), do: 8
  def meta_key_int(:oiftype), do: 9
  def meta_key_int(:skuid), do: 10
  def meta_key_int(:skgid), do: 11
  # 12 = NFT_META_NFTRACE, 13 = NFT_META_RTCLASSID, 14 =
  # NFT_META_SECMARK — nfproto/l4proto sit AFTER those in the
  # kernel enum (a kernel-acceptance catch: 12/13 here made the
  # protocol guards load nftrace/rtclassid instead).
  def meta_key_int(:nftrace), do: 12
  def meta_key_int(:rtclassid), do: 13
  def meta_key_int(:secmark), do: 14
  def meta_key_int(:nfproto), do: 15
  def meta_key_int(:l4proto), do: 16

  @spec meta_key_atom(non_neg_integer()) :: atom() | {:unknown_meta_key, non_neg_integer()}
  def meta_key_atom(0), do: :len
  def meta_key_atom(1), do: :protocol
  def meta_key_atom(2), do: :priority
  def meta_key_atom(3), do: :mark
  def meta_key_atom(4), do: :iif
  def meta_key_atom(5), do: :oif
  def meta_key_atom(6), do: :iifname
  def meta_key_atom(7), do: :oifname
  def meta_key_atom(8), do: :iiftype
  def meta_key_atom(9), do: :oiftype
  def meta_key_atom(10), do: :skuid
  def meta_key_atom(11), do: :skgid
  def meta_key_atom(12), do: :nftrace
  def meta_key_atom(13), do: :rtclassid
  def meta_key_atom(14), do: :secmark
  def meta_key_atom(15), do: :nfproto
  def meta_key_atom(16), do: :l4proto
  def meta_key_atom(n), do: {:unknown_meta_key, n}

  # ===========================================================
  # CT keys (subset — enum nft_ct_keys)
  # ===========================================================

  @spec ct_key_int(atom()) :: non_neg_integer()
  def ct_key_int(:state), do: 0
  def ct_key_int(:direction), do: 1
  def ct_key_int(:status), do: 2
  def ct_key_int(:mark), do: 3
  def ct_key_int(:secmark), do: 4

  @spec ct_key_atom(non_neg_integer()) :: atom() | {:unknown_ct_key, non_neg_integer()}
  def ct_key_atom(0), do: :state
  def ct_key_atom(1), do: :direction
  def ct_key_atom(2), do: :status
  def ct_key_atom(3), do: :mark
  def ct_key_atom(4), do: :secmark
  def ct_key_atom(n), do: {:unknown_ct_key, n}

  # CT state bitmask values (NF_CT_STATE_*)
  defmacro nf_ct_state_invalid_bit, do: 1
  defmacro nf_ct_state_established_bit, do: 2
  defmacro nf_ct_state_related_bit, do: 4
  defmacro nf_ct_state_new_bit, do: 8
  defmacro nf_ct_state_untracked_bit, do: 0x40

  @doc """
  Maps a CT-state atom (or list of atoms) to the kernel's bitmask.
  Multiple states OR together: `[:new, :related]` → 12.
  """
  @spec ct_state_bits(atom() | [atom()]) :: non_neg_integer()
  def ct_state_bits(state) when is_atom(state), do: ct_state_bits([state])

  def ct_state_bits(states) when is_list(states) do
    import Bitwise

    Enum.reduce(states, 0, fn
      :invalid, acc -> acc ||| 1
      :established, acc -> acc ||| 2
      :related, acc -> acc ||| 4
      :new, acc -> acc ||| 8
      :untracked, acc -> acc ||| 0x40
    end)
  end

  # ===========================================================
  # Reject types (enum nft_reject_types)
  # ===========================================================

  @spec reject_type_int(atom()) :: 0..2
  def reject_type_int(:icmp_unreach), do: 0
  def reject_type_int(:tcp_reset), do: 1
  def reject_type_int(:icmpx_unreach), do: 2

  @spec reject_type_atom(0..2) :: atom()
  def reject_type_atom(0), do: :icmp_unreach
  def reject_type_atom(1), do: :tcp_reset
  def reject_type_atom(2), do: :icmpx_unreach

  # ===========================================================
  # Lookup flags (NFT_LOOKUP_F_*)
  # ===========================================================

  defmacro nft_lookup_f_inv, do: 1

  @doc "Maps a lookup-flags list (`[:inv]`) to its u32 bitmask."
  @spec lookup_flags_int([atom()]) :: non_neg_integer()
  def lookup_flags_int(flags) when is_list(flags) do
    import Bitwise

    Enum.reduce(flags, 0, fn
      :inv, acc -> acc ||| 1
      _, acc -> acc
    end)
  end

  # ===========================================================
  # NFLOG (`NFNL_SUBSYS_ULOG`) constants
  # ===========================================================

  # NFULNL message types (low byte of nlmsghdr.type when subsys=4)
  defmacro nfulnl_msg_packet, do: 0
  defmacro nfulnl_msg_config, do: 1

  # NFULNL_CFG_CMD_*
  defmacro nfulnl_cfg_cmd_none, do: 0
  defmacro nfulnl_cfg_cmd_bind, do: 1
  defmacro nfulnl_cfg_cmd_unbind, do: 2
  defmacro nfulnl_cfg_cmd_pf_bind, do: 3
  defmacro nfulnl_cfg_cmd_pf_unbind, do: 4

  # NFULNL_COPY_*
  defmacro nfulnl_copy_none, do: 0
  defmacro nfulnl_copy_meta, do: 1
  defmacro nfulnl_copy_packet, do: 2

  # NFULNL_CFG_F_* (u16, big-endian on the wire)
  defmacro nfulnl_cfg_f_seq, do: 0x1
  defmacro nfulnl_cfg_f_seq_global, do: 0x2
  defmacro nfulnl_cfg_f_conntrack, do: 0x4

  # NFULA_CFG_* attributes (in NFULNL_MSG_CONFIG body)
  defmacro nfula_cfg_cmd, do: 1
  defmacro nfula_cfg_mode, do: 2
  defmacro nfula_cfg_nlbufsiz, do: 3
  defmacro nfula_cfg_timeout, do: 4
  defmacro nfula_cfg_qthresh, do: 5
  defmacro nfula_cfg_flags, do: 6

  # NFULA_* attributes (in NFULNL_MSG_PACKET body)
  defmacro nfula_packet_hdr, do: 1
  defmacro nfula_mark, do: 2
  defmacro nfula_timestamp, do: 3
  defmacro nfula_ifindex_indev, do: 4
  defmacro nfula_ifindex_outdev, do: 5
  defmacro nfula_ifindex_physindev, do: 6
  defmacro nfula_ifindex_physoutdev, do: 7
  defmacro nfula_hwaddr, do: 8
  defmacro nfula_payload, do: 9
  defmacro nfula_prefix, do: 10
  defmacro nfula_uid, do: 11
  defmacro nfula_seq, do: 12
  defmacro nfula_seq_global, do: 13
  defmacro nfula_gid, do: 14
  defmacro nfula_hwtype, do: 15
  defmacro nfula_hwheader, do: 16
  defmacro nfula_hwlen, do: 17
  defmacro nfula_ct, do: 18
  defmacro nfula_ct_info, do: 19
  defmacro nfula_vlan, do: 20
  defmacro nfula_l2hdr, do: 21

  # NFTA_LOG_* — attributes of the nft `log` expression
  defmacro nfta_log_group, do: 1
  defmacro nfta_log_prefix, do: 2
  defmacro nfta_log_snaplen, do: 3
  defmacro nfta_log_qthreshold, do: 4
  defmacro nfta_log_level, do: 5
  defmacro nfta_log_flags, do: 6

  @doc """
  Maps a NFLOG copy-mode atom to the kernel's u8 value:
  `:none` → 0, `:meta` → 1, `:packet` → 2.
  """
  @spec copy_mode_int(atom() | {:packet, non_neg_integer()}) :: 0..2
  def copy_mode_int(:none), do: 0
  def copy_mode_int(:meta), do: 1
  def copy_mode_int(:packet), do: 2
  def copy_mode_int({:packet, _snaplen}), do: 2

  @doc """
  Maps a NFLOG-config-flags list to the u16 bitmask (BE on wire).
  """
  @spec nfulnl_cfg_flags_int([atom()]) :: non_neg_integer()
  def nfulnl_cfg_flags_int(flags) when is_list(flags) do
    import Bitwise

    Enum.reduce(flags, 0, fn
      :seq, acc -> acc ||| 0x1
      :seq_global, acc -> acc ||| 0x2
      :conntrack, acc -> acc ||| 0x4
      _, acc -> acc
    end)
  end

  # ===========================================================
  # NAT flags (NF_NAT_RANGE_*)
  # ===========================================================

  @doc """
  Maps a NAT-flags list to the u32 bitmask the kernel expects in
  `NFTA_NAT_FLAGS` / `NFTA_MASQ_FLAGS` / `NFTA_REDIR_FLAGS`.

  Accepted atoms:

    * `:random` — randomize port selection (`NF_NAT_RANGE_PROTO_RANDOM`).
    * `:fully_random` — fully randomize, including per-connection
      (`NF_NAT_RANGE_PROTO_RANDOM_FULLY`).
    * `:persistent` — same client gets same NAT mapping
      (`NF_NAT_RANGE_PERSISTENT`).
    * `:netmap` — preserve the host portion of the address while
      remapping the network portion (`NF_NAT_RANGE_NETMAP`, 5.0+).

  Note: `:map_ips` and `:proto_specified` are usually set by the
  encoder based on whether addresses / ports are provided, not by
  the caller.
  """
  @spec nat_flags_int([atom()]) :: non_neg_integer()
  def nat_flags_int(flags) when is_list(flags) do
    import Bitwise

    Enum.reduce(flags, 0, fn
      :map_ips, acc -> acc ||| 0x01
      :proto_specified, acc -> acc ||| 0x02
      :random, acc -> acc ||| 0x04
      :persistent, acc -> acc ||| 0x08
      :fully_random, acc -> acc ||| 0x10
      :netmap, acc -> acc ||| 0x40
      _, acc -> acc
    end)
  end

  @doc "Decodes a NAT-flags u32 bitmask into a list of atoms."
  @spec nat_flags_atoms(non_neg_integer()) :: [atom()]
  def nat_flags_atoms(flags) when is_integer(flags) do
    import Bitwise

    []
    |> append_if((flags &&& 0x01) != 0, :map_ips)
    |> append_if((flags &&& 0x02) != 0, :proto_specified)
    |> append_if((flags &&& 0x04) != 0, :random)
    |> append_if((flags &&& 0x08) != 0, :persistent)
    |> append_if((flags &&& 0x10) != 0, :fully_random)
    |> append_if((flags &&& 0x40) != 0, :netmap)
  end

  # ===========================================================
  # Big-endian integer helpers
  # ===========================================================

  @doc "Encodes a u32 as 4 big-endian bytes (nftables convention)."
  @spec u32_be(non_neg_integer()) :: binary()
  def u32_be(v) when is_integer(v) and v >= 0 and v < 0x1_0000_0000,
    do: <<v::big-unsigned-32>>

  @doc "Decodes a 4-byte big-endian u32."
  @spec u32_be!(binary()) :: non_neg_integer()
  def u32_be!(<<v::big-unsigned-32>>), do: v

  @doc "Encodes an s32 as 4 big-endian bytes."
  @spec s32_be(integer()) :: binary()
  def s32_be(v) when is_integer(v), do: <<v::big-signed-32>>

  @doc "Decodes a 4-byte big-endian s32."
  @spec s32_be!(binary()) :: integer()
  def s32_be!(<<v::big-signed-32>>), do: v

  @doc "Encodes a u64 as 8 big-endian bytes."
  @spec u64_be(non_neg_integer()) :: binary()
  def u64_be(v) when is_integer(v) and v >= 0, do: <<v::big-unsigned-64>>

  @doc "Decodes an 8-byte big-endian u64."
  @spec u64_be!(binary()) :: non_neg_integer()
  def u64_be!(<<v::big-unsigned-64>>), do: v

  # ===========================================================
  # Private helpers
  # ===========================================================

  defp append_if(list, true, value), do: list ++ [value]
  defp append_if(list, false, _value), do: list
end
