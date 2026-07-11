defmodule Linx.Netfilter.Decoder do
  @moduledoc """
  Converts kernel-side `%Linx.Netlink.Message{}` payloads back into
  `%Linx.Netfilter.*{}` value structs.

  The shape mirrors `Linx.Netfilter.Encoder` — one decode function
  per entity. `from_msgs/3` groups a stream of decoded entities
  into a `%Ruleset{}`.

  ## Wire format quirks

  Same as `Linx.Netfilter.Encoder`: nftables NLA_U32 / NLA_U64 are
  **big-endian**, attribute IDs are namespaced.
  """

  import Bitwise
  import Linx.Netfilter.Wire

  alias Linx.Netfilter.{
    Chain,
    Event,
    Expr,
    Flowtable,
    Object,
    Rule,
    Ruleset,
    Set,
    Table,
    Verdict,
    Wire
  }

  alias Linx.Netfilter.Map, as: NMap
  alias Linx.Netlink.{Attr, Message}
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
      # The chain/set/object/flowtable decoders attach these by
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

    {tag, comment} = decode_rule_userdata(get_binary(attrs, nfta_rule_userdata()))

    rule = %Rule{
      expressions: expressions,
      chain: chain_name,
      handle: handle,
      tag: tag,
      comment: comment
    }

    {family, table_name, chain_name, rule}
  end

  # Mirror of the encoder's TLV format. See encoder.ex for the
  # type-byte allocations.
  @udata_rule_comment 0
  @udata_rule_linx_tag 16

  defp decode_rule_userdata(nil), do: {nil, nil}
  defp decode_rule_userdata(<<>>), do: {nil, nil}

  defp decode_rule_userdata(bin) do
    bin
    |> walk_udata({nil, nil})
  end

  defp walk_udata(<<>>, acc), do: acc

  defp walk_udata(<<type::8, len::8, rest::binary>>, {tag, comment}) do
    case rest do
      <<value::binary-size(len), more::binary>> ->
        str = String.trim_trailing(value, <<0>>)

        new_acc =
          case type do
            @udata_rule_linx_tag -> {decode_tag(str), comment}
            @udata_rule_comment -> {tag, str}
            _ -> {tag, comment}
          end

        walk_udata(more, new_acc)

      _ ->
        {tag, comment}
    end
  end

  # Rule userdata comes from the kernel, and any writer in the netns
  # controls it — interning it unconditionally would let a co-tenant
  # writing many distinct tag TLVs grow the (permanent) atom table until
  # the VM dies. Only tags whose atom already exists (i.e. ones this
  # application actually uses) come back as atoms; foreign tags stay
  # binaries.
  defp decode_tag(str) do
    String.to_existing_atom(str)
  rescue
    ArgumentError -> str
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
  defp expr_name_atom("limit"), do: :limit
  defp expr_name_atom("dynset"), do: :dynset
  defp expr_name_atom("nat"), do: :nat
  defp expr_name_atom("masq"), do: :masq
  defp expr_name_atom("redir"), do: :redir
  defp expr_name_atom("log"), do: :log
  defp expr_name_atom("quota"), do: :quota
  defp expr_name_atom("objref"), do: :objref
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

  defp decode_expr_data(:dynset, bin) do
    attrs = Attr.decode(bin)

    op =
      case get_u32_be(attrs, nfta_dynset_op(), 0) do
        0 -> :add
        1 -> :update
        2 -> :delete
      end

    nested =
      case get_binary(attrs, nfta_dynset_expr()) do
        nil -> []
        expr_bin -> [decode_expression(expr_bin)]
      end

    %{
      set: get_string(attrs, nfta_dynset_set_name()),
      op: op,
      sreg_key: get_u32_be(attrs, nfta_dynset_sreg_key(), 1),
      timeout: get_u64_be(attrs, nfta_dynset_timeout(), nil),
      exprs: nested
    }
  end

  defp decode_expr_data(:limit, bin) do
    attrs = Attr.decode(bin)

    type =
      case get_u32_be(attrs, nfta_limit_type(), 0) do
        0 -> :packets
        1 -> :bytes
      end

    flags = get_u32_be(attrs, nfta_limit_flags(), 0)

    %{
      rate: get_u64_be(attrs, nfta_limit_rate(), 0),
      per: get_u64_be(attrs, nfta_limit_unit(), 1),
      burst: get_u32_be(attrs, nfta_limit_burst(), 0),
      type: type,
      over: Bitwise.band(flags, nft_limit_f_inv()) != 0
    }
  end

  # Mirrors the encoder's :log shape so pulled rules compare equal to
  # authored ones and re-encode instead of dying in the encoder.
  defp decode_expr_data(:log, bin) do
    attrs = Attr.decode(bin)

    %{
      group: get_u16_be(attrs, nfta_log_group(), nil),
      prefix: get_string(attrs, nfta_log_prefix()),
      snaplen: get_u32_be(attrs, nfta_log_snaplen(), nil),
      qthreshold: get_u16_be(attrs, nfta_log_qthreshold(), nil),
      flags: decode_log_flags(get_u32_be(attrs, nfta_log_flags(), 0))
    }
  end

  defp decode_expr_data(:quota, bin) do
    attrs = Attr.decode(bin)
    flags = get_u32_be(attrs, nfta_quota_flags(), 0)

    %{
      bytes: get_u64_be(attrs, nfta_quota_bytes(), 0),
      used: get_u64_be(attrs, nfta_quota_consumed(), 0),
      over: Bitwise.band(flags, nft_quota_f_inv()) != 0
    }
  end

  defp decode_expr_data(:objref, bin) do
    attrs = Attr.decode(bin)

    %{
      name: get_string(attrs, nfta_objref_imm_name()),
      kind: object_kind_atom(get_u32_be(attrs, nfta_objref_imm_type(), 0))
    }
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

  @doc """
  Decodes a `NEWOBJ` body into `{family, %Object{}}` — the object's
  `:table` field carries its owner, mirroring `set/1`.
  """
  @spec object(binary()) :: {Table.family(), Object.t()}
  def object(body) when is_binary(body) do
    {family_int, _ver, _res_id, attrs_bin} = Codec.decode_nfgenmsg(body)
    family = Wire.family_atom(family_int)
    attrs = Attr.decode(attrs_bin)

    kind = object_kind_atom(get_u32_be(attrs, nfta_obj_type(), 0))

    data =
      case List.keyfind(attrs, nfta_obj_data(), 0) do
        {_, data_bin} -> decode_object_data(kind, data_bin)
        nil -> nil
      end

    {family,
     %Object{
       kind: kind,
       name: get_string(attrs, nfta_obj_name()),
       table: get_string(attrs, nfta_obj_table()),
       data: data,
       handle: get_u64_be(attrs, nfta_obj_handle(), nil)
     }}
  end

  # The kinds the encoder can write decode to the same shapes it
  # takes; other kinds keep their raw NFTA_OBJ_DATA payload.
  defp decode_object_data(:counter, bin) do
    attrs = Attr.decode(bin)

    %{
      packets: get_u64_be(attrs, nfta_counter_packets(), 0),
      bytes: get_u64_be(attrs, nfta_counter_bytes(), 0)
    }
  end

  defp decode_object_data(:quota, bin), do: decode_expr_data(:quota, bin)
  defp decode_object_data(:limit, bin), do: decode_expr_data(:limit, bin)
  defp decode_object_data(_kind, bin), do: bin

  @doc """
  Decodes a `NEWFLOWTABLE` body into `{family, %Flowtable{}}`.
  """
  @spec flowtable(binary()) :: {Table.family(), Flowtable.t()}
  def flowtable(body) when is_binary(body) do
    {family_int, _ver, _res_id, attrs_bin} = Codec.decode_nfgenmsg(body)
    family = Wire.family_atom(family_int)
    attrs = Attr.decode(attrs_bin)

    {hook, priority, devices} = decode_flowtable_hook(attrs)
    flags_int = get_u32_be(attrs, nfta_flowtable_flags(), 0)

    flags =
      Enum.filter(
        [
          if((flags_int &&& nft_flowtable_hw_offload()) != 0, do: :hw_offload),
          if((flags_int &&& nft_flowtable_counter()) != 0, do: :counter)
        ],
        & &1
      )

    {family,
     %Flowtable{
       name: get_string(attrs, nfta_flowtable_name()),
       table: get_string(attrs, nfta_flowtable_table()),
       hook: hook,
       priority: priority,
       devices: devices,
       flags: flags,
       handle: get_u64_be(attrs, nfta_flowtable_handle(), nil)
     }}
  end

  defp decode_flowtable_hook(attrs) do
    case List.keyfind(attrs, nfta_flowtable_hook(), 0) do
      {_, hook_bin} ->
        hook_attrs = Attr.decode(hook_bin)

        devices =
          case List.keyfind(hook_attrs, nfta_flowtable_hook_devs(), 0) do
            {_, devs_bin} ->
              devs_bin
              |> Attr.decode()
              |> Enum.flat_map(fn
                {tag, dev} when tag == nfta_device_name() ->
                  [String.trim_trailing(dev, <<0>>)]

                _ ->
                  []
              end)

            nil ->
              []
          end

        num = get_u32_be(hook_attrs, nfta_flowtable_hook_num(), 0)
        hook = if num == 0, do: :ingress, else: num

        priority =
          case List.keyfind(hook_attrs, nfta_flowtable_hook_priority(), 0) do
            {_, <<p::big-signed-32>>} -> p
            _ -> nil
          end

        {hook, priority, devices}

      nil ->
        {nil, nil, []}
    end
  end

  # Inverse of the encoder's encode_log_flags bit table.
  @log_flag_bits [tcp_seq: 0x01, tcp_opt: 0x02, ip_opt: 0x04, uid: 0x08, macdecode: 0x20]

  defp decode_log_flags(0), do: []

  defp decode_log_flags(int) do
    for {atom, bit} <- @log_flag_bits, Bitwise.band(int, bit) != 0, do: atom
  end

  # Inverse of the encoder's object_kind_int/1.
  defp object_kind_atom(n) do
    cond do
      n == nft_object_counter() -> :counter
      n == nft_object_quota() -> :quota
      n == nft_object_ct_helper() -> :ct_helper
      n == nft_object_limit() -> :limit
      n == nft_object_connlimit() -> :connlimit
      n == nft_object_ct_timeout() -> :ct_timeout
      n == nft_object_secmark() -> :secmark
      n == nft_object_ct_expect() -> :ct_expectation
      n == nft_object_synproxy() -> :synproxy
      true -> {:unknown_object_kind, n}
    end
  end

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

    # NF_QUEUE embeds its queue number in the high 16 bits of the code
    # (NF_QUEUE_NR); mask it off before the kind lookup and surface it
    # as the verdict's target so Verdict.queue(n) round-trips.
    {code, queue_num} =
      if code >= 0 and (code &&& 0xFF) == Wire.verdict_code(:queue) do
        {code &&& 0xFF, code >>> 16}
      else
        {code, nil}
      end

    kind = Wire.verdict_atom(code)

    target =
      cond do
        kind in [:jump, :goto] -> chain
        kind == :queue -> queue_num
        true -> nil
      end

    %Verdict{kind: kind, target: target}
  end

  defp decode_lookup_flags(0), do: []

  defp decode_lookup_flags(int) do
    import Bitwise
    if (int &&& 1) != 0, do: [:inv], else: []
  end

  # ===========================================================
  # Sets / maps
  # ===========================================================

  @doc """
  Decodes a `NEWSET` body into either a `%Linx.Netfilter.Set{}`
  (plain set — no `NFT_SET_F_MAP` flag) or a `%Linx.Netfilter.Map{}`
  (map / vmap).

  Returns `{family, set_or_map}` for downstream assembly.
  """
  @spec set(binary()) :: {Table.family(), Set.t() | NMap.t()}
  def set(body) when is_binary(body) do
    {family_int, _ver, _res_id, attrs_bin} = Codec.decode_nfgenmsg(body)
    family = Wire.family_atom(family_int)
    attrs = Attr.decode(attrs_bin)

    name = get_string(attrs, nfta_set_name())
    table = get_string(attrs, nfta_set_table())
    flags_int = get_u32_be(attrs, nfta_set_flags(), 0)
    flags = Wire.set_flags_atoms(flags_int)
    key_type_int = get_u32_be(attrs, nfta_set_key_type(), 0)
    key_len = get_u32_be(attrs, nfta_set_key_len(), 0)
    key_type = Wire.set_type_atom(key_type_int, key_len)

    is_map? = Enum.member?(flags, :map)
    is_anon? = Enum.member?(flags, :anonymous)

    timeout = get_u64_be(attrs, nfta_set_timeout(), nil)
    gc_interval = get_u32_be(attrs, nfta_set_gc_interval(), nil)
    handle = get_u64_be(attrs, nfta_set_handle(), nil)
    size = decode_set_desc_size(attrs)

    user_flags = Enum.reject(flags, &(&1 in [:map, :anonymous]))

    entity =
      if is_map? do
        data_type_int = get_u32_be(attrs, nfta_set_data_type(), 0)
        data_len = get_u32_be(attrs, nfta_set_data_len(), 0)

        data_type =
          cond do
            data_type_int == 0xFFFFFF00 -> :verdict
            true -> Wire.set_type_atom(data_type_int, data_len)
          end

        %NMap{
          name: name,
          table: table,
          key_type: key_type,
          data_type: data_type,
          flags: user_flags ++ if(is_anon?, do: [:anonymous], else: []),
          elements: [],
          timeout: timeout,
          gc_interval: gc_interval,
          size: size,
          handle: handle,
          comment: nil
        }
      else
        %Set{
          name: name,
          table: table,
          key_type: key_type,
          flags: user_flags ++ if(is_anon?, do: [:anonymous], else: []),
          elements: [],
          timeout: timeout,
          gc_interval: gc_interval,
          size: size,
          handle: handle,
          comment: nil
        }
      end

    {family, entity}
  end

  defp decode_set_desc_size(attrs) do
    case List.keyfind(attrs, nfta_set_desc(), 0) do
      {_, desc_bin} ->
        desc_attrs = Attr.decode(desc_bin)
        get_u32_be(desc_attrs, nfta_set_desc_size(), nil)

      nil ->
        nil
    end
  end

  @doc """
  Decodes a `NEWSETELEM` body into a list of elements attached to
  a `(family, table_name, set_name)`.

  Returns `{family, table_name, set_name, elements}` where
  `elements` is a list of either raw key terms or `{key, value}`
  tuples (the caller resolves which based on whether the parent
  set is plain or a map).

  For now we return the elements with KEY binary unparsed (raw
  binary) and DATA either a raw binary or a `%Verdict{}` for
  verdict data. Higher-level conversion (binary → tuple, etc.)
  happens at assembly time when we know the parent set's
  key_type.
  """
  @spec set_elements(binary()) ::
          {Table.family(), String.t(), String.t(), [{binary(), term()} | binary()]}
  def set_elements(body) when is_binary(body) do
    {family_int, _ver, _res_id, attrs_bin} = Codec.decode_nfgenmsg(body)
    family = Wire.family_atom(family_int)
    attrs = Attr.decode(attrs_bin)

    table = get_string(attrs, nfta_set_elem_list_table())
    set_name = get_string(attrs, nfta_set_elem_list_set())

    elements =
      case List.keyfind(attrs, nfta_set_elem_list_elements(), 0) do
        {_, list_bin} ->
          list_bin
          |> Attr.decode()
          |> Enum.flat_map(fn
            {tag, payload} when tag == nfta_list_elem() -> [decode_one_set_elem(payload)]
            _ -> []
          end)

        nil ->
          []
      end

    {family, table, set_name, elements}
  end

  defp decode_one_set_elem(bin) do
    attrs = Attr.decode(bin)

    key_bin = elem_key(attrs, nfta_set_elem_key())
    key_end_bin = elem_key(attrs, nfta_set_elem_key_end())

    cond do
      # Pipapo interval entry (concatenated interval sets): start and
      # end bounds in one element via NFTA_SET_ELEM_KEY_END — the shape
      # the encoder emits for {:concat, _} interval sets.
      key_end_bin != nil ->
        {:key_with_end, key_bin, key_end_bin, elem_data(attrs)}

      # Interval sets carry their range ends as separate elements flagged
      # NFT_SET_ELEM_INTERVAL_END; surface them as tagged markers so
      # materialize_elements/4 can pair them back into `{:range, lo, hi}`.
      (elem_flags(attrs) &&& nft_set_elem_interval_end()) != 0 ->
        {:interval_end, key_bin}

      true ->
        case elem_data(attrs) do
          nil -> key_bin
          data_value -> {key_bin, data_value}
        end
    end
  end

  defp elem_key(attrs, tag) do
    case List.keyfind(attrs, tag, 0) do
      {_, key_nla} ->
        key_attrs = Attr.decode(key_nla)
        get_binary(key_attrs, nfta_data_value())

      nil ->
        nil
    end
  end

  defp elem_data(attrs) do
    case List.keyfind(attrs, nfta_set_elem_data(), 0) do
      {_, data_nla} ->
        data_attrs = Attr.decode(data_nla)

        cond do
          verdict_bin = get_binary(data_attrs, nfta_data_verdict()) ->
            decode_verdict(verdict_bin)

          true ->
            get_binary(data_attrs, nfta_data_value())
        end

      nil ->
        nil
    end
  end

  defp elem_flags(attrs) do
    case List.keyfind(attrs, nfta_set_elem_flags(), 0) do
      {_, <<flags::big-32>>} -> flags
      _ -> 0
    end
  end

  @doc """
  Materialises a raw set-element list (from `set_elements/1`) into
  the value shape the parent set expects. Plain sets keep raw key
  binaries (the codec doesn't know to expand `<<10, 0, 0, 5>>` back
  to `{10, 0, 0, 5}` without context). Maps preserve `{key, value}`.

  When `interval?` is `true` (the parent set has the `:interval` flag),
  `{:interval_end, key}` markers are paired with the preceding start
  element into `{:range, lo, hi}` (`hi` = marker key − 1, matching the
  encoder's exclusive-end convention); a width-1 interval collapses back
  to its scalar, and a start with no marker runs to the type's maximum.
  """
  @spec materialize_elements(
          [{binary(), term()} | binary() | {:interval_end, binary()}],
          atom(),
          atom() | nil,
          boolean()
        ) :: [term()]
  def materialize_elements(elements, key_type, data_type, interval? \\ false)

  def materialize_elements(elements, key_type, data_type, false) do
    Enum.map(elements, fn
      # Tolerate stray end markers on a set not flagged :interval.
      {:interval_end, k} -> decode_key(k, key_type)
      # Tolerate a KEY_END entry on a set not flagged :interval: keep
      # the start bound as the key.
      {:key_with_end, k, _e, nil} -> decode_key(k, key_type)
      {:key_with_end, k, _e, v} -> {decode_key(k, key_type), decode_data(v, data_type)}
      {k, v} -> {decode_key(k, key_type), decode_data(v, data_type)}
      k -> decode_key(k, key_type)
    end)
  end

  # Concatenated interval sets (pipapo) carry both bounds in one
  # element (NFTA_SET_ELEM_KEY_END); pair the per-field bounds back
  # into scalar-or-{:range, lo, hi} parts.
  def materialize_elements(elements, {:concat, types}, data_type, true) do
    Enum.map(elements, fn
      {:key_with_end, start_bin, end_bin, data} ->
        parts =
          [split_concat_fields(start_bin, types), split_concat_fields(end_bin, types), types]
          |> Enum.zip()
          |> Enum.map(fn {lo_raw, hi_raw, type} ->
            if lo_raw == hi_raw do
              decode_key(lo_raw, type)
            else
              {:range, decode_key(lo_raw, type), decode_key(hi_raw, type)}
            end
          end)

        case data do
          nil -> parts
          _ -> {parts, decode_data(data, data_type)}
        end

      {k, v} ->
        {decode_key(k, {:concat, types}), decode_data(v, data_type)}

      k when is_binary(k) ->
        decode_key(k, {:concat, types})
    end)
  end

  def materialize_elements(elements, key_type, data_type, true) do
    materialize_intervals(elements, key_type, data_type)
  end

  defp materialize_intervals([], _kt, _dt), do: []

  defp materialize_intervals([elem, {:interval_end, end_key} | rest], kt, dt)
       when not is_nil(end_key) do
    {key_bin, data} = split_raw_elem(elem)
    hi_bin = decrement_key(end_key)
    [interval_elem(key_bin, hi_bin, data, kt, dt) | materialize_intervals(rest, kt, dt)]
  end

  # A stray end marker with no preceding start (e.g. dump artifacts) —
  # nothing to pair it with; drop it.
  defp materialize_intervals([{:interval_end, _} | rest], kt, dt),
    do: materialize_intervals(rest, kt, dt)

  # A start with no end marker: the interval runs to the end of the
  # keyspace (the encoder omits the marker when hi is the type max).
  defp materialize_intervals([elem | rest], kt, dt) do
    {key_bin, data} = split_raw_elem(elem)
    hi_bin = :binary.copy(<<0xFF>>, byte_size(key_bin))
    [interval_elem(key_bin, hi_bin, data, kt, dt) | materialize_intervals(rest, kt, dt)]
  end

  defp split_raw_elem({k, v}), do: {k, v}
  defp split_raw_elem(k), do: {k, nil}

  defp interval_elem(key_bin, hi_bin, data, kt, dt) do
    key_term =
      if hi_bin == key_bin do
        decode_key(key_bin, kt)
      else
        {:range, decode_key(key_bin, kt), decode_key(hi_bin, kt)}
      end

    case data do
      nil -> key_term
      _ -> {key_term, decode_data(data, dt)}
    end
  end

  # Big-endian −1 over the full key width (inverse of the encoder's +1).
  # A zero end key can't legitimately reach here (the kernel's leading
  # zero sentinel arrives with no preceding start and is consumed by the
  # stray-marker clause) — refuse to wrap to all-ones rather than
  # fabricate a bogus type-max bound.
  defp decrement_key(bin) do
    size = byte_size(bin) * 8

    case bin do
      <<0::size(size)>> ->
        raise ArgumentError, "interval end key of zero cannot be decremented"

      <<n::size(size)>> ->
        <<n - 1::size(size)>>
    end
  end

  defp decode_key(<<a, b, c, d>>, :ipv4_addr), do: {a, b, c, d}

  defp decode_key(<<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>, :ipv6_addr),
    do: {a, b, c, d, e, f, g, h}

  defp decode_key(<<a, b, c, d, e, f>>, :ether_addr), do: {a, b, c, d, e, f}
  defp decode_key(<<port::big-16>>, :inet_service), do: port
  defp decode_key(<<proto>>, :inet_proto), do: proto
  # Marks are host byte order on the wire (the kernel memcmps them against
  # a native u32 register); the encoder writes them native-endian too.
  defp decode_key(<<mark::native-32>>, :mark), do: mark
  defp decode_key(bin, :ifname), do: String.trim_trailing(bin, <<0>>)

  # A concatenated key blob: split into per-field parts (each padded to
  # the 4-byte register size on the wire) and decode each by its own
  # type. A blob that doesn't match the declared width stays raw.
  defp decode_key(bin, {:concat, types}) when is_binary(bin) do
    expected = Enum.sum(Enum.map(types, fn t -> pad4(elem(Wire.set_type_info(t), 1)) end))

    if byte_size(bin) == expected do
      types
      |> split_concat_fields(bin, [])
      |> Enum.zip(types)
      |> Enum.map(fn {raw, type} -> decode_key(raw, type) end)
    else
      bin
    end
  end

  defp decode_key(bin, _), do: bin

  defp split_concat_fields(bin, types), do: split_concat_fields(types, bin, [])

  defp split_concat_fields([], _rest, acc), do: Enum.reverse(acc)

  defp split_concat_fields([type | types], rest, acc) do
    {_id, len} = Wire.set_type_info(type)
    padded = pad4(len)
    <<field::binary-size(padded), tail::binary>> = rest
    <<raw::binary-size(len), _::binary>> = field
    split_concat_fields(types, tail, [raw | acc])
  end

  defp pad4(n), do: div(n + 3, 4) * 4

  defp decode_data(%Verdict{} = v, :verdict), do: v
  defp decode_data(bin, type), do: decode_key(bin, type)

  # ===========================================================
  # Assembly
  # ===========================================================

  @doc """
  Builds a `%Ruleset{}` from separate lists of decoded entries.

    * `tables` — `[%Table{}]` from a `NFT_MSG_GETTABLE` dump.
    * `chains` — `[{family, %Chain{}}]` from a `NFT_MSG_GETCHAIN` dump.
    * `rules` — `[{family, table_name, chain_name, %Rule{}}]` from
      a `NFT_MSG_GETRULE` dump.
    * `sets` — `[{family, %Set{} | %Map{}}]` from a
      `NFT_MSG_GETSET` dump.
    * `set_elements` — `[{family, table_name, set_name, [elem]}]`
      from per-set `NFT_MSG_GETSETELEM` calls.

  Chains, sets, and rules are attached to their parents by
  `(family, table_name)`. Set elements are materialised against
  the parent set's `key_type` / `data_type` and attached to the
  set in dump order.

  Entities that reference a missing parent are silently dropped.
  """
  @spec from_msgs(
          [Table.t()],
          [{Table.family(), Chain.t()}],
          [{Table.family(), String.t(), String.t(), Rule.t()}],
          [{Table.family(), Set.t() | NMap.t()}],
          [{Table.family(), String.t(), String.t(), [term()]}],
          [{Table.family(), Object.t()}],
          [{Table.family(), Flowtable.t()}]
        ) :: Ruleset.t()
  def from_msgs(
        tables,
        chains,
        rules,
        sets \\ [],
        set_elements \\ [],
        objects \\ [],
        flowtables \\ []
      ) do
    tables_map =
      Enum.reduce(tables, %{}, fn %Table{family: f, name: n} = t, acc ->
        Map.put(acc, {f, n}, t)
      end)

    tables_map = attach_chains(tables_map, chains)
    tables_map = attach_sets(tables_map, sets)
    tables_map = attach_set_elements(tables_map, set_elements)
    tables_map = attach_rules(tables_map, rules)
    tables_map = attach_objects(tables_map, objects)
    tables_map = attach_flowtables(tables_map, flowtables)

    %Ruleset{tables: tables_map}
  end

  defp attach_objects(tables_map, objects) do
    Enum.reduce(objects, tables_map, fn {family, %Object{} = obj}, acc ->
      case Map.fetch(acc, {family, obj.table}) do
        {:ok, %Table{} = t} ->
          objects = Map.put(t.objects, {obj.kind, obj.name}, obj)
          Map.put(acc, {family, obj.table}, %Table{t | objects: objects})

        :error ->
          acc
      end
    end)
  end

  defp attach_flowtables(tables_map, flowtables) do
    Enum.reduce(flowtables, tables_map, fn {family, %Flowtable{} = ft}, acc ->
      case Map.fetch(acc, {family, ft.table}) do
        {:ok, %Table{} = t} ->
          Map.put(acc, {family, ft.table}, %Table{
            t
            | flowtables: Map.put(t.flowtables, ft.name, ft)
          })

        :error ->
          acc
      end
    end)
  end

  defp attach_sets(tables_map, sets) do
    Enum.reduce(sets, tables_map, fn {family, entity}, acc ->
      key = {family, entity_table(entity)}

      case Map.fetch(acc, key) do
        {:ok, %Table{} = t} ->
          updated =
            case entity do
              %Set{} ->
                %Table{t | sets: Map.put(t.sets, entity.name, entity)}

              %NMap{} ->
                %Table{t | maps: Map.put(t.maps, entity.name, entity)}
            end

          Map.put(acc, key, updated)

        :error ->
          acc
      end
    end)
  end

  defp entity_table(%Set{table: t}), do: t
  defp entity_table(%NMap{table: t}), do: t

  defp attach_set_elements(tables_map, set_elements) do
    Enum.reduce(set_elements, tables_map, fn {family, table_name, set_name, raw_elems}, acc ->
      key = {family, table_name}

      case Map.fetch(acc, key) do
        {:ok, %Table{} = t} ->
          cond do
            Map.has_key?(t.sets, set_name) ->
              %Set{} = set = Map.fetch!(t.sets, set_name)

              materialised =
                materialize_elements(raw_elems, set.key_type, nil, :interval in set.flags)

              updated_set = %Set{set | elements: set.elements ++ materialised}
              Map.put(acc, key, %Table{t | sets: Map.put(t.sets, set_name, updated_set)})

            Map.has_key?(t.maps, set_name) ->
              %NMap{} = map = Map.fetch!(t.maps, set_name)

              materialised =
                materialize_elements(
                  raw_elems,
                  map.key_type,
                  map.data_type,
                  :interval in map.flags
                )

              updated_map = %NMap{map | elements: map.elements ++ materialised}
              Map.put(acc, key, %Table{t | maps: Map.put(t.maps, set_name, updated_map)})

            true ->
              acc
          end

        :error ->
          acc
      end
    end)
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
  # Multicast events
  # ===========================================================

  @doc """
  Decodes a `NFNLGRP_NFTABLES` multicast message into a partial
  `%Linx.Netfilter.Event{}` — `gen_id` / `proc_pid` / `proc_name`
  are left nil; the Monitor GenServer fills them in from the most
  recent `NEW_GEN` event.

  For NEW_GEN events, the gen / pid / name come from the body
  itself.

  Dispatches on the low byte of `nlmsghdr.type` (the per-subsys
  message opcode).
  """
  @spec event(Message.t()) :: Event.t()
  def event(%Message{type: type, payload: body}) do
    {_subsys, msg_type} = Codec.split_type(type)
    decode_event(msg_type, body)
  end

  defp decode_event(msg_type, body) do
    cond do
      msg_type == nft_msg_newgen() ->
        gen = decode_gen(body)

        %Event{
          op: :new_gen,
          entity: gen,
          gen_id: gen.id,
          proc_pid: gen.proc_pid,
          proc_name: gen.proc_name
        }

      msg_type == nft_msg_newtable() ->
        %Event{op: :new_table, entity: table(body)}

      msg_type == nft_msg_deltable() or msg_type == nft_msg_destroytable() ->
        %Event{op: :del_table, entity: table(body)}

      msg_type == nft_msg_newchain() ->
        %Event{op: :new_chain, entity: chain(body)}

      msg_type == nft_msg_delchain() or msg_type == nft_msg_destroychain() ->
        %Event{op: :del_chain, entity: chain(body)}

      msg_type == nft_msg_newrule() ->
        %Event{op: :new_rule, entity: rule(body)}

      msg_type == nft_msg_delrule() or msg_type == nft_msg_destroyrule() ->
        %Event{op: :del_rule, entity: rule(body)}

      msg_type == nft_msg_newset() ->
        %Event{op: :new_set, entity: set(body)}

      msg_type == nft_msg_delset() or msg_type == nft_msg_destroyset() ->
        %Event{op: :del_set, entity: set(body)}

      msg_type == nft_msg_newsetelem() ->
        %Event{op: :new_set_element, entity: set_elements(body)}

      msg_type == nft_msg_delsetelem() or msg_type == nft_msg_destroysetelem() ->
        %Event{op: :del_set_element, entity: set_elements(body)}

      true ->
        %Event{op: {:unknown, msg_type}, entity: body}
    end
  end

  defp decode_gen(body) do
    {_family, _ver, _res_id, attrs_bin} = Codec.decode_nfgenmsg(body)
    attrs = Attr.decode(attrs_bin)

    %{
      id: get_u32_be(attrs, nfta_gen_id(), 0),
      proc_pid: get_u32_be(attrs, nfta_gen_proc_pid(), nil),
      proc_name: decode_gen_proc_name(attrs)
    }
  end

  defp nfta_gen_id, do: 1
  defp nfta_gen_proc_pid, do: 2
  defp nfta_gen_proc_name, do: 3

  defp decode_gen_proc_name(attrs) do
    case List.keyfind(attrs, nfta_gen_proc_name(), 0) do
      {_, value} -> String.trim_trailing(value, <<0>>)
      nil -> nil
    end
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

  defp get_u16_be(attrs, tag, default) do
    case List.keyfind(attrs, tag, 0) do
      {^tag, <<v::big-unsigned-16>>} -> v
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
  # dedicated slot for it yet. For now, silently swallow.
  defp maybe_attach_userdata(table, nil), do: table
  defp maybe_attach_userdata(table, _bin), do: table
end
