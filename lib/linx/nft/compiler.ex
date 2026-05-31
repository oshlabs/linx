defmodule Linx.NFT.Compiler do
  @moduledoc """
  AST → `%Linx.Netfilter.Ruleset{}` translation.

  Walks the AST produced by `Linx.NFT.Parser` and calls into the
  validator-setter surface on `Linx.Netfilter.Ruleset` (and
  friends) — the **same** surface the pipeline DSL uses. There's
  no parallel validation here; if a chain hook is invalid for its
  family, or a set element doesn't match the key type, the
  validator-setter raises and we propagate the failure as a
  `Linx.NFT.ParseError` with the AST node's `{file, line, column}`.

  ## Supported

  The slice of the AST that covers the canonical examples in
  `docs/netfilter/EXAMPLES.md`:

    * **Tables** in every family, with optional `comment`.
    * **Chains** with base headers (`type`/`hook`/`priority`/
      `policy`/`device`) and rules.
    * **Rules** with tag + comment, comprising matches and a
      terminal verdict (plus optional `counter` / `log` / NAT /
      `reject`).
    * **Matches** on the common headers — `tcp/udp dport/sport`
      against integer / range / inline-set / `@set_ref`,
      `ip/ip6 saddr/daddr` against address / CIDR / `@set_ref`,
      `meta iif/oif/iifname/oifname/mark`, `ct state`.
    * **Verdicts** — accept / drop / continue / return / queue /
      `jump <chain>` / `goto <chain>` / `reject [with ...]`.
    * **Actions** — `counter`, `log`, `dnat to <addr>[:port]`,
      `snat to`, `masquerade`, `redirect`.
    * **Sets / maps / vmaps** — declarations with `type`, `flags`,
      `timeout`, `gc-interval`, `size`, `elements`.

  ## Not yet supported (raises a clear ParseError)

    * `limit`, `meta mark set`, `ct ... set` — no setter `%Expr{}`
      yet on the Linx side. Pipeline DSL can construct them; the
      compiler will pick them up once they're added.
    * Named objects (`counter` / `quota` / `limit` blocks at table
      level) — declaration OK, but the underlying `%Object{}`
      shapes vary per kind; defer to a follow-up.
    * Flowtables — same reason.
    * `include` and `define` — file-merging and binding semantics
      are not yet implemented (use `Linx.NFT.parse_file/1`).
    * `\#{...}` interpolation — only meaningful from the
      `~NFT` sigil; the compiler is called from there with a
      separate path that emits runtime code.

  Each deferred case raises `Linx.NFT.ParseError` pointing at the
  AST node's source location with a message naming the missing
  feature, so users see exactly what the parser accepted but the
  compiler hasn't wired up yet.
  """

  alias Linx.NFT.ParseError
  alias Linx.Netfilter.{Expr, Ruleset, Set, Verdict, Wire}
  alias Linx.Netfilter.Map, as: NMap

  import Bitwise

  defmodule State do
    @moduledoc false

    @enforce_keys [:file, :original_source]
    defstruct [:file, :original_source]
  end

  @doc """
  Compiles a list of top-level AST items (the output of
  `Linx.NFT.Parser.parse/2`) into a `%Linx.Netfilter.Ruleset{}`.

  ## Options

    * `:file` — source filename for error messages
      (default `"nofile"`).
    * `:source` — original source binary for snippet rendering
      (default `""`).

  Returns `{:ok, %Ruleset{}}` or `{:error, %ParseError{}}`.
  """
  @spec compile([tuple()], keyword()) ::
          {:ok, Ruleset.t()} | {:error, ParseError.t()}
  def compile(ast_items, opts \\ []) when is_list(ast_items) do
    state = %State{
      file: Keyword.get(opts, :file, "nofile"),
      original_source: Keyword.get(opts, :source, "")
    }

    try do
      rs = Enum.reduce(ast_items, Ruleset.new(), &compile_top(&1, &2, state))
      {:ok, rs}
    rescue
      e in ParseError ->
        {:error, e}

      e in ArgumentError ->
        # Validator-setter raised — convert to a ParseError pointing
        # at the file as a whole, since the underlying error doesn't
        # carry an AST meta. (Per-AST errors come from raise_at!/3
        # below and carry precise locations.)
        {:error,
         %ParseError{
           file: state.file,
           line: 0,
           column: 0,
           snippet: nil,
           message: Exception.message(e)
         }}
    end
  end

  # ===========================================================
  # Top level
  # ===========================================================

  defp compile_top({:table, family, name, body, meta}, rs, state) do
    rs =
      wrap_add!(rs, fn rs -> Ruleset.add_table!(rs, family, name) end, meta, state, "add_table")

    Enum.reduce(body, rs, &compile_table_item(&1, family, name, &2, state))
  end

  defp compile_top({:include, _path, meta}, _rs, state) do
    raise_at!(
      state,
      meta,
      "compiler: `include` is not yet supported (use `parse_file/1`)"
    )
  end

  defp compile_top({:define, _name, _value, _meta}, rs, _state) do
    # Captured by the parser AST; the compiler ignores defines for
    # now (no inline substitution implemented yet). Future: thread
    # a binding env through compile_top/compile_table_item/etc.
    rs
  end

  defp compile_top({:comment, _comment}, rs, _state) do
    # Top-level comments are advisory; nothing to attach them to.
    rs
  end

  defp compile_top({:flush_ruleset, _meta}, rs, _state) do
    # Semantically `flush ruleset` clears the existing kernel state
    # before installing fresh rules. At the value-type layer we
    # always start from `Ruleset.new()` — so the directive is a
    # noop here. (When we push to the kernel, the :replace push
    # mode already does the equivalent via DESTROYTABLE.)
    rs
  end

  # ===========================================================
  # Table-body items
  # ===========================================================

  defp compile_table_item({:chain, name, opts, stmts, meta}, family, table_name, rs, state) do
    chain_opts = compile_chain_opts(opts, family, state, meta)

    rs =
      wrap_add!(
        rs,
        fn rs -> Ruleset.add_chain!(rs, {family, table_name}, name, chain_opts) end,
        meta,
        state,
        "add_chain"
      )

    Enum.reduce(stmts, rs, &compile_rule(&1, family, table_name, name, &2, state))
  end

  defp compile_table_item({:set, name, opts, meta}, family, table_name, rs, state) do
    set = build_set(name, opts, state, meta)

    wrap_add!(
      rs,
      fn rs -> Ruleset.add_set!(rs, {family, table_name}, set) end,
      meta,
      state,
      "add_set"
    )
  end

  defp compile_table_item({:map, name, opts, meta}, family, table_name, rs, state) do
    map = build_map(name, opts, state, meta, :map)

    wrap_add!(
      rs,
      fn rs -> Ruleset.add_map!(rs, {family, table_name}, map) end,
      meta,
      state,
      "add_map"
    )
  end

  defp compile_table_item({:vmap, name, opts, meta}, family, table_name, rs, state) do
    map = build_map(name, opts, state, meta, :vmap)

    wrap_add!(
      rs,
      fn rs -> Ruleset.add_map!(rs, {family, table_name}, map) end,
      meta,
      state,
      "add_vmap"
    )
  end

  defp compile_table_item({:object, kind, _name, _opts, meta}, _family, _table_name, _rs, state) do
    raise_at!(
      state,
      meta,
      "compiler: named `#{kind}` objects are not yet supported by the ~NFT compiler (the pipeline DSL can build them)"
    )
  end

  defp compile_table_item({:flowtable, _name, _opts, meta}, _family, _table_name, _rs, state) do
    raise_at!(
      state,
      meta,
      "compiler: flowtables are not yet supported by the ~NFT compiler (the pipeline DSL can build them)"
    )
  end

  defp compile_table_item({:comment, _}, _family, _table_name, rs, _state), do: rs

  # ===========================================================
  # Chain header
  # ===========================================================

  defp compile_chain_opts(opts, family, state, chain_meta) do
    Enum.flat_map(opts, fn
      {:type, t} -> [type: t]
      {:hook, h} -> [hook: h]
      {:priority, prio} -> [priority: resolve_priority(prio, family, state, chain_meta)]
      {:policy, p} -> [policy: p]
      {:device, dev} -> [device: literal_string!(dev, state)]
      {:comment, c} -> [comment: c]
    end)
  end

  defp resolve_priority({:integer, n, _meta}, _family, _state, _chain_meta), do: n

  defp resolve_priority({:alias, name, offset, meta}, family, state, _chain_meta) do
    name_atom = String.to_atom(name)

    base =
      try do
        Wire.priority_int(family, name_atom)
      rescue
        FunctionClauseError ->
          raise_at!(
            state,
            meta,
            "compiler: unknown priority alias `#{name}` for family `#{family}`"
          )
      end

    base + offset
  end

  # ===========================================================
  # Rule
  # ===========================================================

  defp compile_rule({:rule, stmts, rule_opts, meta}, family, table_name, chain_name, rs, state) do
    exprs = Enum.flat_map(stmts, &compile_stmt(&1, family, state))

    rule_kw =
      rule_opts
      |> Enum.flat_map(fn
        {:tag, t} -> [tag: t]
        {:comment, c} -> [comment: c]
        _ -> []
      end)

    wrap_add!(
      rs,
      fn rs -> Ruleset.add_rule!(rs, {family, table_name}, chain_name, exprs, rule_kw) end,
      meta,
      state,
      "add_rule"
    )
  end

  # ===========================================================
  # Statements → Expr list
  # ===========================================================

  defp compile_stmt({:verdict, kind, _meta}, _family, _state) do
    [Expr.immediate(verdict_from(kind))]
  end

  defp compile_stmt({:match, lhs, op, rhs, _meta}, _family, state) do
    {load_expr, value_kind} = compile_lhs(lhs, state)
    cmp_or_lookup = compile_rhs(rhs, op, value_kind, state)
    List.wrap(load_expr) ++ List.wrap(cmp_or_lookup)
  end

  defp compile_stmt({:counter, _opts, _meta}, _family, _state) do
    [Expr.counter()]
  end

  defp compile_stmt({:log, opts, _meta}, _family, _state) do
    [Expr.log(opts)]
  end

  defp compile_stmt({:reject, opts, _meta}, _family, _state) do
    type =
      case Keyword.get(opts, :with) do
        nil -> :icmp_unreach
        # `reject with tcp reset` etc. — first identifier classifies.
        list -> reject_type_from(list)
      end

    [Expr.reject(type)]
  end

  defp compile_stmt({:nat, :masquerade, _target, flags, _meta}, _family, _state) do
    [Expr.masquerade(flags: flags)]
  end

  defp compile_stmt({:nat, :redirect, target, flags, meta}, _family, state) do
    port = nat_target_port(target, state, meta)

    base =
      if port do
        [
          %Expr{name: :immediate, data: %{dreg: 2, value: <<port::big-16>>}},
          Expr.redirect(reg_proto_min: 2, flags: flags)
        ]
      else
        [Expr.redirect(flags: flags)]
      end

    base
  end

  defp compile_stmt({:nat, :dnat, target, flags, meta}, _family, state) do
    {addr, port} = nat_target!(target, state, meta)
    Expr.dnat_to(addr, port, flags: flags)
  end

  defp compile_stmt({:nat, :snat, target, flags, meta}, _family, state) do
    {addr, port} = nat_target!(target, state, meta)
    Expr.snat_to(addr, port, flags: flags)
  end

  defp compile_stmt({:limit, _rate, _opts, meta}, _family, state) do
    raise_at!(
      state,
      meta,
      "compiler: `limit` statement requires a `%Expr.limit{}` constructor that's not yet implemented"
    )
  end

  defp compile_stmt({:meta_set, _field, _value, meta}, _family, state) do
    raise_at!(
      state,
      meta,
      "compiler: assigning `meta`/`ct` fields (`set` action) requires a setter `%Expr{}` that's not yet implemented"
    )
  end

  defp compile_stmt({op, _kind, _value, _, _} = node, _family, state) when op in [:match] do
    raise_at!(state, lhs_meta(node), "compiler: unexpected statement shape #{inspect(op)}")
  end

  defp compile_stmt(other, _family, state) do
    raise_at!(
      state,
      stmt_meta(other),
      "compiler: unsupported rule statement: #{inspect(elem(other, 0))}"
    )
  end

  defp stmt_meta(tuple), do: elem(tuple, tuple_size(tuple) - 1)
  defp lhs_meta({:match, _, _, _, meta}), do: meta
  defp lhs_meta(_), do: %{line: 0, column: 0}

  # ---- LHS ----

  defp compile_lhs({:payload, header, field, _meta}, state) do
    case payload_dispatch(header, field) do
      {:ok, alias_atom, kind} ->
        {Expr.payload(alias_atom), kind}

      :unknown ->
        raise_at!(
          state,
          %{line: 0, column: 0},
          "compiler: unknown payload field `#{header} #{field}`"
        )
    end
  end

  defp compile_lhs({:meta, field, meta}, state) do
    case meta_kind(field) do
      nil ->
        raise_at!(state, meta, "compiler: unsupported meta field `#{field}`")

      kind ->
        {Expr.meta(field), kind}
    end
  end

  defp compile_lhs({:ct, field, meta}, state) do
    case ct_kind(field) do
      nil ->
        raise_at!(state, meta, "compiler: unsupported ct field `#{field}`")

      kind ->
        {Expr.ct(field), kind}
    end
  end

  defp payload_dispatch(:tcp, :sport), do: {:ok, :tcp_sport, {:int, 2}}
  defp payload_dispatch(:tcp, :dport), do: {:ok, :tcp_dport, {:int, 2}}
  defp payload_dispatch(:udp, :sport), do: {:ok, :udp_sport, {:int, 2}}
  defp payload_dispatch(:udp, :dport), do: {:ok, :udp_dport, {:int, 2}}
  defp payload_dispatch(:ip, :saddr), do: {:ok, :ip_saddr, :ipv4}
  defp payload_dispatch(:ip, :daddr), do: {:ok, :ip_daddr, :ipv4}
  defp payload_dispatch(:ip, :protocol), do: {:ok, :ip_protocol, {:int, 1}}
  defp payload_dispatch(:ip6, :saddr), do: {:ok, :ip6_saddr, :ipv6}
  defp payload_dispatch(:ip6, :daddr), do: {:ok, :ip6_daddr, :ipv6}
  defp payload_dispatch(:icmp, :type), do: {:ok, :icmp_type, {:int, 1}}
  defp payload_dispatch(:icmp, :code), do: {:ok, :icmp_code, {:int, 1}}
  defp payload_dispatch(:icmpv6, :type), do: {:ok, :icmpv6_type, {:int, 1}}
  defp payload_dispatch(:icmpv6, :code), do: {:ok, :icmpv6_code, {:int, 1}}
  defp payload_dispatch(_, _), do: :unknown

  defp meta_kind(:iif), do: {:int, 4}
  defp meta_kind(:oif), do: {:int, 4}
  defp meta_kind(:iifname), do: :ifname
  defp meta_kind(:oifname), do: :ifname
  defp meta_kind(:mark), do: {:int, 4}
  defp meta_kind(:protocol), do: {:int, 2}
  defp meta_kind(:nfproto), do: {:int, 1}
  defp meta_kind(:l4proto), do: {:int, 1}
  defp meta_kind(:length), do: {:int, 4}
  defp meta_kind(:skuid), do: {:int, 4}
  defp meta_kind(:skgid), do: {:int, 4}
  defp meta_kind(_), do: nil

  defp ct_kind(:state), do: :ct_state
  defp ct_kind(:direction), do: {:int, 1}
  defp ct_kind(:mark), do: {:int, 4}
  defp ct_kind(_), do: nil

  # ---- RHS ----

  defp compile_rhs({:set_ref, name, _}, _op, _kind, _state) do
    Expr.lookup(name)
  end

  # ct state with multiple values is a bitmask OR plus bitwise-AND
  # match, NOT a set lookup. Handle before the generic set_inline /
  # list catchalls below.
  defp compile_rhs({:set_inline, elems, meta}, op, :ct_state, state) do
    bits = ct_state_bits_from_elems!(elems, state, meta)
    ct_state_match(op, bits)
  end

  defp compile_rhs({:list, elems, meta}, op, :ct_state, state) do
    bits = ct_state_bits_from_elems!(elems, state, meta)
    ct_state_match(op, bits)
  end

  defp compile_rhs({:set_inline, elems, _}, _op, kind, state) do
    set_key_type = set_key_type_for(kind)
    values = Enum.map(elems, &literal_for_set!(&1, set_key_type, state))
    flags = if Enum.any?(elems, &range_or_cidr?/1), do: [:constant, :interval], else: [:constant]
    Expr.set_literal(values, set_key_type, flags: flags)
  end

  defp compile_rhs({:integer, n, _}, op, {:int, width}, _state) do
    Expr.cmp(op, encode_int(n, width))
  end

  defp compile_rhs({:time, n, _}, op, {:int, width}, _state) do
    Expr.cmp(op, encode_int(n, width))
  end

  defp compile_rhs({:string, s, _}, op, :ifname, _state) do
    Expr.cmp(op, pad_ifname(s))
  end

  defp compile_rhs({:string, s, meta}, op, {:int, _width}, state) do
    case Integer.parse(s) do
      {n, ""} -> compile_rhs({:integer, n, meta}, op, {:int, 4}, state)
      _ -> raise_at!(state, meta, "compiler: expected integer value, got string #{inspect(s)}")
    end
  end

  defp compile_rhs({:address, :ipv4, addr, meta}, op, :ipv4, state) do
    bytes = parse_ipv4!(addr, state, meta)
    Expr.cmp(op, bytes)
  end

  defp compile_rhs({:address, :ipv6, addr, meta}, op, :ipv6, state) do
    bytes = parse_ipv6!(addr, state, meta)
    Expr.cmp(op, bytes)
  end

  defp compile_rhs({:address, :cidr_v4, cidr, meta}, _op, :ipv4, state) do
    {addr, prefix} = split_cidr!(cidr, state, meta)
    addr_bytes = parse_ipv4!(addr, state, meta)
    mask = ipv4_mask(prefix)
    [Expr.bitwise(mask, <<0, 0, 0, 0>>), Expr.cmp(:eq, apply_mask(addr_bytes, mask))]
  end

  defp compile_rhs({:address, :cidr_v6, cidr, meta}, _op, :ipv6, state) do
    {addr, prefix} = split_cidr!(cidr, state, meta)
    addr_bytes = parse_ipv6!(addr, state, meta)
    mask = ipv6_mask(prefix)
    [Expr.bitwise(mask, <<0::128>>), Expr.cmp(:eq, apply_mask(addr_bytes, mask))]
  end

  defp compile_rhs({:range, lo, hi, meta}, _op, {:int, width}, _state) do
    lo_n = literal_int!(lo)
    hi_n = literal_int!(hi)
    # Anonymous set with interval flag.
    Expr.set_literal(
      [{:range, lo_n, hi_n}],
      set_key_type_for({:int, width}),
      flags: [:constant, :interval]
    )
    |> case do
      expr -> expr
    end
    |> tap(fn _ -> _ = meta end)
  end

  defp compile_rhs({:identifier, name, meta}, op, :ct_state, state) do
    # ct state matching is a bitmask check: a packet's state field
    # has at most one bit set, but `ct state X` semantically means
    # "X bit is set", so the kernel-correct shape is
    # bitwise-AND with the state's bit, then cmp_neq_zero. For
    # `ct state != X`, invert the cmp op (cmp_eq_zero).
    bits = ct_state_bits!(String.split(name, ","), state, meta)
    ct_state_match(op, bits)
  end

  defp compile_rhs({:identifier, name, _meta}, op, :ifname, _state) do
    Expr.cmp(op, pad_ifname(name))
  end

  defp compile_rhs({:identifier, name, meta}, op, {:int, width}, state) do
    case parse_int_keyword(name) do
      {:ok, n} ->
        Expr.cmp(op, encode_int(n, width))

      :error ->
        raise_at!(
          state,
          meta,
          "compiler: don't know how to interpret identifier `#{name}` as integer"
        )
    end
  end

  defp compile_rhs({:list, elems, meta}, op, kind, state) do
    # Comma-separated list outside `{}` braces — treat as anon set.
    compile_rhs({:set_inline, elems, meta}, op, kind, state)
  end

  defp compile_rhs(node, _op, kind, state) do
    raise_at!(
      state,
      value_meta(node),
      "compiler: cannot use value #{inspect(node)} with field kind #{inspect(kind)}"
    )
  end

  defp ct_state_bits_from_elems!(elems, state, fallback_meta) do
    Enum.reduce(elems, 0, fn elem, acc ->
      case elem do
        {:identifier, name, _} ->
          case safe_ct_state_bits(String.to_atom(name)) do
            nil ->
              raise_at!(
                state,
                value_meta(elem) || fallback_meta,
                "compiler: unknown ct state `#{name}`"
              )

            n ->
              bor(acc, n)
          end

        other ->
          raise_at!(
            state,
            value_meta(other) || fallback_meta,
            "compiler: ct state element must be a state name, got #{inspect(other)}"
          )
      end
    end)
  end

  defp ct_state_match(:eq, bits) do
    [
      Expr.bitwise(<<bits::big-32>>, <<0::big-32>>),
      Expr.cmp(:neq, <<0::big-32>>)
    ]
  end

  defp ct_state_match(:neq, bits) do
    [
      Expr.bitwise(<<bits::big-32>>, <<0::big-32>>),
      Expr.cmp(:eq, <<0::big-32>>)
    ]
  end

  # ---- Set / value-kind helpers ----

  defp set_key_type_for({:int, 2}), do: :inet_service
  defp set_key_type_for({:int, 4}), do: :mark
  defp set_key_type_for({:int, 1}), do: :inet_proto
  defp set_key_type_for(:ipv4), do: :ipv4_addr
  defp set_key_type_for(:ipv6), do: :ipv6_addr
  defp set_key_type_for(:ifname), do: :ifname
  defp set_key_type_for(:ct_state), do: :ct_state
  defp set_key_type_for(other), do: other

  defp literal_for_set!({:integer, n, _}, _kind, _state), do: n
  defp literal_for_set!({:time, n, _}, _kind, _state), do: n
  defp literal_for_set!({:address, :ipv4, addr, _}, _, _), do: addr
  defp literal_for_set!({:address, :ipv6, addr, _}, _, _), do: addr
  defp literal_for_set!({:address, :cidr_v4, cidr, _}, _, _), do: cidr
  defp literal_for_set!({:address, :cidr_v6, cidr, _}, _, _), do: cidr
  defp literal_for_set!({:string, s, _}, _, _), do: s

  # When the set's key type is an integer-shaped one, identifier
  # elements like `tcp` / `echo-request` / `nd-router-solicit`
  # resolve to their numeric values via parse_int_keyword.
  defp literal_for_set!({:identifier, name, meta} = node, key_type, state)
       when key_type in [:inet_proto, :inet_service, :mark] do
    case parse_int_keyword(name) do
      {:ok, n} ->
        n

      :error ->
        raise_at!(
          state,
          value_meta(node) || meta,
          "compiler: unknown name `#{name}` in #{key_type} set"
        )
    end
  end

  defp literal_for_set!({:identifier, s, _}, _, _), do: s

  defp literal_for_set!({:range, lo, hi, _}, _, _state),
    do: {:range, literal_int!(lo), literal_int!(hi)}

  defp literal_for_set!(node, _kind, state) do
    raise_at!(
      state,
      value_meta(node),
      "compiler: unsupported set element shape: #{inspect(node)}"
    )
  end

  defp literal_int!({:integer, n, _}), do: n
  defp literal_int!({:time, n, _}), do: n

  defp literal_int!(node),
    do: raise_at!(%{file: "?", original_source: ""}, value_meta(node), "expected integer literal")

  defp range_or_cidr?({:range, _, _, _}), do: true
  defp range_or_cidr?({:address, :cidr_v4, _, _}), do: true
  defp range_or_cidr?({:address, :cidr_v6, _, _}), do: true
  defp range_or_cidr?(_), do: false

  # ---- Sets / Maps construction ----

  defp build_set(name, opts, state, meta) do
    type =
      case Keyword.get(opts, :type) do
        nil ->
          raise_at!(state, meta, "compiler: set `#{name}` missing required `type` declaration")

        {:concat, _} ->
          raise_at!(
            state,
            meta,
            "compiler: concatenated set types are not yet supported by the ~NFT compiler"
          )

        atom when is_atom(atom) ->
          atom

        other ->
          raise_at!(state, meta, "compiler: unsupported set type spec #{inspect(other)}")
      end

    flags = Keyword.get(opts, :flags, [])

    elements =
      opts
      |> Keyword.get(:elements, [])
      |> Enum.map(&literal_for_set!(&1, type, state))

    Set.new!(name,
      key_type: type,
      flags: flags,
      elements: elements,
      timeout: literal_int_or_nil(opts[:timeout]),
      gc_interval: literal_int_or_nil(opts[:gc_interval]),
      size: literal_int_or_nil(opts[:size]),
      comment: opts[:comment]
    )
  end

  defp build_map(name, opts, state, meta, kind) do
    {key_type, data_type} =
      case Keyword.get(opts, :type) do
        {:map_type, k, d} when is_atom(k) and is_atom(d) ->
          {k, d}

        {:map_type, _k, _d} ->
          raise_at!(
            state,
            meta,
            "compiler: concatenated map keys are not yet supported by the ~NFT compiler"
          )

        other ->
          raise_at!(
            state,
            meta,
            "compiler: `#{kind}` requires `type KEY : DATA`; got #{inspect(other)}"
          )
      end

    if kind == :vmap and data_type != :verdict do
      raise_at!(
        state,
        meta,
        "compiler: vmap data type must be `verdict`, got #{inspect(data_type)}"
      )
    end

    elements =
      opts
      |> Keyword.get(:elements, [])
      |> Enum.map(&build_map_element(&1, state))

    NMap.new!(name,
      key_type: key_type,
      data_type: data_type,
      flags: Keyword.get(opts, :flags, []),
      elements: elements,
      timeout: literal_int_or_nil(opts[:timeout]),
      gc_interval: literal_int_or_nil(opts[:gc_interval]),
      size: literal_int_or_nil(opts[:size]),
      comment: opts[:comment]
    )
  end

  defp build_map_element({:map_elem, key, {:verdict, vk, _vmeta}, _emeta}, _state) do
    {literal_simple(key), verdict_from(vk)}
  end

  defp build_map_element({:map_elem, key, value, _emeta}, _state) do
    {literal_simple(key), literal_simple(value)}
  end

  defp build_map_element(other, state) do
    raise_at!(
      state,
      value_meta(other),
      "compiler: map element must be `KEY : VALUE`, got #{inspect(other)}"
    )
  end

  defp literal_simple({:integer, n, _}), do: n
  defp literal_simple({:string, s, _}), do: s
  defp literal_simple({:address, _, v, _}), do: v
  defp literal_simple({:identifier, s, _}), do: s
  defp literal_simple(other), do: other

  defp literal_int_or_nil(nil), do: nil
  defp literal_int_or_nil({:integer, n, _}), do: n
  defp literal_int_or_nil({:time, n, _}), do: n
  defp literal_int_or_nil(_), do: nil

  defp literal_string!({:string, s, _}, _state), do: s
  defp literal_string!({:identifier, s, _}, _state), do: s

  defp literal_string!(node, state),
    do: raise_at!(state, value_meta(node), "compiler: expected string value")

  # ===========================================================
  # Verdicts
  # ===========================================================

  defp verdict_from(:accept), do: Verdict.accept()
  defp verdict_from(:drop), do: Verdict.drop()
  defp verdict_from(:continue), do: Verdict.continue()
  defp verdict_from(:return), do: Verdict.return()
  defp verdict_from(:queue), do: Verdict.queue(0)
  defp verdict_from({:jump, chain}), do: Verdict.jump(chain)
  defp verdict_from({:goto, chain}), do: Verdict.goto(chain)
  defp verdict_from(other), do: raise(ArgumentError, "unknown verdict #{inspect(other)}")

  defp reject_type_from([]), do: :icmp_unreach

  defp reject_type_from([{:identifier, "tcp", _} | _]), do: :tcp_reset
  defp reject_type_from([{:identifier, "icmp", _} | _]), do: :icmp_unreach
  defp reject_type_from([{:identifier, "icmpx", _} | _]), do: :icmpx_unreach
  defp reject_type_from(_), do: :icmp_unreach

  # ===========================================================
  # NAT helpers
  # ===========================================================

  defp nat_target!(nil, state, meta) do
    raise_at!(state, meta, "compiler: NAT statement missing `to <address>[:port]` target")
  end

  defp nat_target!({:address, :ipv4, addr, _}, _state, _meta), do: {addr, nil}
  defp nat_target!({:address, :ipv6, addr, _}, _state, _meta), do: {addr, nil}
  defp nat_target!({:string, addr, _}, _state, _meta), do: {addr, nil}

  defp nat_target!({:range, lo, hi, _}, _state, _meta) do
    # `dnat to <ip>:<port_lo>-<port_hi>` — port range with no addr.
    {nil, {literal_int!(lo), literal_int!(hi)}}
  end

  defp nat_target!({:integer, port, _}, _state, _meta), do: {nil, port}

  defp nat_target!(other, state, meta) do
    raise_at!(state, meta, "compiler: unsupported NAT target shape: #{inspect(other)}")
  end

  defp nat_target_port({:integer, n, _}, _state, _meta), do: n
  defp nat_target_port(nil, _state, _meta), do: nil

  defp nat_target_port(other, state, meta) do
    raise_at!(
      state,
      meta,
      "compiler: redirect target must be a port integer, got: #{inspect(other)}"
    )
  end

  # ===========================================================
  # Address parsing
  # ===========================================================

  defp parse_ipv4!(addr, state, meta) do
    case Linx.IP.parse(addr) do
      {:ok, %Linx.IP{family: :inet, bytes: bytes}} -> bytes
      _ -> raise_at!(state, meta, "compiler: invalid IPv4 address `#{addr}`")
    end
  end

  defp parse_ipv6!(addr, state, meta) do
    case Linx.IP.parse(addr) do
      {:ok, %Linx.IP{family: :inet6, bytes: bytes}} -> bytes
      _ -> raise_at!(state, meta, "compiler: invalid IPv6 address `#{addr}`")
    end
  end

  defp split_cidr!(cidr, state, meta) do
    case String.split(cidr, "/", parts: 2) do
      [addr, prefix_str] ->
        case Integer.parse(prefix_str) do
          {p, ""} -> {addr, p}
          _ -> raise_at!(state, meta, "compiler: invalid CIDR prefix in `#{cidr}`")
        end

      _ ->
        raise_at!(state, meta, "compiler: invalid CIDR `#{cidr}`")
    end
  end

  defp ipv4_mask(p) when p in 0..32 do
    bits = mask_bits(p, 32)
    <<bits::big-32>>
  end

  defp ipv6_mask(p) when p in 0..128 do
    bits = mask_bits(p, 128)
    <<bits::big-128>>
  end

  # All-ones in the top `prefix` bits of a `total`-bit field.
  defp mask_bits(0, _total), do: 0

  defp mask_bits(prefix, total) when prefix <= total do
    all = bsl(1, total) - 1
    keep_low = bsl(1, total - prefix) - 1
    band(all, bnot(keep_low))
  end

  defp apply_mask(addr_bytes, mask_bytes) do
    addr_int = :binary.decode_unsigned(addr_bytes)
    mask_int = :binary.decode_unsigned(mask_bytes)
    masked = band(addr_int, mask_int)
    n_bits = byte_size(addr_bytes) * 8
    <<masked::size(n_bits)>>
  end

  # ===========================================================
  # Misc helpers
  # ===========================================================

  defp encode_int(n, 1), do: <<n>>
  defp encode_int(n, 2), do: <<n::big-16>>
  defp encode_int(n, 4), do: <<n::big-32>>
  defp encode_int(n, 8), do: <<n::big-64>>

  defp pad_ifname(s) when is_binary(s) do
    # Linux IFNAMSIZ == 16; nft compares against a 16-byte zero-
    # padded buffer.
    padded = s <> String.duplicate(<<0>>, 16 - byte_size(s))
    binary_part(padded, 0, 16)
  end

  # ct state takes a comma-separated list of state atoms whose
  # bits are OR-ed together for the comparison value.
  defp ct_state_bits!(names, state, meta) do
    Enum.reduce(names, 0, fn raw, acc ->
      name = raw |> String.trim() |> String.to_atom()

      case safe_ct_state_bits(name) do
        nil -> raise_at!(state, meta, "compiler: unknown ct state `#{raw}`")
        n when is_integer(n) -> bor(acc, n)
      end
    end)
  end

  defp safe_ct_state_bits(name) do
    try do
      Wire.ct_state_bits(name)
    rescue
      _ -> nil
    end
  end

  # IP protocol numbers (used by `ip protocol NAME` matches and as
  # 1-byte set elements).
  defp parse_int_keyword("tcp"), do: {:ok, 6}
  defp parse_int_keyword("udp"), do: {:ok, 17}
  defp parse_int_keyword("icmp"), do: {:ok, 1}
  defp parse_int_keyword("icmpv6"), do: {:ok, 58}

  # ICMPv6 type values (RFC 4443 + ND from RFC 4861 + extensions).
  # These are unique to the ICMPv6 namespace; ICMPv4-specific
  # symbolic names (`echo-request` = 8, etc.) are NOT supported here
  # yet — ICMPv4 uses are rare and most authors write the integer.
  defp parse_int_keyword("destination-unreachable"), do: {:ok, 1}
  defp parse_int_keyword("packet-too-big"), do: {:ok, 2}
  defp parse_int_keyword("time-exceeded"), do: {:ok, 3}
  defp parse_int_keyword("parameter-problem"), do: {:ok, 4}
  defp parse_int_keyword("echo-request"), do: {:ok, 128}
  defp parse_int_keyword("echo-reply"), do: {:ok, 129}
  defp parse_int_keyword("mld-listener-query"), do: {:ok, 130}
  defp parse_int_keyword("mld-listener-report"), do: {:ok, 131}
  defp parse_int_keyword("mld-listener-done"), do: {:ok, 132}
  defp parse_int_keyword("nd-router-solicit"), do: {:ok, 133}
  defp parse_int_keyword("nd-router-advert"), do: {:ok, 134}
  defp parse_int_keyword("nd-neighbor-solicit"), do: {:ok, 135}
  defp parse_int_keyword("nd-neighbor-advert"), do: {:ok, 136}
  defp parse_int_keyword("redirect"), do: {:ok, 137}
  defp parse_int_keyword("router-renumbering"), do: {:ok, 138}
  defp parse_int_keyword("ind-neighbor-solicit"), do: {:ok, 141}
  defp parse_int_keyword("ind-neighbor-advert"), do: {:ok, 142}
  defp parse_int_keyword("mld2-listener-report"), do: {:ok, 143}

  defp parse_int_keyword(_), do: :error

  defp value_meta({_, _, meta}) when is_map(meta), do: meta
  defp value_meta({_, _, _, meta}) when is_map(meta), do: meta
  defp value_meta({_, _, _, _, meta}) when is_map(meta), do: meta
  defp value_meta(_), do: %{line: 0, column: 0}

  # ===========================================================
  # Error helpers
  # ===========================================================

  defp wrap_add!(rs, fun, meta, state, op) do
    fun.(rs)
  rescue
    e in ArgumentError ->
      raise_at!(state, meta, "compiler: `#{op}` rejected by validator: #{Exception.message(e)}")
  end

  defp raise_at!(state, meta, msg) do
    line = Map.get(meta || %{}, :line, 0)
    column = Map.get(meta || %{}, :column, 0)

    ParseError.raise_syntax_error!(
      %{
        file: state.file,
        line: line,
        column: column,
        snippet: snippet_for(state.original_source, line)
      },
      msg
    )
  end

  defp snippet_for("", _line), do: nil
  defp snippet_for(_source, line) when line < 1, do: nil

  defp snippet_for(source, line) do
    source
    |> String.split(["\r\n", "\n", "\r"])
    |> Enum.at(line - 1)
  end
end
