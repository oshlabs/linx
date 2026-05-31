defmodule Linx.NFT.RuntimeCompiler do
  @moduledoc """
  AST → Elixir AST (quoted code) translation for `~NFT` sigil
  bodies that contain `\#{...}` interpolations.

  This is the runtime-emit sibling of `Linx.NFT.Compiler`. Where
  the static compiler walks the AST and calls the validator-setter
  functions on `Linx.Netfilter.Ruleset` directly to produce a
  ready-made `%Ruleset{}` value at *compile time*, the runtime
  compiler walks the same AST and produces an Elixir AST that,
  when evaluated at *runtime*, calls the same validator-setter
  functions to produce the `%Ruleset{}`. The two paths are
  semantically identical for static sigils; the runtime emit path
  exists so the sigil can splice the values of interpolated
  Elixir expressions into the right positions.

  The macro picks which path to use based on whether any
  `:elixir_expr` tokens were produced by the tokenizer.

  ## Static portions vs runtime portions

  AST nodes outside the value-position of a match (i.e. table
  family, chain name, hook, priority, …) **must** be static —
  the parser produces the same AST for them, and the runtime
  compiler emits them as literal values via `Macro.escape/1`.

  AST nodes at value positions inside matches CAN be `:elixir_expr`.
  When they are, the runtime compiler:

    1. Parses the raw Elixir source of the interpolation with
       `Code.string_to_quoted!/1` to recover the original AST.
    2. Emits a call to `Linx.NFT.Runtime.cmp!/3` (or one of the
       other encoders) passing the parsed Elixir AST + the field
       kind the surrounding nft syntax expects.

  Result: at runtime, the Elixir expression is evaluated in the
  caller's scope, encoded per the typed field, and spliced into
  the rule's expression list.

  ## Scope

  Mirrors `Linx.NFT.Compiler`'s scope. Anything the static
  compiler rejects (limit / meta-set / named objects / flowtables
  / concat keys / includes) the runtime compiler also rejects,
  with the same error message. Interpolation is supported at:

    * Match RHS where the field kind is `{:int, _}` / `:ipv4` /
      `:ipv6` / `:ifname`.

  Interpolations in keyword positions (table name, chain name,
  family, hook, etc.) raise a clear `ParseError` — they'd require
  case-by-case wiring through each validator-setter.
  """

  alias Linx.NFT.ParseError
  alias Linx.Netfilter.{Verdict, Wire}

  defmodule State do
    @moduledoc false
    @enforce_keys [:file, :original_source]
    defstruct [:file, :original_source]
  end

  @doc """
  Emits Elixir AST that, when evaluated, returns a
  `%Linx.Netfilter.Ruleset{}`. Returns `{:ok, quoted}` or
  `{:error, %ParseError{}}`.
  """
  @spec emit([tuple()], keyword()) ::
          {:ok, Macro.t()} | {:error, ParseError.t()}
  def emit(ast_items, opts \\ []) when is_list(ast_items) do
    state = %State{
      file: Keyword.get(opts, :file, "nofile"),
      original_source: Keyword.get(opts, :source, "")
    }

    try do
      rs_var = Macro.var(:rs, __MODULE__)
      steps = Enum.flat_map(ast_items, &build_top(&1, rs_var, state))

      body =
        quote do
          unquote(rs_var) = Linx.Netfilter.Ruleset.new()
          unquote_splicing(steps)
          unquote(rs_var)
        end

      {:ok, body}
    rescue
      e in ParseError -> {:error, e}
    end
  end

  # ===========================================================
  # Top-level items
  # ===========================================================

  defp build_top({:table, family, name, body, _meta}, rs_var, state) do
    table_step =
      quote do
        unquote(rs_var) =
          Linx.Netfilter.Ruleset.add_table!(unquote(rs_var), unquote(family), unquote(name))
      end

    body_steps = Enum.flat_map(body, &build_table_item(&1, family, name, rs_var, state))
    [table_step | body_steps]
  end

  defp build_top({:include, _path, meta}, _rs_var, state) do
    raise_at!(
      state,
      meta,
      "compiler: `include` is not yet supported (use `Linx.NFT.parse_file/1` instead)"
    )
  end

  defp build_top({:define, _name, _value, _meta}, _rs_var, _state), do: []

  defp build_top({:comment, _}, _rs_var, _state), do: []

  defp build_top({:flush_ruleset, _meta}, _rs_var, _state), do: []

  # ===========================================================
  # Table-body items
  # ===========================================================

  defp build_table_item({:chain, name, opts, stmts, meta}, family, table_name, rs_var, state) do
    chain_opts = static_chain_opts(opts, family, state, meta)

    chain_step =
      quote do
        unquote(rs_var) =
          Linx.Netfilter.Ruleset.add_chain!(
            unquote(rs_var),
            {unquote(family), unquote(table_name)},
            unquote(name),
            unquote(chain_opts)
          )
      end

    rule_steps =
      Enum.map(stmts, &build_rule(&1, family, table_name, name, rs_var, state))

    [chain_step | rule_steps]
  end

  defp build_table_item({:set, _name, _opts, meta}, _family, _table_name, _rs_var, state) do
    raise_at!(
      state,
      meta,
      "compiler: set declarations inside `~NFT` sigils with interpolation are not yet supported"
    )
  end

  defp build_table_item({:map, _name, _opts, meta}, _family, _table_name, _rs_var, state) do
    raise_at!(
      state,
      meta,
      "compiler: map declarations inside `~NFT` sigils with interpolation are not yet supported"
    )
  end

  defp build_table_item({:vmap, _name, _opts, meta}, _family, _table_name, _rs_var, state) do
    raise_at!(
      state,
      meta,
      "compiler: vmap declarations inside `~NFT` sigils with interpolation are not yet supported"
    )
  end

  defp build_table_item({:object, kind, _name, _opts, meta}, _f, _t, _rs, state) do
    raise_at!(
      state,
      meta,
      "compiler: named `#{kind}` objects are not yet supported by the ~NFT compiler"
    )
  end

  defp build_table_item({:flowtable, _name, _opts, meta}, _f, _t, _rs, state) do
    raise_at!(state, meta, "compiler: flowtables are not yet supported by the ~NFT compiler")
  end

  defp build_table_item({:comment, _}, _f, _t, _rs, _state), do: []

  # ===========================================================
  # Chain header — must be static
  # ===========================================================

  defp static_chain_opts(opts, family, state, chain_meta) do
    Enum.flat_map(opts, fn
      {:type, t} -> [type: t]
      {:hook, h} -> [hook: h]
      {:priority, prio} -> [priority: resolve_priority(prio, family, state, chain_meta)]
      {:policy, p} -> [policy: p]
      {:device, dev} -> [device: literal_string!(dev, state, chain_meta)]
      {:comment, c} -> [comment: c]
    end)
  end

  defp resolve_priority({:integer, n, _}, _family, _state, _cmeta), do: n

  defp resolve_priority({:alias, name, offset, meta}, family, state, _cmeta) do
    atom = String.to_atom(name)

    base =
      try do
        Wire.priority_int(family, atom)
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

  defp literal_string!({:string, s, _}, _state, _meta), do: s
  defp literal_string!({:identifier, s, _}, _state, _meta), do: s

  defp literal_string!(node, state, meta) do
    raise_at!(state, value_meta(node) || meta, "compiler: expected static string here")
  end

  # ===========================================================
  # Rules
  # ===========================================================

  defp build_rule({:rule, stmts, rule_opts, _meta}, family, table_name, chain_name, rs_var, state) do
    expr_asts = Enum.flat_map(stmts, &build_stmt(&1, state))
    rule_kw = static_rule_opts(rule_opts)

    quote do
      unquote(rs_var) =
        Linx.Netfilter.Ruleset.add_rule!(
          unquote(rs_var),
          {unquote(family), unquote(table_name)},
          unquote(chain_name),
          [unquote_splicing(expr_asts)],
          unquote(rule_kw)
        )
    end
  end

  defp static_rule_opts(opts) do
    Enum.flat_map(opts, fn
      {:tag, t} -> [tag: t]
      {:comment, c} -> [comment: c]
      _ -> []
    end)
  end

  # ===========================================================
  # Statements → list of quoted Expr ASTs
  # ===========================================================

  defp build_stmt({:verdict, kind, _meta}, _state) do
    v = verdict_from(kind)
    [quote(do: Linx.Netfilter.Expr.immediate(unquote(Macro.escape(v))))]
  end

  defp build_stmt({:match, lhs, op, rhs, _meta}, state) do
    {load_quoted, value_kind} = build_lhs(lhs, state)
    cmp_quoted = build_rhs(rhs, op, value_kind, state)
    [load_quoted, cmp_quoted]
  end

  defp build_stmt({:counter, _opts, _meta}, _state) do
    [quote(do: Linx.Netfilter.Expr.counter())]
  end

  defp build_stmt({:log, opts, _meta}, _state) do
    [quote(do: Linx.Netfilter.Expr.log(unquote(opts)))]
  end

  defp build_stmt({:reject, _opts, _meta}, _state) do
    [quote(do: Linx.Netfilter.Expr.reject())]
  end

  defp build_stmt({:nat, :masquerade, _target, flags, _meta}, _state) do
    [quote(do: Linx.Netfilter.Expr.masquerade(flags: unquote(flags)))]
  end

  defp build_stmt({:nat, kind, target, flags, _meta}, _state) when kind in [:dnat, :snat] do
    target_quoted = build_nat_target(target)

    case kind do
      :dnat ->
        [
          quote(
            do: Linx.Netfilter.Expr.dnat_to(unquote(target_quoted), nil, flags: unquote(flags))
          )
        ]

      :snat ->
        [
          quote(
            do: Linx.Netfilter.Expr.snat_to(unquote(target_quoted), nil, flags: unquote(flags))
          )
        ]
    end
  end

  defp build_stmt(other, state) do
    raise_at!(
      state,
      value_meta(other) || %{line: 0, column: 0},
      "compiler: rule statement #{inspect(elem(other, 0))} is not yet supported with interpolation"
    )
  end

  # NAT target: can be a static address or an interpolation. For
  # simplicity, encode at runtime through `Linx.NFT.Runtime.encode_ipv4!/1`
  # so the same helper handles all input shapes.
  defp build_nat_target({:address, :ipv4, addr, _meta}), do: addr
  defp build_nat_target({:address, :ipv6, addr, _meta}), do: addr
  defp build_nat_target({:string, s, _meta}), do: s

  defp build_nat_target({:elixir_expr, raw, meta}) do
    expr_ast = parse_elixir_or_raise!(raw, meta)
    expr_ast
  end

  defp build_nat_target(nil), do: nil

  # ---- LHS (always static for matches in N8e) ----

  defp build_lhs({:payload, header, field, _meta}, state) do
    case payload_dispatch(header, field) do
      {:ok, alias_atom, kind} ->
        {quote(do: Linx.Netfilter.Expr.payload(unquote(alias_atom))), kind}

      :unknown ->
        raise_at!(
          state,
          %{line: 0, column: 0},
          "compiler: unknown payload field `#{header} #{field}`"
        )
    end
  end

  defp build_lhs({:meta, field, meta}, state) do
    case meta_kind(field) do
      nil -> raise_at!(state, meta, "compiler: unsupported meta field `#{field}`")
      kind -> {quote(do: Linx.Netfilter.Expr.meta(unquote(field))), kind}
    end
  end

  defp build_lhs({:ct, field, meta}, state) do
    case ct_kind(field) do
      nil -> raise_at!(state, meta, "compiler: unsupported ct field `#{field}`")
      kind -> {quote(do: Linx.Netfilter.Expr.ct(unquote(field))), kind}
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
  defp payload_dispatch(_, _), do: :unknown

  defp meta_kind(:iif), do: {:int, 4}
  defp meta_kind(:oif), do: {:int, 4}
  defp meta_kind(:iifname), do: :ifname
  defp meta_kind(:oifname), do: :ifname
  defp meta_kind(:mark), do: {:int, 4}
  defp meta_kind(:protocol), do: {:int, 2}
  defp meta_kind(:nfproto), do: {:int, 1}
  defp meta_kind(:l4proto), do: {:int, 1}
  defp meta_kind(_), do: nil

  defp ct_kind(:state), do: :ct_state
  defp ct_kind(:mark), do: {:int, 4}
  defp ct_kind(_), do: nil

  # ---- RHS — the only place :elixir_expr currently lands ----

  defp build_rhs({:elixir_expr, raw, meta}, op, value_kind, _state) do
    expr_ast = parse_elixir_or_raise!(raw, meta)

    quote do
      Linx.NFT.Runtime.cmp!(unquote(op), unquote(expr_ast), unquote(Macro.escape(value_kind)))
    end
  end

  defp build_rhs({:integer, n, _}, op, {:int, w}, _state) do
    bytes = encode_int_static(n, w)
    quote(do: Linx.Netfilter.Expr.cmp(unquote(op), unquote(bytes)))
  end

  defp build_rhs({:address, :ipv4, addr, meta}, op, :ipv4, state) do
    bytes = parse_ipv4!(addr, state, meta)
    quote(do: Linx.Netfilter.Expr.cmp(unquote(op), unquote(bytes)))
  end

  defp build_rhs({:address, :ipv6, addr, meta}, op, :ipv6, state) do
    bytes = parse_ipv6!(addr, state, meta)
    quote(do: Linx.Netfilter.Expr.cmp(unquote(op), unquote(bytes)))
  end

  defp build_rhs({:string, s, _meta}, op, :ifname, _state) do
    bytes = pad_ifname(s)
    quote(do: Linx.Netfilter.Expr.cmp(unquote(op), unquote(bytes)))
  end

  defp build_rhs({:identifier, name, _meta}, op, :ifname, _state) do
    bytes = pad_ifname(name)
    quote(do: Linx.Netfilter.Expr.cmp(unquote(op), unquote(bytes)))
  end

  defp build_rhs({:set_ref, name, _}, _op, _kind, _state) do
    quote(do: Linx.Netfilter.Expr.lookup(unquote(name)))
  end

  defp build_rhs(node, _op, kind, state) do
    raise_at!(
      state,
      value_meta(node) || %{line: 0, column: 0},
      "compiler: cannot use value #{inspect(node)} with field kind #{inspect(kind)} in the runtime-emit path"
    )
  end

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

  # ===========================================================
  # Static helpers — shared with the static Compiler
  # ===========================================================

  defp encode_int_static(n, 1), do: <<n>>
  defp encode_int_static(n, 2), do: <<n::big-16>>
  defp encode_int_static(n, 4), do: <<n::big-32>>
  defp encode_int_static(n, 8), do: <<n::big-64>>

  defp pad_ifname(s) when is_binary(s) do
    cond do
      byte_size(s) == 16 -> s
      byte_size(s) < 16 -> s <> :binary.copy(<<0>>, 16 - byte_size(s))
      true -> binary_part(s, 0, 16)
    end
  end

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

  defp parse_elixir_or_raise!(raw, meta) do
    case Code.string_to_quoted(raw,
           file: Map.get(meta, :file, "nofile"),
           line: Map.get(meta, :line, 1),
           column: Map.get(meta, :column, 1)
         ) do
      {:ok, ast} ->
        ast

      {:error, {_loc, msg, _rest}} ->
        raise ParseError,
          file: Map.get(meta, :file, "nofile"),
          line: Map.get(meta, :line, 1),
          column: Map.get(meta, :column, 1),
          snippet: nil,
          message: "compiler: Elixir interpolation didn't parse: #{inspect(msg)}"
    end
  end

  defp value_meta({_, _, meta}) when is_map(meta), do: meta
  defp value_meta({_, _, _, meta}) when is_map(meta), do: meta
  defp value_meta({_, _, _, _, meta}) when is_map(meta), do: meta
  defp value_meta(_), do: nil

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
