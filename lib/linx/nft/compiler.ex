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
  `docs/netfilter/netfilter-examples.md`:

    * **Tables** in every family, with optional `comment`.
    * **Chains** with base headers (`type`/`hook`/`priority`/
      `policy`/`device`) and rules.
    * **Rules** with tag + comment, comprising matches and a
      terminal verdict (plus optional `counter` / `log` / NAT /
      `reject`).
    * **Matches** on the common headers — `tcp/udp dport/sport`
      against integer / range / inline-set / `@set_ref`,
      `ip/ip6 saddr/daddr` against address / CIDR / `@set_ref`,
      `ip protocol`, `ip6 nexthdr/hoplimit`, `icmp/icmpv6
      type/code` (with per-protocol symbolic names),
      `meta iif/oif` (by index or name, resolved at compile time
      like nft), `meta iifname/oifname/mark`, `ct state`.
    * **Verdicts** — accept / drop / continue / return / queue /
      `jump <chain>` / `goto <chain>` / `reject [with ...]`.
    * **Verdict maps** — `tcp dport vmap @named` and inline
      anonymous `ct state vmap { established : accept, ... }`.
    * **Actions** — `counter` (anonymous or `counter name "obj"`),
      `log` (prefix/group/snaplen/queue-threshold/flags),
      `limit rate [over] N/unit [burst ...]`,
      `dnat to <addr>[:port]`, `snat to`, `masquerade`,
      `redirect`.
    * **Sets / maps / vmaps** — declarations with `type`, `flags`,
      `timeout`, `gc-interval`, `size`, `elements`.
    * **Named counter objects** — table-level `counter name { … }`
      declarations plus `counter name` objref statements.
    * **`define` / `$var`** — top-level defines with parse-time
      substitution, duplicate-define errors, and did-you-mean
      suggestions on unknown variables.

  ## Not yet supported (raises a clear ParseError)

    * `meta mark set`, `ct ... set` — no setter `%Expr{}` yet on
      the Linx side. Pipeline DSL can construct them; the compiler
      will pick them up once they're added.
    * Named `quota` / `limit` / ct-helper objects — the `%Object{}`
      data shapes and NFTA_OBJ_DATA encodings land per kind
      (`:counter` shipped first).
    * Concatenated selectors and set elements (`a . b`) — parse
      into `{:concat_lhs, …}` / `{:concat, …}` nodes; lowering
      waits for the pipapo/concat backend work (NFT-PLAN.md
      Phase 6).
    * Flowtables.
    * `include` — file-merging is not yet implemented.
    * `\#{...}` interpolation — only meaningful from the
      `~NFT` sigil; the compiler is called from there with a
      separate path that emits runtime code.

  See `NFT-PLAN.md` for the full parity roadmap.

  Each deferred case raises `Linx.NFT.ParseError` pointing at the
  AST node's source location with a message naming the missing
  feature, so users see exactly what the parser accepted but the
  compiler hasn't wired up yet.
  """

  alias Linx.NFT.ParseError
  alias Linx.Netfilter.{Expr, Ruleset, Set, Verdict, Wire}
  alias Linx.Netfilter.Map, as: NMap

  import Bitwise

  # ICMP / ICMPv6 type namespaces collide (`echo-request` is 8 in
  # ICMPv4 but 128 in ICMPv6), so symbolic names are resolved
  # against the LHS field's kind — the same context-driven
  # `symbol_parse` discipline nft's evaluate.c uses — and the value
  # then flows through the generic 1-byte-integer path.
  @icmp_type_names %{
    "echo-reply" => 0,
    "destination-unreachable" => 3,
    "source-quench" => 4,
    "redirect" => 5,
    "echo-request" => 8,
    "router-advertisement" => 9,
    "router-solicitation" => 10,
    "time-exceeded" => 11,
    "parameter-problem" => 12,
    "timestamp-request" => 13,
    "timestamp-reply" => 14,
    "info-request" => 15,
    "info-reply" => 16,
    "address-mask-request" => 17,
    "address-mask-reply" => 18
  }

  @icmpv6_type_names %{
    "destination-unreachable" => 1,
    "packet-too-big" => 2,
    "time-exceeded" => 3,
    "parameter-problem" => 4,
    "echo-request" => 128,
    "echo-reply" => 129,
    "mld-listener-query" => 130,
    "mld-listener-report" => 131,
    "mld-listener-done" => 132,
    "nd-router-solicit" => 133,
    "nd-router-advert" => 134,
    "nd-neighbor-solicit" => 135,
    "nd-neighbor-advert" => 136,
    "redirect" => 137,
    "router-renumbering" => 138,
    "ind-neighbor-solicit" => 141,
    "ind-neighbor-advert" => 142,
    "mld2-listener-report" => 143
  }

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
      ast_items = resolve_defines(ast_items, state)
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

  # Includes are resolved (and spliced out) by `Linx.NFT.parse/2`
  # before compilation; one reaching the compiler means the sigil
  # path, where a file include inside inline Elixir source has no
  # sensible base directory.
  defp compile_top({:include, _path, meta}, _rs, state) do
    raise_at!(
      state,
      meta,
      "compiler: `include` is not supported inside the ~NFT sigil — " <>
        "use Linx.NFT.parse_file/2 for file-based rulesets"
    )
  end

  defp compile_top({:define, _name, _value, _meta}, rs, _state) do
    # Already consumed by resolve_defines/2 — nothing left to emit.
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
  # define / $var resolution
  # ===========================================================

  # nft binds `define` names to UNEVALUATED expressions and
  # resolves `$var` references during parsing; duplicate defines in
  # the same scope are an error (`redefine` overrides — not
  # supported yet). We do the same as a pre-pass over the AST:
  # collect top-level defines in order (later defines may reference
  # earlier ones), then substitute every `{:var_ref, name, meta}`
  # node. The substituted value keeps the USE site's location so
  # type errors point where the variable was used.
  defp resolve_defines(items, state) do
    bindings =
      Enum.reduce(items, %{}, fn
        {:define, name, value, meta}, acc ->
          if Map.has_key?(acc, name) do
            raise_at!(
              state,
              meta,
              "compiler: redefinition of `#{name}` (defined earlier in this file)"
            )
          end

          {:ok, resolved} = substitute_vars(value, acc, state)
          Map.put(acc, name, resolved)

        _other, acc ->
          acc
      end)

    {:ok, resolved} = substitute_vars(items, bindings, state)
    resolved
  end

  defp substitute_vars({:var_ref, name, meta}, bindings, state) do
    case Map.fetch(bindings, name) do
      {:ok, value} ->
        {:ok, re_meta(value, meta)}

      :error ->
        suggestion =
          bindings
          |> Map.keys()
          |> Enum.max_by(&String.jaro_distance(&1, name), fn -> nil end)
          |> case do
            nil ->
              ""

            best ->
              if String.jaro_distance(best, name) > 0.7,
                do: " — did you mean `$#{best}`?",
                else: ""
          end

        raise_at!(state, meta, "compiler: undefined variable `$#{name}`#{suggestion}")
    end
  end

  defp substitute_vars(list, bindings, state) when is_list(list) do
    {:ok, Enum.map(list, fn item -> elem(substitute_vars(item, bindings, state), 1) end)}
  end

  defp substitute_vars(tuple, bindings, state) when is_tuple(tuple) do
    {:ok,
     tuple
     |> Tuple.to_list()
     |> Enum.map(fn item -> elem(substitute_vars(item, bindings, state), 1) end)
     |> List.to_tuple()}
  end

  defp substitute_vars(other, _bindings, _state), do: {:ok, other}

  # Point the substituted value's location at the use site.
  defp re_meta(tuple, meta) when is_tuple(tuple) do
    last = tuple_size(tuple) - 1

    case elem(tuple, last) do
      %{line: _, column: _} -> put_elem(tuple, last, meta)
      _ -> tuple
    end
  end

  defp re_meta(other, _meta), do: other

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

  defp compile_table_item({:object, :counter, name, opts, meta}, family, table_name, rs, state) do
    data = %{
      packets: object_int_opt(opts, :packets, state),
      bytes: object_int_opt(opts, :bytes, state)
    }

    {:ok, obj} = Linx.Netfilter.Object.new(:counter, name, data)

    wrap_add!(
      rs,
      fn rs -> Ruleset.add_object!(rs, {family, table_name}, obj) end,
      meta,
      state,
      "add_object"
    )
  end

  defp compile_table_item({:object, :quota, name, opts, meta}, family, table_name, rs, state) do
    data = %{
      bytes: Keyword.fetch!(opts, :bytes),
      over: Keyword.get(opts, :over, false),
      used: Keyword.get(opts, :used, 0)
    }

    {:ok, obj} = Linx.Netfilter.Object.new(:quota, name, data)

    wrap_add!(
      rs,
      fn rs -> Ruleset.add_object!(rs, {family, table_name}, obj) end,
      meta,
      state,
      "add_object"
    )
  end

  defp compile_table_item({:object, :limit, name, opts, meta}, family, table_name, rs, state) do
    limit_stmt = Keyword.fetch!(opts, :limit)
    [%Expr{name: :limit, data: data}] = compile_stmt(limit_stmt, family, state)
    {:ok, obj} = Linx.Netfilter.Object.new(:limit, name, data)

    wrap_add!(
      rs,
      fn rs -> Ruleset.add_object!(rs, {family, table_name}, obj) end,
      meta,
      state,
      "add_object"
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
    # Protocol-context tracking — our slice of evaluate.c's
    # proto_ctx machinery: a transport-header match in a family
    # that doesn't pin the protocol needs a `meta l4proto` guard
    # first (otherwise `tcp dport 22` also matches UDP packets,
    # whose ports sit at the same transport offsets), and an
    # `ip`/`ip6` header match in an `inet` chain needs a
    # `meta nfproto` guard. Explicit matches on those metas pin
    # the context, so hand-written guards aren't duplicated.
    {exprs, _ctx} =
      Enum.reduce(stmts, {[], initial_proto_ctx(family)}, fn stmt, {acc, ctx} ->
        {deps, ctx2} = proto_deps(stmt, ctx, state)
        {acc ++ deps ++ compile_stmt(stmt, family, state), ctx2}
      end)

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

  # `tcp dport vmap @dispatch` — a named verdict-map lookup: load
  # the selector, then a lookup whose destination register is the
  # verdict register (0), so the map's data BECOMES the verdict.
  defp compile_stmt({:vmap, lhs, {:set_ref, name, _}, _meta}, _family, state) do
    {load_expr, _kind} = compile_lhs(lhs, state)
    [load_expr, Expr.lookup(name, dreg: 0)]
  end

  # `ct state vmap { established : accept, invalid : drop }` — an
  # anonymous verdict map: emit a `__anon_vmap` sentinel that the
  # encoder expands into an anonymous map + verdict-register lookup
  # at push time (mirroring the `__anon_set` lifecycle).
  defp compile_stmt({:vmap, lhs, {:map_inline, elems, vmeta}, _meta}, _family, state) do
    {load_expr, kind} = compile_lhs(lhs, state)
    key_type = set_key_type_for(kind)

    elements =
      Enum.map(elems, fn
        {:map_elem, key, data, _} ->
          {vmap_key!(key, kind, key_type, state), vmap_verdict!(data, state)}

        other ->
          raise_at!(
            state,
            value_meta(other) || vmeta,
            "compiler: vmap literal elements must be `key : verdict` pairs"
          )
      end)

    [
      load_expr,
      %Expr{name: :__anon_vmap, data: %{key_type: key_type, elements: elements, sreg: 1}}
    ]
  end

  # `add @ratelimit { ip saddr limit rate 6/minute }` — dynamic
  # set update: load the key selector, then an nft_dynset that
  # add/update/deletes the element, optionally attaching a
  # per-element timeout and stateful expressions.
  defp compile_stmt({:set_update, op, set, key_lhs, elem_opts, meta}, family, state) do
    {load_expr, _kind} = compile_lhs(key_lhs, state)

    timeout =
      case Keyword.get(elem_opts, :timeout) do
        nil ->
          nil

        {:time, ms, _} ->
          ms

        other ->
          raise_at!(
            state,
            value_meta(other),
            "compiler: set-update element timeout must be a time literal (e.g. `90s`)"
          )
      end

    stateful =
      elem_opts
      |> Keyword.get_values(:stateful)
      |> Enum.flat_map(&compile_stmt(&1, family, state))

    _ = meta

    [load_expr, Expr.dynset(set, op: op, sreg_key: 1, timeout: timeout, exprs: stateful)]
  end

  # Masked comparison: `tcp flags & (syn|ack) == syn`,
  # `ct mark & 0xff == 0x4` — load, AND with the mask, compare.
  defp compile_stmt({:match, {:masked, lhs, mask_ast, _}, op, rhs, meta}, _family, state) do
    {load_expr, kind} = compile_lhs(lhs, state)
    {width, order} = mask_shape!(kind, meta, state)

    mask = flag_int!(mask_ast, kind, state)
    value = flag_int!(rhs, kind, state)
    op = if op == :implicit, do: :eq, else: op

    List.wrap(load_expr) ++
      [
        Expr.bitwise(int_bin(mask, width, order), int_bin(0, width, order)),
        Expr.cmp(op, int_bin(value, width, order))
      ]
  end

  defp compile_stmt({:match, lhs, op, rhs, _meta}, _family, state) do
    {load_expr, value_kind} = compile_lhs(lhs, state)

    # nft's OP_IMPLICIT: plain equality for ordinary fields; flag
    # fields get their bitmask-test semantics in compile_rhs.
    op = if op == :implicit and value_kind not in [:tcp_flags], do: :eq, else: op

    cmp_or_lookup = compile_rhs(rhs, op, value_kind, state)
    List.wrap(load_expr) ++ List.wrap(cmp_or_lookup)
  end

  # `quota name "obj"` / `limit name "obj"` — table-level object
  # references (counter name goes through its own clause below).
  defp compile_stmt({:objref, kind, name, _meta}, _family, _state) do
    [Expr.objref(name, kind)]
  end

  # Inline (per-rule) quota: `quota over 500 mbytes drop`.
  defp compile_stmt({:quota, opts, _meta}, _family, _state) do
    [
      Expr.quota(
        bytes: Keyword.fetch!(opts, :bytes),
        over: Keyword.get(opts, :over, false),
        used: Keyword.get(opts, :used, 0)
      )
    ]
  end

  # `counter name "hits"` — reference to a table-level named
  # counter object (all referencing rules share its state);
  # plain `counter` (with or without initial packets/bytes) is a
  # per-rule anonymous counter.
  defp compile_stmt({:counter, opts, meta}, _family, state) do
    case Keyword.get(opts, :name) do
      nil ->
        [Expr.counter()]

      {:string, name, _} ->
        [Expr.objref(name, :counter)]

      {:identifier, name, _} ->
        [Expr.objref(name, :counter)]

      other ->
        raise_at!(
          state,
          value_meta(other) || meta,
          "compiler: `counter name` expects a counter object name"
        )
    end
  end

  # Translate the parser's nft-flavored log options into the
  # `Expr.log/1` contract. Two impedance mismatches matter:
  #
  #   * nft's plain `log` (no group) logs via the kernel logger,
  #     NOT nflog — so pass `group: nil` explicitly to suppress
  #     the pipeline-DSL convenience default of group 5000, which
  #     would silently change where messages go.
  #   * `flags all` is a single keyword in nft syntax but a flag
  #     LIST on the wire (NF_LOG_MASK).
  defp compile_stmt({:log, opts, meta}, _family, state) do
    expr_opts =
      Enum.flat_map(opts, fn
        {:prefix, p} ->
          [prefix: p]

        {:group, g} ->
          [group: g]

        {:snaplen, n} ->
          [snaplen: n]

        {:"queue-threshold", n} ->
          [qthreshold: n]

        {:flags, flag} ->
          [flags: log_flags!(flag, state, meta)]

        {:level, _} ->
          raise_at!(
            state,
            meta,
            "compiler: `log level` is not yet supported (no NFTA_LOG_LEVEL encoding)"
          )

        {key, _} ->
          raise_at!(state, meta, "compiler: unsupported log option `#{key}`")
      end)

    [Expr.log(Keyword.put_new(expr_opts, :group, nil))]
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

  defp compile_stmt({:limit, {:rate, n, unit}, opts, meta}, _family, state) do
    per =
      case unit do
        :second -> 1
        :minute -> 60
        :hour -> 3600
        :day -> 86_400
        :week -> 604_800
        other -> raise_at!(state, meta, "compiler: unknown limit rate unit `#{other}`")
      end

    {burst, type} =
      case Keyword.get(opts, :burst) do
        nil -> {nil, :packets}
        {b, unit_atom} when unit_atom in [:packets, :bytes] -> {b, unit_atom}
        b when is_integer(b) -> {b, :packets}
      end

    limit_opts =
      [rate: n, per: per, type: type, over: Keyword.get(opts, :over, false)]
      |> then(fn kw -> if burst, do: Keyword.put(kw, :burst, burst), else: kw end)

    [Expr.limit(limit_opts)]
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

  # A vmap key, resolved against the LHS field's kind: ct states
  # by name, ICMP types by their per-protocol tables, everything
  # else via the generic set-literal path.
  defp vmap_key!({:identifier, name, meta}, :ct_state, _key_type, state) do
    case safe_ct_state_bits(String.to_atom(name)) do
      nil -> raise_at!(state, meta, "compiler: unknown ct state `#{name}`")
      bits -> bits
    end
  end

  defp vmap_key!(key, :icmp_type, key_type, state) do
    key
    |> resolve_named_ints(@icmp_type_names, "ICMP type", state)
    |> literal_for_set!(key_type, state)
  end

  defp vmap_key!(key, :icmpv6_type, key_type, state) do
    key
    |> resolve_named_ints(@icmpv6_type_names, "ICMPv6 type", state)
    |> literal_for_set!(key_type, state)
  end

  defp vmap_key!(key, _kind, key_type, state) do
    literal_for_set!(key, key_type, state)
  end

  defp vmap_verdict!({:verdict, :accept, _}, _state), do: Verdict.accept()
  defp vmap_verdict!({:verdict, :drop, _}, _state), do: Verdict.drop()
  defp vmap_verdict!({:verdict, {:jump, target}, _}, _state), do: Verdict.jump(target)
  defp vmap_verdict!({:verdict, {:goto, target}, _}, _state), do: Verdict.goto(target)
  defp vmap_verdict!({:verdict, kind, _}, _state) when is_atom(kind), do: Verdict.new!(kind)

  defp vmap_verdict!(other, state) do
    raise_at!(
      state,
      value_meta(other),
      "compiler: vmap data must be a verdict (accept/drop/jump/goto/...)"
    )
  end

  defp object_int_opt(opts, key, state) do
    case Keyword.get(opts, key) do
      nil -> 0
      {:integer, n, _} -> n
      other -> raise_at!(state, value_meta(other), "compiler: expected integer #{key} value")
    end
  end

  @log_all_flags [:tcp_seq, :tcp_opt, :ip_opt, :uid, :macdecode]

  defp log_flags!(:all, _state, _meta), do: @log_all_flags
  defp log_flags!(:skuid, _state, _meta), do: [:uid]
  defp log_flags!(:ether, _state, _meta), do: [:macdecode]

  defp log_flags!(other, state, meta) do
    raise_at!(state, meta, "compiler: unsupported log flags `#{other}`")
  end

  defp stmt_meta(tuple), do: elem(tuple, tuple_size(tuple) - 1)
  defp lhs_meta({:match, _, _, _, meta}), do: meta
  defp lhs_meta(_), do: %{line: 0, column: 0}

  # ---- Protocol-context dependencies ----

  @nfproto_ipv4 2
  @nfproto_ipv6 10

  @l4proto %{
    tcp: 6,
    udp: 17,
    icmp: 1,
    icmpv6: 58,
    sctp: 132,
    dccp: 33,
    ah: 51,
    esp: 50,
    comp: 108
  }

  defp initial_proto_ctx(:ip), do: %{nfproto: :ipv4, l4proto: nil}
  defp initial_proto_ctx(:ip6), do: %{nfproto: :ipv6, l4proto: nil}
  defp initial_proto_ctx(_), do: %{nfproto: nil, l4proto: nil}

  # Returns {dependency_exprs, updated_ctx} for one rule statement.
  defp proto_deps({:match, lhs, op, rhs, _meta}, ctx, state) do
    {deps, ctx} = lhs_proto_deps(lhs, ctx, state)
    # Implicit juxtaposition pins the context the same as `==`.
    pin_op = if op == :implicit, do: :eq, else: op
    {deps, pin_from_match(lhs, pin_op, rhs, ctx)}
  end

  defp proto_deps({:vmap, lhs, _target, _meta}, ctx, state),
    do: lhs_proto_deps(lhs, ctx, state)

  defp proto_deps({:set_update, _op, _set, key_lhs, _opts, _meta}, ctx, state),
    do: lhs_proto_deps(key_lhs, ctx, state)

  defp proto_deps(_stmt, ctx, _state), do: {[], ctx}

  defp lhs_proto_deps({:masked, inner, _mask, _meta}, ctx, state),
    do: lhs_proto_deps(inner, ctx, state)

  defp lhs_proto_deps({:concat_lhs, parts, _meta}, ctx, state) do
    Enum.reduce(parts, {[], ctx}, fn part, {deps, ctx} ->
      {more, ctx2} = lhs_proto_deps(part, ctx, state)
      {deps ++ more, ctx2}
    end)
  end

  defp lhs_proto_deps({:payload, header, _field, meta}, ctx, state) do
    case header do
      :ip ->
        require_nfproto(:ipv4, ctx, meta, state)

      :ip6 ->
        require_nfproto(:ipv6, ctx, meta, state)

      transport when is_map_key(@l4proto, transport) ->
        require_l4proto(transport, ctx, meta, state)

      _ ->
        {[], ctx}
    end
  end

  defp lhs_proto_deps(_lhs, ctx, _state), do: {[], ctx}

  defp require_nfproto(want, ctx, meta, state) do
    case ctx.nfproto do
      ^want ->
        {[], ctx}

      nil ->
        value = if want == :ipv4, do: @nfproto_ipv4, else: @nfproto_ipv6
        {[Expr.meta(:nfproto), Expr.cmp(:eq, <<value>>)], %{ctx | nfproto: want}}

      other ->
        raise_at!(
          state,
          meta,
          "compiler: #{want} header match conflicts with the rule's #{other} context"
        )
    end
  end

  defp require_l4proto(transport, ctx, meta, state) do
    proto = Map.fetch!(@l4proto, transport)

    # icmp only exists in IPv4 packets and icmpv6 in IPv6 —
    # contradiction with a pinned network protocol is an error
    # (nft rejects `icmpv6 type` in an ip-family table the same
    # way). The l4proto value itself implies the network protocol,
    # so no extra nfproto guard is emitted.
    case {transport, ctx.nfproto} do
      {:icmp, :ipv6} ->
        raise_at!(state, meta, "compiler: icmp match conflicts with the rule's ipv6 context")

      {:icmpv6, :ipv4} ->
        raise_at!(state, meta, "compiler: icmpv6 match conflicts with the rule's ipv4 context")

      _ ->
        :ok
    end

    case ctx.l4proto do
      ^proto ->
        {[], ctx}

      nil ->
        {[Expr.meta(:l4proto), Expr.cmp(:eq, <<proto>>)], %{ctx | l4proto: proto}}

      other ->
        raise_at!(
          state,
          meta,
          "compiler: #{transport} match conflicts with the rule's transport protocol " <>
            "(already pinned to protocol #{other})"
        )
    end
  end

  # A hand-written `meta l4proto tcp` / `meta nfproto ipv4` /
  # `ip protocol tcp` equality match pins the context so we don't
  # re-emit the guard.
  defp pin_from_match({:meta, :l4proto, _}, :eq, rhs, ctx) do
    case proto_value(rhs) do
      nil -> ctx
      n -> %{ctx | l4proto: n}
    end
  end

  defp pin_from_match({:meta, :nfproto, _}, :eq, rhs, ctx) do
    case proto_value(rhs) do
      @nfproto_ipv4 -> %{ctx | nfproto: :ipv4}
      @nfproto_ipv6 -> %{ctx | nfproto: :ipv6}
      _ -> ctx
    end
  end

  defp pin_from_match({:payload, :ip, :protocol, _}, :eq, rhs, ctx) do
    case proto_value(rhs) do
      nil -> ctx
      n -> %{ctx | l4proto: n}
    end
  end

  defp pin_from_match(_lhs, _op, _rhs, ctx), do: ctx

  defp proto_value({:integer, n, _}), do: n

  defp proto_value({:identifier, name, _}) do
    case parse_int_keyword(name) do
      {:ok, n} -> n
      :error -> nil
    end
  end

  defp proto_value(_), do: nil

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

  # Concatenated selectors (`ip daddr . tcp dport`): each part
  # loads into consecutive 32-bit registers starting at
  # NFT_REG32_00 (= 8), one register per 4 bytes of field width —
  # the same layout nft's own concat compilation uses. The lookup
  # then reads from register 8.
  @reg32_base 8

  defp compile_lhs({:concat_lhs, parts, _meta}, state) do
    {loads, kinds, _next_reg} =
      Enum.reduce(parts, {[], [], @reg32_base}, fn part, {loads, kinds, reg} ->
        {expr, kind} = compile_lhs(part, state)
        expr = %{expr | data: %{expr.data | dreg: reg}}
        {loads ++ [expr], kinds ++ [kind], reg + div(kind_byte_len!(kind, part, state) + 3, 4)}
      end)

    {loads, {:concat_kinds, kinds}}
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
  defp payload_dispatch(:tcp, :flags), do: {:ok, :tcp_flags, :tcp_flags}
  defp payload_dispatch(:udp, :sport), do: {:ok, :udp_sport, {:int, 2}}
  defp payload_dispatch(:udp, :dport), do: {:ok, :udp_dport, {:int, 2}}
  defp payload_dispatch(:ip, :saddr), do: {:ok, :ip_saddr, :ipv4}
  defp payload_dispatch(:ip, :daddr), do: {:ok, :ip_daddr, :ipv4}
  defp payload_dispatch(:ip, :protocol), do: {:ok, :ip_protocol, {:int, 1}}
  defp payload_dispatch(:ip6, :saddr), do: {:ok, :ip6_saddr, :ipv6}
  defp payload_dispatch(:ip6, :daddr), do: {:ok, :ip6_daddr, :ipv6}
  defp payload_dispatch(:ip6, :nexthdr), do: {:ok, :ip6_nexthdr, {:int, 1}}
  defp payload_dispatch(:ip6, :hoplimit), do: {:ok, :ip6_hoplimit, {:int, 1}}
  defp payload_dispatch(:icmp, :type), do: {:ok, :icmp_type, :icmp_type}
  defp payload_dispatch(:icmp, :code), do: {:ok, :icmp_code, {:int, 1}}
  defp payload_dispatch(:icmpv6, :type), do: {:ok, :icmpv6_type, :icmpv6_type}
  defp payload_dispatch(:icmpv6, :code), do: {:ok, :icmpv6_code, {:int, 1}}
  defp payload_dispatch(_, _), do: :unknown

  # Byte-order matters for multi-byte kinds: packet-header payloads are
  # network order (big-endian) — the register holds raw packet bytes — but
  # the kernel stores these meta/ct fields in *host* order and memcmps the
  # native register against NFTA_DATA_VALUE verbatim. `{:int, w}` is
  # network order; `{:int, w, :host}` is host order. `meta protocol` is a
  # __be16 (network order); 1-byte fields have no order.
  defp meta_kind(:iif), do: :ifindex
  defp meta_kind(:oif), do: :ifindex
  defp meta_kind(:iifname), do: :ifname
  defp meta_kind(:oifname), do: :ifname
  defp meta_kind(:mark), do: {:int, 4, :host}
  defp meta_kind(:protocol), do: {:int, 2}
  defp meta_kind(:nfproto), do: {:int, 1}
  defp meta_kind(:l4proto), do: {:int, 1}
  defp meta_kind(:length), do: {:int, 4, :host}
  defp meta_kind(:skuid), do: {:int, 4, :host}
  defp meta_kind(:skgid), do: {:int, 4, :host}
  defp meta_kind(_), do: nil

  defp ct_kind(:state), do: :ct_state
  defp ct_kind(:direction), do: {:int, 1}
  defp ct_kind(:mark), do: {:int, 4, :host}
  defp ct_kind(_), do: nil

  # ---- RHS ----

  @tcp_flag_names %{
    "fin" => 0x01,
    "syn" => 0x02,
    "rst" => 0x04,
    "psh" => 0x08,
    "ack" => 0x10,
    "urg" => 0x20,
    "ecn" => 0x40,
    "cwr" => 0x80
  }

  # `tcp flags syn` (implicit) — a BITMASK TEST: flags & syn != 0,
  # exactly nft's OP_IMPLICIT semantics for flag fields.
  defp compile_rhs(value, :implicit, :tcp_flags, state) do
    bits = flag_int!(value, :tcp_flags, state)

    [
      Expr.bitwise(<<bits>>, <<0>>),
      Expr.cmp(:neq, <<0>>)
    ]
  end

  # `tcp flags == syn` (explicit) — an EXACT comparison.
  defp compile_rhs(value, op, :tcp_flags, state) when op in [:eq, :neq] do
    Expr.cmp(op, <<flag_int!(value, :tcp_flags, state)>>)
  end

  defp compile_rhs(value, op, :icmp_type, state) do
    value
    |> resolve_named_ints(@icmp_type_names, "ICMP type", state)
    |> compile_rhs(op, {:int, 1}, state)
  end

  defp compile_rhs(value, op, :icmpv6_type, state) do
    value
    |> resolve_named_ints(@icmpv6_type_names, "ICMPv6 type", state)
    |> compile_rhs(op, {:int, 1}, state)
  end

  # Concatenated-selector RHS: only whole-key set membership makes
  # sense — either a declared set or an inline literal.
  defp compile_rhs({:set_ref, name, _}, _op, {:concat_kinds, _kinds}, _state) do
    Expr.lookup(name, sreg: @reg32_base)
  end

  defp compile_rhs({:set_inline, elems, _}, _op, {:concat_kinds, kinds}, state) do
    key_type = {:concat, Enum.map(kinds, &set_key_type_for/1)}
    values = Enum.map(elems, &literal_for_set!(&1, key_type, state))
    Expr.set_literal(values, key_type, flags: [:constant], sreg: @reg32_base)
  end

  defp compile_rhs(other, _op, {:concat_kinds, _kinds}, state) do
    raise_at!(
      state,
      value_meta(other),
      "compiler: concatenated selectors match against `@set` references or " <>
        "`{ a . b, ... }` literals only"
    )
  end

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

  # `meta iif`/`oif` compare an interface INDEX (host-order u32).
  # nft resolves interface names to indexes at rule-load time via
  # if_nametoindex(3) — do the same with :net.if_name2index/1, so
  # `iif "lo"` works. The interface must exist on the compiling
  # host, exactly as with nft.
  defp compile_rhs({:integer, n, _}, op, :ifindex, _state) do
    Expr.cmp(op, encode_int_host(n, 4))
  end

  defp compile_rhs({:string, s, meta}, op, :ifindex, state) do
    Expr.cmp(op, encode_int_host(ifindex!(s, state, meta), 4))
  end

  defp compile_rhs({:identifier, s, meta}, op, :ifindex, state) do
    Expr.cmp(op, encode_int_host(ifindex!(s, state, meta), 4))
  end

  defp compile_rhs({:integer, n, _}, op, {:int, width}, _state) do
    Expr.cmp(op, encode_int(n, width))
  end

  defp compile_rhs({:integer, n, _}, op, {:int, width, :host}, _state) do
    Expr.cmp(op, encode_int_host(n, width))
  end

  defp compile_rhs({:time, n, _}, op, {:int, width}, _state) do
    Expr.cmp(op, encode_int(n, width))
  end

  defp compile_rhs({:string, s, _}, op, :ifname, _state) do
    Expr.cmp(op, pad_ifname(s))
  end

  defp compile_rhs({:string, s, meta}, op, {:int, _, _} = kind, state) do
    compile_int_string(s, meta, op, kind, state)
  end

  defp compile_rhs({:string, s, meta}, op, {:int, _width} = kind, state) do
    compile_int_string(s, meta, op, kind, state)
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

  # Interval sets are compared in memcmp order, which for a host-order
  # field on a little-endian machine is not numeric order — correct
  # support needs a byteorder conversion expression the compiler doesn't
  # emit yet. Refuse rather than install a range that matches the wrong
  # packets.
  defp compile_rhs({:range, _lo, _hi, meta}, _op, {:int, _width, :host}, state) do
    raise_at!(
      state,
      meta,
      "compiler: ranges over host-byte-order fields (meta mark/iif/oif/length/" <>
        "skuid/skgid, ct mark) are not supported yet"
    )
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

  defp compile_rhs({:identifier, name, meta}, op, {:int, width, :host}, state) do
    case parse_int_keyword(name) do
      {:ok, n} ->
        Expr.cmp(op, encode_int_host(n, width))

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

  # Unclassifiable literal the tokenizer demoted instead of
  # rejecting (mirrors nft, whose scanner never fails and whose
  # evaluation step reports the error with a location).
  defp compile_rhs({:symbol, raw, meta}, _op, kind, state) do
    raise_at!(
      state,
      meta,
      "compiler: cannot interpret literal `#{raw}` as #{kind_name(kind)}"
    )
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

  defp set_key_type_for(:ifindex), do: :mark
  defp set_key_type_for(:icmp_type), do: :inet_proto
  defp set_key_type_for(:icmpv6_type), do: :inet_proto
  defp set_key_type_for({:int, 2}), do: :inet_service
  defp set_key_type_for({:int, 4}), do: :mark
  defp set_key_type_for({:int, 1}), do: :inet_proto
  # Host-order u32 fields use the :mark set type: the encoder emits :mark
  # keys in native order, matching the native register these fields load.
  defp set_key_type_for({:int, 4, :host}), do: :mark
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

  defp literal_for_set!({:range, lo, hi, _}, _key_type, state),
    do: {:range, literal_bound!(lo, state), literal_bound!(hi, state)}

  # Concatenated element against a concatenated key type: resolve
  # each part against its field's type. The stored element is a
  # list, one raw value per field.
  defp literal_for_set!({:concat, parts, meta}, {:concat, types}, state) do
    if length(parts) != length(types) do
      raise_at!(
        state,
        meta,
        "compiler: concatenated element has #{length(parts)} parts but the " <>
          "set key has #{length(types)} fields"
      )
    end

    parts
    |> Enum.zip(types)
    |> Enum.map(fn {part, type} -> literal_for_set!(part, type, state) end)
  end

  defp literal_for_set!({:concat, _parts, meta}, key_type, state) do
    raise_at!(
      state,
      meta,
      "compiler: concatenated element used with non-concatenated set key " <>
        "type #{inspect(key_type)}"
    )
  end

  defp literal_for_set!({:symbol, raw, meta}, key_type, state) do
    raise_at!(
      state,
      meta,
      "compiler: cannot interpret literal `#{raw}` as a #{key_type} set element"
    )
  end

  defp literal_for_set!(node, _kind, state) do
    raise_at!(
      state,
      value_meta(node),
      "compiler: unsupported set element shape: #{inspect(node)}"
    )
  end

  # Replaces symbolic names with their integer values throughout a
  # value node (single values, inline sets, lists, ranges), keyed
  # by a per-field name table. Unknown names raise located errors.
  defp resolve_named_ints({:identifier, name, meta}, table, what, state) do
    case Map.fetch(table, name) do
      {:ok, n} -> {:integer, n, meta}
      :error -> raise_at!(state, meta, "compiler: unknown #{what} `#{name}`")
    end
  end

  defp resolve_named_ints({:set_inline, elems, meta}, table, what, state) do
    {:set_inline, Enum.map(elems, &resolve_named_ints(&1, table, what, state)), meta}
  end

  defp resolve_named_ints({:list, elems, meta}, table, what, state) do
    {:list, Enum.map(elems, &resolve_named_ints(&1, table, what, state)), meta}
  end

  defp resolve_named_ints({:range, lo, hi, meta}, table, what, state) do
    {:range, resolve_named_ints(lo, table, what, state),
     resolve_named_ints(hi, table, what, state), meta}
  end

  defp resolve_named_ints(other, _table, _what, _state), do: other

  # Byte width of a selector's value — determines how many 32-bit
  # registers a concatenation part occupies.
  defp kind_byte_len!({:int, w}, _part, _state), do: w
  defp kind_byte_len!({:int, w, :host}, _part, _state), do: w
  defp kind_byte_len!(:ipv4, _part, _state), do: 4
  defp kind_byte_len!(:ipv6, _part, _state), do: 16
  defp kind_byte_len!(:ifname, _part, _state), do: 16
  defp kind_byte_len!(:ifindex, _part, _state), do: 4
  defp kind_byte_len!(:ct_state, _part, _state), do: 4
  defp kind_byte_len!(:icmp_type, _part, _state), do: 1
  defp kind_byte_len!(:icmpv6_type, _part, _state), do: 1

  defp kind_byte_len!(kind, part, state) do
    raise_at!(
      state,
      lhs_meta(part),
      "compiler: selector kind #{inspect(kind)} cannot be used in a concatenation"
    )
  end

  # A flag/mask operand: integer, symbolic name (per field kind),
  # or a `(a|b|c)` OR-combination.
  defp flag_int!({:integer, n, _}, _kind, _state), do: n

  defp flag_int!({:identifier, name, meta}, kind, state) do
    table = if kind == :tcp_flags, do: @tcp_flag_names, else: %{}

    case Map.fetch(table, name) do
      {:ok, bits} ->
        bits

      :error ->
        case parse_int_keyword(name) do
          {:ok, n} -> n
          :error -> raise_at!(state, meta, "compiler: unknown flag/value `#{name}`")
        end
    end
  end

  defp flag_int!({:or_list, parts, _}, kind, state) do
    Enum.reduce(parts, 0, fn part, acc -> bor(acc, flag_int!(part, kind, state)) end)
  end

  defp flag_int!(other, _kind, state) do
    raise_at!(state, value_meta(other), "compiler: expected a flag value or (a|b) combination")
  end

  # Byte width and byte order for masked comparisons, per field kind.
  defp mask_shape!(:tcp_flags, _meta, _state), do: {1, :big}
  defp mask_shape!({:int, w}, _meta, _state), do: {w, :big}
  defp mask_shape!({:int, w, :host}, _meta, _state), do: {w, :native}
  defp mask_shape!(:ct_state, _meta, _state), do: {4, :big}

  defp mask_shape!(kind, meta, state) do
    raise_at!(state, meta, "compiler: `& mask` is not supported on #{kind_name(kind)} fields")
  end

  defp int_bin(n, width, :big), do: <<n::big-size(width * 8)>>
  defp int_bin(n, width, :native), do: <<n::native-size(width * 8)>>

  defp ifindex!(name, state, meta) do
    case :net.if_name2index(String.to_charlist(name)) do
      {:ok, index} ->
        index

      {:error, _} ->
        raise_at!(
          state,
          meta,
          "compiler: unknown interface `#{name}` — `iif`/`oif` resolve the name " <>
            "to an index at compile time (like nft), so the interface must exist; " <>
            "use `iifname`/`oifname` to match by name string instead"
        )
    end
  end

  defp kind_name({:int, w}), do: "a #{w * 8}-bit integer"
  defp kind_name({:int, w, :host}), do: "a #{w * 8}-bit integer"
  defp kind_name(:ipv4), do: "an IPv4 address"
  defp kind_name(:ipv6), do: "an IPv6 address"
  defp kind_name(:ifname), do: "an interface name"
  defp kind_name(:ct_state), do: "a ct state"
  defp kind_name(other), do: inspect(other)

  # A range bound: integer ports/marks, or addresses
  # (`10.0.0.1-10.0.0.9`); the encoder turns address strings into
  # key bytes.
  defp literal_bound!({:integer, n, _}, _state), do: n
  defp literal_bound!({:time, n, _}, _state), do: n
  defp literal_bound!({:address, :ipv4, addr, _}, _state), do: addr
  defp literal_bound!({:address, :ipv6, addr, _}, _state), do: addr

  defp literal_bound!(node, state) do
    raise_at!(state, value_meta(node), "compiler: unsupported range bound")
  end

  defp literal_int!({:integer, n, _}), do: n
  defp literal_int!({:time, n, _}), do: n

  defp literal_int!(node),
    do: raise_at!(%{file: "?", original_source: ""}, value_meta(node), "expected integer literal")

  # Resolved-element (post-literal_for_set!) interval detection:
  # {:range, lo, hi} tuples, CIDR strings, or concat parts thereof.
  defp interval_element?({:range, _, _}), do: true
  defp interval_element?(v) when is_binary(v), do: String.contains?(v, "/")
  defp interval_element?(parts) when is_list(parts), do: Enum.any?(parts, &interval_element?/1)
  defp interval_element?(_), do: false

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

        {:concat, parts} ->
          {:concat, parts}

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

    # nft's evaluation rejects range/CIDR elements in sets without
    # the interval flag ("interval expression not allowed") — the
    # kernel-side backends need to know up front.
    if :interval not in flags and Enum.any?(elements, &interval_element?/1) do
      raise_at!(
        state,
        meta,
        "compiler: set `#{name}` has range/CIDR elements — add `flags interval`"
      )
    end

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

  # `dnat to 10.0.0.5:8080` — address plus explicit port (the
  # tokenizer splits the colon form the way nft's scanner does).
  defp nat_target!({:nat_target, inner, port_val, meta}, state, _meta) do
    {addr, nil} = nat_target!(inner, state, meta)

    port =
      case port_val do
        {:integer, n, _} -> n
        {:range, lo, hi, _} -> {literal_int!(lo), literal_int!(hi)}
        other -> raise_at!(state, value_meta(other), "compiler: unsupported NAT port shape")
      end

    {addr, port}
  end

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

  # Host byte order — for the meta/ct fields the kernel stores natively
  # (see meta_kind/1). The register is memcmp'd against these bytes.
  defp encode_int_host(n, 1), do: <<n>>
  defp encode_int_host(n, 2), do: <<n::native-16>>
  defp encode_int_host(n, 4), do: <<n::native-32>>
  defp encode_int_host(n, 8), do: <<n::native-64>>

  defp compile_int_string(s, meta, op, kind, state) do
    case Integer.parse(s) do
      {n, ""} -> compile_rhs({:integer, n, meta}, op, kind, state)
      _ -> raise_at!(state, meta, "compiler: expected integer value, got string #{inspect(s)}")
    end
  end

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
  defp parse_int_keyword("sctp"), do: {:ok, 132}
  defp parse_int_keyword("dccp"), do: {:ok, 33}

  # `meta nfproto` values.
  defp parse_int_keyword("ipv4"), do: {:ok, 2}
  defp parse_int_keyword("ipv6"), do: {:ok, 10}

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

  @spec raise_at!(term(), term(), String.t()) :: no_return()
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
