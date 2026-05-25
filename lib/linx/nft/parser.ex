defmodule Linx.NFT.Parser do
  @moduledoc """
  Recursive-descent parser over a token stream produced by
  `Linx.NFT.Tokenizer`. Builds a small internal AST that
  `Linx.NFT.Compiler` later walks and translates into calls on the
  `Linx.Netfilter.Ruleset` validator-setter surface (the same
  surface the pipeline DSL uses — no parallel validation layer).

  Mirrors the shape of `Phoenix.LiveView.TagEngine.Parser`: a
  function per non-terminal, a token list as the threaded state,
  consume helpers that raise `Linx.NFT.ParseError` on mismatch
  with the token's `{file, line, column}` and source snippet.

  ## AST shape

  Top-level items (the result of `parse/1`):

      {:table, family, name, body, meta}
      {:include, path, meta}
      {:define, name, value, meta}

  Inside a table `body`:

      {:chain, name, opts, stmts, meta}
      {:set, name, opts, meta}
      {:map, name, opts, meta}
      {:vmap, name, opts, meta}
      {:object, kind, name, opts, meta}
      {:flowtable, name, opts, meta}

  Inside a chain `stmts`:

      {:rule, exprs, rule_opts, meta}

  Inside a rule's `exprs` (one node per source-level statement,
  whether a match clause, a verdict, or an action):

      {:match, lhs, op, rhs, meta}
      {:verdict, kind, meta}            # :accept, :drop, {:jump, "chain"}, ...
      {:counter, opts, meta}
      {:log, opts, meta}
      {:limit, rate, opts, meta}
      {:nat, kind, target, opts, meta}  # kind: :dnat | :snat | :masquerade | :redirect
      {:meta_set, field, value, meta}   # `meta mark set 0xdead`
      {:reject, opts, meta}
      {:queue, opts, meta}

  LHS (left-hand side of a match):

      {:payload, header, field, meta}   # `tcp dport`, `ip saddr`
      {:meta, field, meta}              # `meta iif`
      {:ct, field, meta}                # `ct state`
      {:set_ref, name, meta}            # bare `@blocklist` as predicate
      {:not, inner_lhs, meta}           # `not @blocklist`

  RHS values (the value-position grammar):

      {:integer, n, meta}               | {:string, s, meta}
      {:address, kind, raw, meta}       # :ipv4 / :ipv6 / :mac / :cidr_v4 / :cidr_v6
      {:identifier, name, meta}         # bare identifier (e.g. `established`)
      {:set_inline, [vals], meta}       # `{ 22, 80, 443 }`
      {:set_ref, name, meta}            # `@blocklist`
      {:range, lo, hi, meta}            # `22-25`
      {:list, [vals], meta}             # `22, 80, 443` (no braces)
      {:elixir_expr, raw, meta}         # `\#{...}` interpolation
      {:wildcard, meta}                 # `*` (e.g. `iifname "eth*"`)

  ## Scope notes

  N8b ships the structural shape and the slice of the grammar
  needed for the canonical `~NFT` examples in
  `docs/netfilter/EXAMPLES.md`. The set of recognised statement
  / lhs / rhs shapes will grow per future N8 sub-commit as the
  compiler (N8c) and the long-tail extension milestones add
  callers. The architectural commitments — recursive descent,
  raise-on-mismatch, file:line:column on every AST node — are
  finalised here.
  """

  alias Linx.NFT.ParseError

  defmodule State do
    @moduledoc false

    @enforce_keys [:file, :original_source]
    defstruct [:file, :original_source]
  end

  @type ast :: tuple()

  @match_headers ~w(ip ip6 tcp udp icmp icmpv6 sctp dccp ah esp comp)
  @meta_fields ~w(iif oif iifname oifname mark protocol nfproto l4proto length skuid skgid)
  @ct_fields ~w(state direction mark zone label status helper protocol)
  @verdict_atoms ~w(accept drop continue return queue)
  @policy_atoms ~w(accept drop)

  @doc """
  Parses a token list into a list of top-level AST items.

  ## Options

    * `:file` — source filename for error messages
      (default `"nofile"`).
    * `:source` — original source binary for snippet rendering
      (default `""`).

  Returns `{:ok, ast_items}` or `{:error, %Linx.NFT.ParseError{}}`.
  """
  @spec parse([tuple()], keyword()) ::
          {:ok, [ast()]} | {:error, ParseError.t()}
  def parse(tokens, opts \\ []) when is_list(tokens) do
    state = %State{
      file: Keyword.get(opts, :file, "nofile"),
      original_source: Keyword.get(opts, :source, "")
    }

    try do
      items = parse_top(skip_seps(tokens), state, [])
      {:ok, Enum.reverse(items)}
    rescue
      e in ParseError -> {:error, e}
    end
  end

  # ===========================================================
  # Top level
  # ===========================================================

  defp parse_top([], _state, acc), do: acc

  defp parse_top(tokens, state, acc) do
    tokens = skip_seps(tokens)

    case tokens do
      [] ->
        acc

      [{:identifier, "table", meta} | rest] ->
        {item, rest2} = parse_table(rest, meta, state)
        parse_top(skip_seps(rest2), state, [item | acc])

      [{:identifier, "include", meta} | rest] ->
        {item, rest2} = parse_include(rest, meta, state)
        parse_top(skip_seps(rest2), state, [item | acc])

      [{:identifier, "define", meta} | rest] ->
        {item, rest2} = parse_define(rest, meta, state)
        parse_top(skip_seps(rest2), state, [item | acc])

      [tok | _] ->
        raise_unexpected!(state, tok, "expected `table`, `include`, or `define`")
    end
  end

  defp parse_include(tokens, meta, state) do
    {path, rest} = expect_string!(tokens, state, "include path (quoted string)")
    {{:include, path, meta}, rest}
  end

  defp parse_define(tokens, meta, state) do
    {name, rest} = expect_identifier!(tokens, state, "define name")
    rest = expect_punct!(rest, :assign, state, "`=`")
    {value, rest} = parse_value(rest, state)
    {{:define, name, value, meta}, rest}
  end

  # ===========================================================
  # `table FAMILY NAME { ... }`
  # ===========================================================

  defp parse_table(tokens, meta, state) do
    {family, rest} = expect_family!(tokens, state)
    {name, rest} = expect_table_or_chain_name!(rest, state, "table name")
    rest = expect_punct!(rest, :lbrace, state, "`{` after table name")
    {body, rest} = parse_table_body(skip_seps(rest), state, [])
    rest = expect_punct!(rest, :rbrace, state, "`}` to close table body")
    {{:table, family, name, body, meta}, rest}
  end

  defp parse_table_body([{:rbrace, _} | _] = tokens, _state, acc) do
    {Enum.reverse(acc), tokens}
  end

  defp parse_table_body([], state, _acc) do
    raise_eof!(state, "expected `}` to close table body")
  end

  defp parse_table_body(tokens, state, acc) do
    tokens = skip_seps(tokens)

    case tokens do
      [] ->
        raise_eof!(state, "expected `}` to close table body")

      [{:rbrace, _} | _] ->
        {Enum.reverse(acc), tokens}

      [{:identifier, "chain", meta} | rest] ->
        {item, rest2} = parse_chain(rest, meta, state)
        parse_table_body(skip_seps(rest2), state, [item | acc])

      [{:identifier, "set", meta} | rest] ->
        {item, rest2} = parse_named_collection(rest, :set, meta, state)
        parse_table_body(skip_seps(rest2), state, [item | acc])

      [{:identifier, "map", meta} | rest] ->
        {item, rest2} = parse_named_collection(rest, :map, meta, state)
        parse_table_body(skip_seps(rest2), state, [item | acc])

      [{:identifier, "vmap", meta} | rest] ->
        {item, rest2} = parse_named_collection(rest, :vmap, meta, state)
        parse_table_body(skip_seps(rest2), state, [item | acc])

      [{:identifier, "counter", meta} | rest] ->
        {item, rest2} = parse_object(rest, :counter, meta, state)
        parse_table_body(skip_seps(rest2), state, [item | acc])

      [{:identifier, "quota", meta} | rest] ->
        {item, rest2} = parse_object(rest, :quota, meta, state)
        parse_table_body(skip_seps(rest2), state, [item | acc])

      [{:identifier, "limit", meta} | rest] ->
        {item, rest2} = parse_object(rest, :limit, meta, state)
        parse_table_body(skip_seps(rest2), state, [item | acc])

      [{:identifier, "flowtable", meta} | rest] ->
        {item, rest2} = parse_flowtable(rest, meta, state)
        parse_table_body(skip_seps(rest2), state, [item | acc])

      [{:identifier, "comment", _meta} | rest] ->
        {comment, rest2} = expect_string!(rest, state, "comment text")
        # Table-level comment.
        parse_table_body(skip_seps(rest2), state, [{:comment, comment} | acc])

      [tok | _] ->
        raise_unexpected!(state, tok,
          "expected `chain`, `set`, `map`, `vmap`, `counter`, `quota`, `limit`, `flowtable`, `comment`, or `}`"
        )
    end
  end

  # ===========================================================
  # `chain NAME { ... }`
  # ===========================================================

  defp parse_chain(tokens, meta, state) do
    {name, rest} = expect_table_or_chain_name!(tokens, state, "chain name")
    rest = expect_punct!(rest, :lbrace, state, "`{` after chain name")
    {opts, stmts, rest} = parse_chain_body(skip_seps(rest), state, [], [])
    rest = expect_punct!(rest, :rbrace, state, "`}` to close chain body")
    {{:chain, name, opts, stmts, meta}, rest}
  end

  defp parse_chain_body([{:rbrace, _} | _] = tokens, _state, opts, stmts) do
    {Enum.reverse(opts), Enum.reverse(stmts), tokens}
  end

  defp parse_chain_body([], state, _opts, _stmts) do
    raise_eof!(state, "expected `}` to close chain body")
  end

  defp parse_chain_body(tokens, state, opts, stmts) do
    tokens = skip_seps(tokens)

    case tokens do
      [] ->
        raise_eof!(state, "expected `}` to close chain body")

      [{:rbrace, _} | _] ->
        {Enum.reverse(opts), Enum.reverse(stmts), tokens}

      # `type filter hook input priority 0` — base-chain header.
      [{:identifier, "type", _meta} | rest] ->
        {header_opts, rest2} = parse_base_chain_header(rest, state)
        parse_chain_body(skip_seps(rest2), state, header_opts ++ opts, stmts)

      # `policy drop|accept` — stand-alone directive after `type ...`.
      [{:identifier, "policy", _meta} | rest] ->
        {policy, rest2} = expect_one_of_atom!(rest, @policy_atoms, state, "policy (`accept`|`drop`)")
        parse_chain_body(skip_seps(rest2), state, [{:policy, policy} | opts], stmts)

      # `devices = { ifname, ... }` or `device "ifname"` for ingress/egress chains.
      [{:identifier, "device", _meta} | rest] ->
        {dev, rest2} = parse_value(rest, state)
        parse_chain_body(skip_seps(rest2), state, [{:device, dev} | opts], stmts)

      # `comment "..."` — chain-level comment.
      [{:identifier, "comment", _meta} | rest] ->
        {comment, rest2} = expect_string!(rest, state, "comment text")
        parse_chain_body(skip_seps(rest2), state, [{:comment, comment} | opts], stmts)

      # Otherwise: it's a rule.
      _ ->
        {rule, rest2} = parse_rule(tokens, state)
        parse_chain_body(skip_seps(rest2), state, opts, [rule | stmts])
    end
  end

  # `type filter hook input priority 0`  -- consumed token before this was `type`.
  defp parse_base_chain_header(tokens, state) do
    {type, rest} = expect_atom_identifier!(tokens, state, "chain type (`filter`|`nat`|`route`)")
    rest = expect_identifier_word!(rest, "hook", state)
    {hook, rest} = expect_atom_identifier!(rest, state, "hook name")
    rest = expect_identifier_word!(rest, "priority", state)
    {prio, rest} = parse_priority(rest, state)
    {[{:type, type}, {:hook, hook}, {:priority, prio}], rest}
  end

  # Priority: integer, signed integer (`-150`), or named alias
  # (`filter`, `dstnat`, `srcnat`, `mangle`, `raw`, …) optionally
  # offset by `+ N` / `- N`. Compiler resolves the named aliases.
  defp parse_priority(tokens, state) do
    case tokens do
      [{:dash, _}, {:integer, n, meta} | rest] -> {{:integer, -n, meta}, rest}
      [{:integer, n, meta} | rest] -> {{:integer, n, meta}, rest}
      [{:identifier, name, meta} | rest] -> parse_priority_alias(name, meta, rest)
      [tok | _] -> raise_unexpected!(state, tok, "expected priority value (integer or named alias)")
      [] -> raise_eof!(state, "expected priority value")
    end
  end

  defp parse_priority_alias(name, meta, tokens) do
    case tokens do
      [{:dash, _}, {:integer, n, _} | rest] -> {{:alias, name, -n, meta}, rest}
      [{:identifier, "+", _}, {:integer, n, _} | rest] -> {{:alias, name, n, meta}, rest}
      _ -> {{:alias, name, 0, meta}, tokens}
    end
  end

  # ===========================================================
  # Named collections: set / map / vmap
  # ===========================================================

  defp parse_named_collection(tokens, kind, meta, state) do
    {name, rest} = expect_identifier!(tokens, state, "#{kind} name")
    rest = expect_punct!(rest, :lbrace, state, "`{` after #{kind} name")
    {opts, rest} = parse_collection_body(skip_seps(rest), state, [])
    rest = expect_punct!(rest, :rbrace, state, "`}` to close #{kind} body")
    {{kind, name, opts, meta}, rest}
  end

  defp parse_collection_body([{:rbrace, _} | _] = tokens, _state, acc) do
    {Enum.reverse(acc), tokens}
  end

  defp parse_collection_body([], state, _acc) do
    raise_eof!(state, "expected `}` to close collection body")
  end

  defp parse_collection_body(tokens, state, acc) do
    tokens = skip_seps(tokens)

    case tokens do
      [] ->
        raise_eof!(state, "expected `}` to close collection body")

      [{:rbrace, _} | _] ->
        {Enum.reverse(acc), tokens}

      [{:identifier, "type", _meta} | rest] ->
        {tspec, rest2} = parse_type_spec(rest, state)
        parse_collection_body(skip_seps(rest2), state, [{:type, tspec} | acc])

      [{:identifier, "flags", _meta} | rest] ->
        {flags, rest2} = parse_comma_list(rest, state, &expect_atom_identifier!/3, "flag name")
        parse_collection_body(skip_seps(rest2), state, [{:flags, flags} | acc])

      [{:identifier, "timeout", _meta} | rest] ->
        {value, rest2} = parse_value(rest, state)
        parse_collection_body(skip_seps(rest2), state, [{:timeout, value} | acc])

      [{:identifier, "gc-interval", _meta} | rest] ->
        {value, rest2} = parse_value(rest, state)
        parse_collection_body(skip_seps(rest2), state, [{:gc_interval, value} | acc])

      [{:identifier, "size", _meta} | rest] ->
        {value, rest2} = parse_value(rest, state)
        parse_collection_body(skip_seps(rest2), state, [{:size, value} | acc])

      [{:identifier, "elements", _meta} | rest] ->
        rest = expect_punct!(rest, :assign, state, "`=` after `elements`")
        {elems, rest2} = parse_brace_value_list(rest, state)
        parse_collection_body(skip_seps(rest2), state, [{:elements, elems} | acc])

      [{:identifier, "comment", _meta} | rest] ->
        {comment, rest2} = expect_string!(rest, state, "comment text")
        parse_collection_body(skip_seps(rest2), state, [{:comment, comment} | acc])

      [tok | _] ->
        raise_unexpected!(state, tok,
          "expected `type`, `flags`, `timeout`, `gc-interval`, `size`, `elements`, `comment`, or `}`"
        )
    end
  end

  # `type ipv4_addr` or `type ipv4_addr . inet_service` (concatenation)
  # For maps: `type ipv4_addr : verdict`
  defp parse_type_spec(tokens, state) do
    {parts, rest} = parse_dot_separated_idents(tokens, state)

    case rest do
      [{:colon, _} | rest2] ->
        {data_type, rest3} = parse_dot_separated_idents(rest2, state)
        spec = {:map_type, parts_to_spec(parts), parts_to_spec(data_type)}
        {spec, rest3}

      _ ->
        {parts_to_spec(parts), rest}
    end
  end

  defp parts_to_spec([single]), do: single
  defp parts_to_spec(many), do: {:concat, many}

  defp parse_dot_separated_idents(tokens, state) do
    {name, rest} = expect_atom_identifier!(tokens, state, "type name")
    do_dot_idents(rest, state, [name])
  end

  defp do_dot_idents([{:dot, _} | rest], state, acc) do
    {name, rest2} = expect_atom_identifier!(rest, state, "type name after `.`")
    do_dot_idents(rest2, state, [name | acc])
  end

  defp do_dot_idents(tokens, _state, acc), do: {Enum.reverse(acc), tokens}

  # ===========================================================
  # Named objects
  # ===========================================================

  defp parse_object(tokens, kind, meta, state) do
    {name, rest} = expect_identifier!(tokens, state, "#{kind} name")

    case rest do
      [{:lbrace, _} | rest2] ->
        {opts, rest3} = parse_object_body(skip_seps(rest2), state, [])
        rest4 = expect_punct!(rest3, :rbrace, state, "`}` to close #{kind} body")
        {{:object, kind, name, opts, meta}, rest4}

      _ ->
        # Bare declaration: `counter packets 0 bytes 0` etc. Stop at
        # the statement separator.
        {opts, rest2} = parse_object_inline(rest, state, [])
        {{:object, kind, name, opts, meta}, rest2}
    end
  end

  defp parse_object_body([{:rbrace, _} | _] = tokens, _state, acc) do
    {Enum.reverse(acc), tokens}
  end

  defp parse_object_body([], state, _acc) do
    raise_eof!(state, "expected `}` to close object body")
  end

  defp parse_object_body(tokens, state, acc) do
    tokens = skip_seps(tokens)

    case tokens do
      [] ->
        raise_eof!(state, "expected `}` to close object body")

      [{:rbrace, _} | _] ->
        {Enum.reverse(acc), tokens}

      [{:identifier, key, _meta} | rest] ->
        {value, rest2} = parse_value(rest, state)
        parse_object_body(skip_seps(rest2), state, [{String.to_atom(key), value} | acc])

      [tok | _] ->
        raise_unexpected!(state, tok, "expected object attribute or `}`")
    end
  end

  defp parse_object_inline([{:stmt_sep, _} | _] = tokens, _state, acc), do: {Enum.reverse(acc), tokens}
  defp parse_object_inline([{:rbrace, _} | _] = tokens, _state, acc), do: {Enum.reverse(acc), tokens}
  defp parse_object_inline([], _state, acc), do: {Enum.reverse(acc), []}

  defp parse_object_inline([{:identifier, key, _} | rest], state, acc) do
    {value, rest2} = parse_value(rest, state)
    parse_object_inline(rest2, state, [{String.to_atom(key), value} | acc])
  end

  defp parse_object_inline([tok | _], state, _acc) do
    raise_unexpected!(state, tok, "expected object attribute")
  end

  defp parse_flowtable(tokens, meta, state) do
    {name, rest} = expect_identifier!(tokens, state, "flowtable name")
    rest = expect_punct!(rest, :lbrace, state, "`{` after flowtable name")
    {opts, rest} = parse_flowtable_body(skip_seps(rest), state, [])
    rest = expect_punct!(rest, :rbrace, state, "`}` to close flowtable body")
    {{:flowtable, name, opts, meta}, rest}
  end

  defp parse_flowtable_body([{:rbrace, _} | _] = tokens, _state, acc) do
    {Enum.reverse(acc), tokens}
  end

  defp parse_flowtable_body([], state, _acc) do
    raise_eof!(state, "expected `}` to close flowtable body")
  end

  defp parse_flowtable_body(tokens, state, acc) do
    tokens = skip_seps(tokens)

    case tokens do
      [] ->
        raise_eof!(state, "expected `}` to close flowtable body")

      [{:rbrace, _} | _] ->
        {Enum.reverse(acc), tokens}

      [{:identifier, "hook", _} | rest] ->
        {hook, rest2} = expect_atom_identifier!(rest, state, "hook name")
        parse_flowtable_body(skip_seps(rest2), state, [{:hook, hook} | acc])

      [{:identifier, "priority", _} | rest] ->
        {prio, rest2} = parse_priority(rest, state)
        parse_flowtable_body(skip_seps(rest2), state, [{:priority, prio} | acc])

      [{:identifier, "devices", _} | rest] ->
        rest = expect_punct!(rest, :assign, state, "`=` after `devices`")
        {devs, rest2} = parse_brace_value_list(rest, state)
        parse_flowtable_body(skip_seps(rest2), state, [{:devices, devs} | acc])

      [{:identifier, "flags", _} | rest] ->
        {flags, rest2} = parse_comma_list(rest, state, &expect_atom_identifier!/3, "flag name")
        parse_flowtable_body(skip_seps(rest2), state, [{:flags, flags} | acc])

      [tok | _] ->
        raise_unexpected!(state, tok, "expected `hook`, `priority`, `devices`, `flags`, or `}`")
    end
  end

  # ===========================================================
  # Rules
  # ===========================================================

  defp parse_rule(tokens, state) do
    meta = peek_meta(tokens)
    {stmts, opts, tokens} = parse_rule_stmts(tokens, state, [], [])
    {{:rule, stmts, opts, meta}, tokens}
  end

  defp parse_rule_stmts([{:stmt_sep, _} | _] = tokens, _state, stmts, opts) do
    {Enum.reverse(stmts), Enum.reverse(opts), tokens}
  end

  defp parse_rule_stmts([{:rbrace, _} | _] = tokens, _state, stmts, opts) do
    {Enum.reverse(stmts), Enum.reverse(opts), tokens}
  end

  defp parse_rule_stmts([], _state, stmts, opts) do
    {Enum.reverse(stmts), Enum.reverse(opts), []}
  end

  defp parse_rule_stmts(tokens, state, stmts, opts) do
    case tokens do
      [{:identifier, "comment", _meta} | rest] ->
        {comment, rest2} = expect_string!(rest, state, "comment text")
        parse_rule_stmts(rest2, state, stmts, [{:comment, comment} | opts])

      _ ->
        {stmt, rest} = parse_stmt(tokens, state)
        parse_rule_stmts(rest, state, [stmt | stmts], opts)
    end
  end

  # parse_stmt: one rule statement. Dispatch on the first token's
  # identifier value when applicable.
  defp parse_stmt([{:identifier, "accept", meta} | rest], _state),
    do: {{:verdict, :accept, meta}, rest}

  defp parse_stmt([{:identifier, "drop", meta} | rest], _state),
    do: {{:verdict, :drop, meta}, rest}

  defp parse_stmt([{:identifier, "continue", meta} | rest], _state),
    do: {{:verdict, :continue, meta}, rest}

  defp parse_stmt([{:identifier, "return", meta} | rest], _state),
    do: {{:verdict, :return, meta}, rest}

  defp parse_stmt([{:identifier, "queue", meta} | rest], _state),
    do: {{:verdict, :queue, meta}, rest}

  defp parse_stmt([{:identifier, "jump", meta} | rest], state) do
    {target, rest2} = expect_identifier!(rest, state, "jump target chain name")
    {{:verdict, {:jump, target}, meta}, rest2}
  end

  defp parse_stmt([{:identifier, "goto", meta} | rest], state) do
    {target, rest2} = expect_identifier!(rest, state, "goto target chain name")
    {{:verdict, {:goto, target}, meta}, rest2}
  end

  defp parse_stmt([{:identifier, "reject", meta} | rest], state),
    do: parse_reject_stmt(rest, meta, state)

  defp parse_stmt([{:identifier, "counter", meta} | rest], state),
    do: parse_counter_stmt(rest, meta, state)

  defp parse_stmt([{:identifier, "log", meta} | rest], state),
    do: parse_log_stmt(rest, meta, state)

  defp parse_stmt([{:identifier, "limit", meta} | rest], state),
    do: parse_limit_stmt(rest, meta, state)

  defp parse_stmt([{:identifier, "dnat", meta} | rest], state),
    do: parse_nat_stmt(rest, :dnat, meta, state)

  defp parse_stmt([{:identifier, "snat", meta} | rest], state),
    do: parse_nat_stmt(rest, :snat, meta, state)

  defp parse_stmt([{:identifier, "masquerade", meta} | rest], state),
    do: parse_masquerade_stmt(rest, meta, state)

  defp parse_stmt([{:identifier, "redirect", meta} | rest], state),
    do: parse_redirect_stmt(rest, meta, state)

  defp parse_stmt([{:identifier, "meta", meta} | rest], state),
    do: parse_meta_stmt(rest, meta, state)

  defp parse_stmt([{:identifier, "ct", meta} | rest], state),
    do: parse_ct_stmt(rest, meta, state)

  defp parse_stmt([{:identifier, header, _meta} | _] = tokens, state)
       when header in @match_headers do
    parse_match_stmt(tokens, state)
  end

  # `not @set` — negated set membership as a stand-alone match.
  defp parse_stmt([{:identifier, "not", meta}, {:at, _}, {:identifier, name, _} | rest], _state) do
    {{:match, {:not, {:set_ref, name, meta}, meta}, :membership, nil, meta}, rest}
  end

  defp parse_stmt([{:at, meta}, {:identifier, name, _} | rest], _state) do
    {{:match, {:set_ref, name, meta}, :membership, nil, meta}, rest}
  end

  defp parse_stmt([tok | _], state) do
    raise_unexpected!(state, tok, "expected rule statement (match, verdict, action)")
  end

  defp parse_stmt([], state) do
    raise_eof!(state, "expected rule statement")
  end

  # ---- match statements ----

  defp parse_match_stmt(tokens, state) do
    {lhs, rest} = parse_match_lhs(tokens, state)
    {op, rest} = parse_match_op(rest)
    {rhs, rest} = parse_value(rest, state)
    meta = lhs_meta(lhs)
    {{:match, lhs, op, rhs, meta}, rest}
  end

  defp parse_match_lhs([{:identifier, header, meta} | rest], state)
       when header in @match_headers do
    {field, rest2} = expect_identifier!(rest, state, "#{header} field name")
    {{:payload, String.to_atom(header), String.to_atom(field), meta}, rest2}
  end

  defp parse_match_lhs([{:identifier, "meta", meta} | rest], state) do
    {field, rest2} = expect_identifier!(rest, state, "meta field name")

    unless field in @meta_fields do
      raise_at!(state, meta, "unknown meta field #{inspect(field)}")
    end

    {{:meta, String.to_atom(field), meta}, rest2}
  end

  defp parse_match_lhs([{:identifier, "ct", meta} | rest], state) do
    {field, rest2} = expect_identifier!(rest, state, "ct field name")

    unless field in @ct_fields do
      raise_at!(state, meta, "unknown ct field #{inspect(field)}")
    end

    {{:ct, String.to_atom(field), meta}, rest2}
  end

  defp parse_match_lhs([tok | _], state) do
    raise_unexpected!(state, tok, "expected match lhs (payload header, `meta`, or `ct`)")
  end

  defp parse_match_op([{:eq, _} | rest]), do: {:eq, rest}
  defp parse_match_op([{:neq, _} | rest]), do: {:neq, rest}
  defp parse_match_op([{:lt, _} | rest]), do: {:lt, rest}
  defp parse_match_op([{:lte, _} | rest]), do: {:lte, rest}
  defp parse_match_op([{:gt, _} | rest]), do: {:gt, rest}
  defp parse_match_op([{:gte, _} | rest]), do: {:gte, rest}
  defp parse_match_op(tokens), do: {:eq, tokens}

  # ---- specific action statements ----

  defp parse_reject_stmt(tokens, meta, state) do
    case tokens do
      [{:identifier, "with", _} | rest] ->
        # `reject with icmp type net-unreachable` etc. — capture the
        # tail as a list of identifiers until the next stmt-sep.
        {opts, rest2} = parse_until_stmt_sep(rest, state, [], &collect_reject_with/2)
        {{:reject, [{:with, opts}], meta}, rest2}

      _ ->
        {{:reject, [], meta}, tokens}
    end
  end

  defp collect_reject_with(tok, _state), do: tok

  defp parse_counter_stmt(tokens, meta, state) do
    case tokens do
      [{:identifier, "packets", _}, {:integer, p, _},
       {:identifier, "bytes", _}, {:integer, b, _} | rest] ->
        {{:counter, [packets: p, bytes: b], meta}, rest}

      [{:identifier, "name", _} | rest] ->
        # `counter name @namedctr` or `counter name "x"`
        {ref, rest2} = parse_value(rest, state)
        {{:counter, [name: ref], meta}, rest2}

      _ ->
        {{:counter, [], meta}, tokens}
    end
  end

  defp parse_log_stmt(tokens, meta, state) do
    {opts, rest} = parse_kv_options(tokens, state, log_keys(), [])
    {{:log, opts, meta}, rest}
  end

  defp log_keys do
    %{
      "prefix" => :string_value,
      "group" => :integer_value,
      "level" => :atom_value,
      "flags" => :atom_value,
      "queue-threshold" => :integer_value,
      "snaplen" => :integer_value
    }
  end

  defp parse_limit_stmt(tokens, meta, state) do
    # `limit rate [over] N/(second|minute|...)  [burst N packets]`
    rest = expect_identifier_word!(tokens, "rate", state)

    {over_flag, rest} =
      case rest do
        [{:identifier, "over", _} | r] -> {true, r}
        _ -> {false, rest}
      end

    {n, rest} = expect_integer!(rest, state, "limit rate count")
    rest = expect_punct!(rest, :slash, state, "`/` between count and unit")
    {unit, rest} = expect_atom_identifier!(rest, state, "limit unit (second|minute|hour|day)")

    {opts, rest} = parse_limit_tail(rest, state, [])

    {{:limit, {:rate, n, unit}, [{:over, over_flag} | opts], meta}, rest}
  end

  defp parse_limit_tail(tokens, state, acc) do
    case tokens do
      [{:identifier, "burst", _}, {:integer, n, _} | rest] ->
        # Optionally followed by `packets` or `bytes` unit identifier.
        case rest do
          [{:identifier, unit, _} | rest2] when unit in ~w(packets bytes) ->
            parse_limit_tail(rest2, state, [{:burst, {n, String.to_atom(unit)}} | acc])

          _ ->
            parse_limit_tail(rest, state, [{:burst, n} | acc])
        end

      _ ->
        {Enum.reverse(acc), tokens}
    end
  end

  defp parse_nat_stmt(tokens, kind, meta, state) do
    rest = expect_identifier_word!(tokens, "to", state)
    {target, rest} = parse_value(rest, state)
    {opts, rest} = parse_nat_opts(rest, state, [])
    {{:nat, kind, target, opts, meta}, rest}
  end

  defp parse_masquerade_stmt(tokens, meta, state) do
    {opts, rest} = parse_nat_opts(tokens, state, [])
    {{:nat, :masquerade, nil, opts, meta}, rest}
  end

  defp parse_redirect_stmt(tokens, meta, state) do
    case tokens do
      [{:identifier, "to", _} | rest] ->
        {target, rest2} = parse_value(rest, state)
        {opts, rest3} = parse_nat_opts(rest2, state, [])
        {{:nat, :redirect, target, opts, meta}, rest3}

      _ ->
        {opts, rest} = parse_nat_opts(tokens, state, [])
        {{:nat, :redirect, nil, opts, meta}, rest}
    end
  end

  defp parse_nat_opts(tokens, state, acc) do
    case tokens do
      [{:identifier, flag, _} | rest]
      when flag in ~w(random fully-random persistent) ->
        parse_nat_opts(rest, state, [String.to_atom(flag) | acc])

      _ ->
        {Enum.reverse(acc), tokens}
    end
  end

  # `meta mark set 0xdeadbeef` — meta field assignment.
  defp parse_meta_stmt(tokens, meta, state) do
    {field, rest} = expect_identifier!(tokens, state, "meta field name")

    case rest do
      [{:identifier, "set", _} | rest2] ->
        {value, rest3} = parse_value(rest2, state)
        {{:meta_set, String.to_atom(field), value, meta}, rest3}

      _ ->
        # `meta FIELD VALUE` as a match (without explicit op).
        {op, rest2} = parse_match_op(rest)
        {value, rest3} = parse_value(rest2, state)

        unless field in @meta_fields do
          raise_at!(state, meta, "unknown meta field #{inspect(field)}")
        end

        {{:match, {:meta, String.to_atom(field), meta}, op, value, meta}, rest3}
    end
  end

  # `ct state established`, `ct mark set 0x...`
  defp parse_ct_stmt(tokens, meta, state) do
    {field, rest} = expect_identifier!(tokens, state, "ct field name")

    case rest do
      [{:identifier, "set", _} | rest2] ->
        {value, rest3} = parse_value(rest2, state)
        {{:meta_set, String.to_atom("ct_" <> field), value, meta}, rest3}

      _ ->
        {op, rest2} = parse_match_op(rest)
        {value, rest3} = parse_value(rest2, state)

        unless field in @ct_fields do
          raise_at!(state, meta, "unknown ct field #{inspect(field)}")
        end

        {{:match, {:ct, String.to_atom(field), meta}, op, value, meta}, rest3}
    end
  end

  defp parse_until_stmt_sep([{:stmt_sep, _} | _] = tokens, _state, acc, _f),
    do: {Enum.reverse(acc), tokens}

  defp parse_until_stmt_sep([{:rbrace, _} | _] = tokens, _state, acc, _f),
    do: {Enum.reverse(acc), tokens}

  defp parse_until_stmt_sep([], _state, acc, _f), do: {Enum.reverse(acc), []}

  defp parse_until_stmt_sep([tok | rest], state, acc, f) do
    parse_until_stmt_sep(rest, state, [f.(tok, state) | acc], f)
  end

  # ===========================================================
  # Values
  # ===========================================================

  # Parse a single value-position token (with possible list /
  # range / inline-set extension).
  defp parse_value(tokens, state) do
    {head, rest} = parse_single_value(tokens, state)

    case rest do
      # Range: `22-25` lexes as `{:integer, 22}, {:dash}, {:integer, 25}`.
      [{:dash, _}, {:integer, _, _} | _] = rest ->
        [{:dash, _} | rest2] = rest
        {hi, rest3} = parse_single_value(rest2, state)
        {{:range, head, hi, value_meta(head)}, rest3}

      # Comma-separated list (only at value position; sets use {} braces).
      [{:comma, _} | _] = rest ->
        parse_value_list(head, rest, state)

      _ ->
        {head, rest}
    end
  end

  defp parse_value_list(head, [{:comma, _} | rest], state) do
    rest = skip_seps(rest)
    {next, rest2} = parse_single_value(rest, state)

    case rest2 do
      [{:comma, _} | _] = rest2 ->
        {{:list, more, _meta}, rest3} = parse_value_list(next, rest2, state)
        {{:list, [head | [next | more]], value_meta(head)}, rest3}

      _ ->
        {{:list, [head, next], value_meta(head)}, rest2}
    end
  end

  defp parse_single_value([{:integer, n, meta} | rest], _state),
    do: {{:integer, n, meta}, rest}

  defp parse_single_value([{:time, seconds, meta} | rest], _state),
    do: {{:time, seconds, meta}, rest}

  defp parse_single_value([{:string, s, meta} | rest], _state),
    do: {{:string, s, meta}, rest}

  defp parse_single_value([{:ipv4, v, meta} | rest], _state),
    do: {{:address, :ipv4, v, meta}, rest}

  defp parse_single_value([{:ipv6, v, meta} | rest], _state),
    do: {{:address, :ipv6, v, meta}, rest}

  defp parse_single_value([{:mac, v, meta} | rest], _state),
    do: {{:address, :mac, v, meta}, rest}

  defp parse_single_value([{:cidr_v4, v, meta} | rest], _state),
    do: {{:address, :cidr_v4, v, meta}, rest}

  defp parse_single_value([{:cidr_v6, v, meta} | rest], _state),
    do: {{:address, :cidr_v6, v, meta}, rest}

  defp parse_single_value([{:elixir_expr, raw, meta} | rest], _state),
    do: {{:elixir_expr, raw, meta}, rest}

  defp parse_single_value([{:star, meta} | rest], _state),
    do: {{:wildcard, meta}, rest}

  defp parse_single_value([{:at, meta}, {:identifier, name, _} | rest], _state),
    do: {{:set_ref, name, meta}, rest}

  defp parse_single_value([{:dollar, meta}, {:identifier, name, _} | rest], _state),
    do: {{:var_ref, name, meta}, rest}

  defp parse_single_value([{:lbrace, meta} | _] = tokens, state) do
    {elems, rest} = parse_brace_value_list(tokens, state)
    {{:set_inline, elems, meta}, rest}
  end

  defp parse_single_value([{:identifier, name, meta} | rest], _state) do
    # Could be a symbolic value (`established`, `tcp`, an interface
    # name like `eth0`) or the start of a more complex value. For
    # N8b we treat it as a bare identifier; the compiler is in
    # charge of mapping `established` → `:established`, etc.
    {{:identifier, name, meta}, rest}
  end

  defp parse_single_value([tok | _], state) do
    raise_unexpected!(state, tok, "expected a value")
  end

  defp parse_single_value([], state) do
    raise_eof!(state, "expected a value")
  end

  defp parse_brace_value_list([{:lbrace, _} | rest], state) do
    rest = skip_seps(rest)
    do_brace_list(rest, state, [])
  end

  defp do_brace_list([{:rbrace, _} | rest], _state, acc) do
    {Enum.reverse(acc), rest}
  end

  defp do_brace_list(tokens, state, acc) do
    tokens = skip_seps(tokens)

    case tokens do
      [{:rbrace, _} | rest] ->
        {Enum.reverse(acc), rest}

      _ ->
        {val, rest} = parse_set_element(tokens, state)
        rest = skip_seps(rest)

        case rest do
          [{:comma, _} | rest2] -> do_brace_list(skip_seps(rest2), state, [val | acc])
          [{:rbrace, _} | rest2] -> {Enum.reverse([val | acc]), rest2}
          [tok | _] -> raise_unexpected!(state, tok, "expected `,` or `}` in set element list")
          [] -> raise_eof!(state, "unterminated set element list — expected `}`")
        end
    end
  end

  # A set element is a value, optionally `value : action` for maps.
  defp parse_set_element(tokens, state) do
    {key, rest} = parse_single_value(tokens, state)

    case rest do
      [{:colon, _} | rest2] ->
        rest2 = skip_seps(rest2)
        # The "data" side of a map element can be a verdict, a
        # value, or another inline set/value.
        {data, rest3} = parse_map_data(rest2, state)
        {{:map_elem, key, data, value_meta(key)}, rest3}

      [{:dash, _}, {:integer, _, _} | _] = rest ->
        [{:dash, _} | rest2] = rest
        {hi, rest3} = parse_single_value(rest2, state)
        {{:range, key, hi, value_meta(key)}, rest3}

      _ ->
        {key, rest}
    end
  end

  # Map data is a verdict (`accept`, `jump CHAIN`, ...) or a value.
  defp parse_map_data([{:identifier, v, meta} | rest], _state) when v in @verdict_atoms do
    {{:verdict, String.to_atom(v), meta}, rest}
  end

  defp parse_map_data([{:identifier, "jump", meta} | rest], state) do
    {target, rest2} = expect_identifier!(rest, state, "jump target chain name")
    {{:verdict, {:jump, target}, meta}, rest2}
  end

  defp parse_map_data([{:identifier, "goto", meta} | rest], state) do
    {target, rest2} = expect_identifier!(rest, state, "goto target chain name")
    {{:verdict, {:goto, target}, meta}, rest2}
  end

  defp parse_map_data(tokens, state), do: parse_single_value(tokens, state)

  defp parse_comma_list(tokens, state, item_parser, what) do
    {first, rest} = item_parser.(tokens, state, what)
    do_comma_list(rest, state, item_parser, what, [first])
  end

  defp do_comma_list([{:comma, _} | rest], state, item_parser, what, acc) do
    rest = skip_seps(rest)
    {item, rest2} = item_parser.(rest, state, what)
    do_comma_list(rest2, state, item_parser, what, [item | acc])
  end

  defp do_comma_list(tokens, _state, _item_parser, _what, acc) do
    {Enum.reverse(acc), tokens}
  end

  defp parse_kv_options(tokens, state, key_spec, acc) do
    case tokens do
      [{:identifier, key, _meta} | rest] ->
        case Map.fetch(key_spec, key) do
          {:ok, kind} ->
            {value, rest2} = parse_kv_value(rest, kind, state, key)
            parse_kv_options(rest2, state, key_spec, [{String.to_atom(key), value} | acc])

          :error ->
            {Enum.reverse(acc), tokens}
        end

      _ ->
        {Enum.reverse(acc), tokens}
    end
  end

  defp parse_kv_value(tokens, :string_value, state, key) do
    expect_string!(tokens, state, "string value for `#{key}`")
  end

  defp parse_kv_value(tokens, :integer_value, state, key) do
    expect_integer!(tokens, state, "integer value for `#{key}`")
  end

  defp parse_kv_value(tokens, :atom_value, state, key) do
    expect_atom_identifier!(tokens, state, "identifier value for `#{key}`")
  end

  # ===========================================================
  # Token-consume helpers
  # ===========================================================

  defp skip_seps([{:stmt_sep, _} | rest]), do: skip_seps(rest)
  defp skip_seps(tokens), do: tokens

  defp expect_punct!(tokens, kind, state, what) do
    case tokens do
      [{^kind, _meta} | rest] ->
        rest

      [tok | _] ->
        raise_unexpected!(state, tok, "expected #{what}")

      [] ->
        raise_eof!(state, "expected #{what}")
    end
  end

  defp expect_identifier!(tokens, state, what) do
    case tokens do
      [{:identifier, name, _meta} | rest] -> {name, rest}
      [tok | _] -> raise_unexpected!(state, tok, "expected #{what}")
      [] -> raise_eof!(state, "expected #{what}")
    end
  end

  # Like expect_identifier!, but returns the identifier as an atom.
  defp expect_atom_identifier!(tokens, state, what) do
    case tokens do
      [{:identifier, name, _meta} | rest] -> {String.to_atom(name), rest}
      [tok | _] -> raise_unexpected!(state, tok, "expected #{what}")
      [] -> raise_eof!(state, "expected #{what}")
    end
  end

  defp expect_one_of_atom!(tokens, allowed, state, what) do
    case tokens do
      [{:identifier, name, _meta} | rest] ->
        if name in allowed do
          {String.to_atom(name), rest}
        else
          raise_unexpected!(state, hd(tokens), "expected #{what}")
        end

      [tok | _] ->
        raise_unexpected!(state, tok, "expected #{what}")

      [] ->
        raise_eof!(state, "expected #{what}")
    end
  end

  # Expects a specific keyword identifier (e.g. `hook`, `priority`).
  defp expect_identifier_word!(tokens, word, state) do
    case tokens do
      [{:identifier, ^word, _} | rest] -> rest
      [tok | _] -> raise_unexpected!(state, tok, "expected `#{word}` keyword")
      [] -> raise_eof!(state, "expected `#{word}` keyword")
    end
  end

  defp expect_integer!(tokens, state, what) do
    case tokens do
      [{:integer, n, _meta} | rest] -> {n, rest}
      [tok | _] -> raise_unexpected!(state, tok, "expected #{what}")
      [] -> raise_eof!(state, "expected #{what}")
    end
  end

  defp expect_string!(tokens, state, what) do
    case tokens do
      [{:string, s, _meta} | rest] -> {s, rest}
      [tok | _] -> raise_unexpected!(state, tok, "expected #{what}")
      [] -> raise_eof!(state, "expected #{what}")
    end
  end

  defp expect_family!(tokens, state) do
    families = ~w(ip ip6 inet arp bridge netdev)

    case tokens do
      [{:identifier, name, _meta} | rest] when name in ["ip", "ip6", "inet", "arp", "bridge", "netdev"] ->
        {String.to_atom(name), rest}

      [tok | _] ->
        raise_unexpected!(state, tok, "expected table family (one of #{Enum.join(families, "|")})")

      [] ->
        raise_eof!(state, "expected table family")
    end
  end

  # Table / chain names are identifiers; nft also allows quoted
  # strings as names. Both produce the same internal string.
  defp expect_table_or_chain_name!(tokens, state, what) do
    case tokens do
      [{:identifier, name, _} | rest] -> {name, rest}
      [{:string, name, _} | rest] -> {name, rest}
      [tok | _] -> raise_unexpected!(state, tok, "expected #{what}")
      [] -> raise_eof!(state, "expected #{what}")
    end
  end

  # ===========================================================
  # Meta extractors
  # ===========================================================

  defp peek_meta([{_, meta} | _]) when is_map(meta), do: meta
  defp peek_meta([{_, _, meta} | _]) when is_map(meta), do: meta
  defp peek_meta(_), do: %{line: 0, column: 0}

  defp lhs_meta({:payload, _h, _f, meta}), do: meta
  defp lhs_meta({:meta, _f, meta}), do: meta
  defp lhs_meta({:ct, _f, meta}), do: meta

  defp value_meta({_, _, meta}) when is_map(meta), do: meta
  defp value_meta({_, _, _, meta}) when is_map(meta), do: meta
  defp value_meta(_), do: %{line: 0, column: 0}

  # ===========================================================
  # Error helpers
  # ===========================================================

  defp raise_unexpected!(state, {:stmt_sep, meta}, msg) do
    raise_at!(state, meta, msg <> " but got end of statement")
  end

  defp raise_unexpected!(state, {kind, meta}, msg) when is_atom(kind) and is_map(meta) do
    raise_at!(state, meta, msg <> " but got `#{render_kind(kind)}`")
  end

  defp raise_unexpected!(state, {kind, value, meta}, msg) when is_atom(kind) and is_map(meta) do
    raise_at!(state, meta, msg <> " but got `#{render_value(kind, value)}`")
  end

  defp raise_unexpected!(state, _other, msg) do
    raise_at!(state, %{line: 1, column: 1}, msg)
  end

  defp raise_eof!(state, msg) do
    ParseError.raise_syntax_error!(
      %{file: state.file, line: 0, column: 0, snippet: nil},
      msg <> " (unexpected end of input)"
    )
  end

  defp raise_at!(state, meta, msg) do
    ParseError.raise_syntax_error!(
      %{
        file: state.file,
        line: Map.get(meta, :line, 0),
        column: Map.get(meta, :column, 0),
        snippet: snippet_for(state.original_source, Map.get(meta, :line, 0))
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

  defp render_kind(:lbrace), do: "{"
  defp render_kind(:rbrace), do: "}"
  defp render_kind(:lparen), do: "("
  defp render_kind(:rparen), do: ")"
  defp render_kind(:lbracket), do: "["
  defp render_kind(:rbracket), do: "]"
  defp render_kind(:comma), do: ","
  defp render_kind(:colon), do: ":"
  defp render_kind(:assign), do: "="
  defp render_kind(:dash), do: "-"
  defp render_kind(:slash), do: "/"
  defp render_kind(:star), do: "*"
  defp render_kind(:at), do: "@"
  defp render_kind(:dollar), do: "$"
  defp render_kind(:dot), do: "."
  defp render_kind(other), do: Atom.to_string(other)

  defp render_value(:identifier, v), do: v
  defp render_value(:integer, v), do: Integer.to_string(v)
  defp render_value(:string, v), do: ~s/"#{v}"/
  defp render_value(:ipv4, v), do: v
  defp render_value(:ipv6, v), do: v
  defp render_value(:mac, v), do: v
  defp render_value(:cidr_v4, v), do: v
  defp render_value(:cidr_v6, v), do: v
  defp render_value(_kind, v), do: inspect(v)
end
