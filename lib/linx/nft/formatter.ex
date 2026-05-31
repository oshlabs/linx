defmodule Linx.NFT.Formatter do
  @moduledoc """
  Canonical-emit pretty-printer for `%Linx.Netfilter.Ruleset{}`.

  The inverse of `Linx.NFT.Compiler`: walks the ruleset value and
  emits syntactically valid nft source. The output round-trips
  back through `Linx.NFT.parse/1` to a structurally equivalent
  ruleset (modulo trivia — `format/1` makes no attempt to preserve
  the comments, blank lines, or original ordering of items it
  wasn't itself told about). Trivia-preserving emit is a v2
  enhancement; this commit's goal is canonicalisation, not source
  fidelity.

  ## Per-construct policy

    * Tables are emitted in `{family, name}` order.
    * Inside each table: chains first, then sets, then maps and
      vmaps. (Element-order across these blocks is independent of
      original source.)
    * Chains emit the full base header (`type hook priority`) on
      one line, then `policy X` on the next (if set), a blank
      line, then one rule per line.
    * Rules emit as a single space-joined statement sequence,
      optionally trailed by `comment "…"`.
    * Expressions are paired into match statements (`payload +
      cmp` → `tcp dport 22`, `payload + bitwise + cmp` → CIDR,
      `payload + lookup` → `tcp dport @ports`, `payload +
      __anon_set` → `tcp dport { 22, 80 }`, `ct + cmp` →
      `ct state established`, `meta + cmp` → `meta iif "eth0"`).
      Standalone expressions (`counter`, `log`, `reject`, NAT,
      etc.) emit as their token form.

  ## Limitations

  Anything the formatter doesn't yet know how to render emits a
  `# <unsupported expression: …>` comment in line, so the output
  remains valid nft (a comment) and the gap is visible. As the
  compiler grows (e.g. `limit`, `meta mark set`), the formatter
  gains the inverse cases alongside.

  ## `mix format` integration

  Implements the `Mix.Tasks.Format` behaviour: when listed under
  `:plugins` in a project's `.formatter.exs`, `mix format`
  reflows both inline `~NFT"…"` sigil bodies inside `.ex`
  sources AND standalone `.nft` files. Users wire it up with:

      # .formatter.exs
      [
        plugins: [Linx.NFT.Formatter],
        inputs: ["{lib,test}/**/*.{ex,exs}", "**/*.nft"]
      ]

  Behaviour:

    * **Static `~NFT` sigil body / `.nft` file** — parses,
      runs through `format/1`, returns the canonical
      single-formatted source. Idempotent (N8f's
      output-stability assertion already proves this).
    * **Interpolation-bearing `~NFT` sigil body** — left
      verbatim. AST-aware formatting that preserves `\#{…}`
      positions while reflowing the surrounding nft syntax is a
      future enhancement.
    * **Parse error in a `.nft` file** — raises
      `Linx.NFT.ParseError`, surfacing visibly so the user
      fixes the bad file. (For sigils, parse errors leave the
      body unchanged — the surrounding compile run will report
      the same error anyway, with better stack context.)
  """

  @behaviour Mix.Tasks.Format

  alias Linx.NFT.{ParseError, Tokenizer}
  alias Linx.Netfilter.{Chain, Expr, Rule, Ruleset, Set, Table, Verdict, Wire}
  alias Linx.Netfilter.Map, as: NMap

  @doc """
  Emits `%Ruleset{}` as nft source. Always returns a binary; never
  raises.
  """
  @spec format(Ruleset.t()) :: String.t()
  def format(%Ruleset{tables: tables}) do
    tables
    |> Map.values()
    |> Enum.sort_by(fn t -> {Atom.to_string(t.family), t.name} end)
    |> Enum.map(&format_table/1)
    |> Enum.join("\n")
  end

  # ===========================================================
  # Tables
  # ===========================================================

  defp format_table(%Table{family: f, name: n, chains: chains, sets: sets, maps: maps}) do
    body_parts =
      Enum.concat([
        Enum.sort_by(Map.values(sets), & &1.name) |> Enum.map(&format_set/1),
        Enum.sort_by(Map.values(maps), & &1.name) |> Enum.map(&format_map/1),
        Enum.sort_by(Map.values(chains), & &1.name) |> Enum.map(&format_chain/1)
      ])

    body = Enum.join(body_parts, "\n\n")
    "table #{f} #{n} {\n#{indent(body, 2)}\n}\n"
  end

  # ===========================================================
  # Chains
  # ===========================================================

  defp format_chain(%Chain{name: n, type: t, hook: h, priority: p, policy: pol, rules: rules}) do
    header =
      [
        format_base_header(t, h, p),
        if(pol, do: "policy #{pol}", else: nil)
      ]
      |> Enum.reject(&is_nil/1)
      |> Enum.join("\n")

    rules_text =
      rules
      |> Enum.map(&format_rule/1)
      |> Enum.join("\n")

    body =
      cond do
        header != "" and rules_text != "" -> header <> "\n\n" <> rules_text
        header != "" -> header
        true -> rules_text
      end

    "chain #{n} {\n#{indent(body, 2)}\n}"
  end

  defp format_base_header(nil, _, _), do: nil
  defp format_base_header(_, nil, _), do: nil
  defp format_base_header(_, _, nil), do: nil
  defp format_base_header(t, h, p), do: "type #{t} hook #{h} priority #{p}"

  # ===========================================================
  # Sets / maps
  # ===========================================================

  defp format_set(%Set{name: name, key_type: kt, flags: flags, elements: elems, timeout: to}) do
    body =
      [
        "type #{kt}",
        if(flags != [] and flags != [nil],
          do: "flags #{Enum.join(flags, ", ")}",
          else: nil
        ),
        if(to, do: "timeout #{format_seconds(to)}", else: nil),
        if(elems != [],
          do: "elements = { #{elems |> Enum.map(&format_set_value/1) |> Enum.join(", ")} }",
          else: nil
        )
      ]
      |> Enum.reject(&is_nil/1)
      |> Enum.join("\n")

    "set #{name} {\n#{indent(body, 2)}\n}"
  end

  defp format_map(%NMap{
         name: name,
         key_type: kt,
         data_type: dt,
         flags: flags,
         elements: elems,
         timeout: to
       }) do
    keyword = if dt == :verdict, do: "vmap", else: "map"

    body =
      [
        "type #{kt} : #{dt}",
        if(flags != [] and flags != [nil],
          do: "flags #{Enum.join(flags, ", ")}",
          else: nil
        ),
        if(to, do: "timeout #{format_seconds(to)}", else: nil),
        if(elems != [],
          do: "elements = { #{elems |> Enum.map(&format_map_element/1) |> Enum.join(", ")} }",
          else: nil
        )
      ]
      |> Enum.reject(&is_nil/1)
      |> Enum.join("\n")

    "#{keyword} #{name} {\n#{indent(body, 2)}\n}"
  end

  defp format_set_value({:range, lo, hi}), do: "#{lo}-#{hi}"
  defp format_set_value(v) when is_integer(v), do: Integer.to_string(v)
  defp format_set_value(v) when is_binary(v), do: v
  defp format_set_value(other), do: inspect(other)

  # Like format_set_value/1 but key-type-aware. For :ifname sets,
  # element strings need to be quoted so the parser reads them
  # back as `:string` tokens (bare `eth0.10` would lex as
  # `ident . int` since `.` isn't an identifier char).
  defp render_set_element({:range, lo, hi}, _kt), do: "#{lo}-#{hi}"
  defp render_set_element(v, _kt) when is_integer(v), do: Integer.to_string(v)
  defp render_set_element(v, :ifname) when is_binary(v), do: ~s/"#{v}"/
  defp render_set_element(v, _kt) when is_binary(v), do: v
  defp render_set_element(other, _kt), do: inspect(other)

  defp format_map_element({key, %Verdict{} = v}),
    do: "#{format_set_value(key)} : #{format_verdict(v)}"

  defp format_map_element({key, value}),
    do: "#{format_set_value(key)} : #{format_set_value(value)}"

  defp format_seconds(secs) when is_integer(secs) do
    cond do
      rem(secs, 604_800) == 0 -> "#{div(secs, 604_800)}w"
      rem(secs, 86_400) == 0 -> "#{div(secs, 86_400)}d"
      rem(secs, 3600) == 0 -> "#{div(secs, 3600)}h"
      rem(secs, 60) == 0 -> "#{div(secs, 60)}m"
      true -> "#{secs}s"
    end
  end

  # ===========================================================
  # Rules
  # ===========================================================

  defp format_rule(%Rule{expressions: exprs, comment: comment}) do
    stmts = format_exprs(exprs)
    pieces = if comment, do: stmts ++ [~s/comment "#{escape_string(comment)}"/], else: stmts
    Enum.join(pieces, " ")
  end

  defp format_exprs(exprs), do: do_format_exprs(exprs, [])

  defp do_format_exprs([], acc), do: Enum.reverse(acc)

  # ---- payload + cmp ----
  defp do_format_exprs(
         [
           %Expr{name: :payload, data: %{base: b, offset: o, len: l}},
           %Expr{name: :cmp, data: %{op: op, value: v}}
           | rest
         ],
         acc
       ) do
    field = payload_field(b, o, l)
    rhs = render_payload_value(v, b, o, l)
    stmt = stmt(field, render_op(op), rhs)
    do_format_exprs(rest, [stmt | acc])
  end

  # ---- payload + bitwise + cmp → CIDR ----
  defp do_format_exprs(
         [
           %Expr{name: :payload, data: %{base: b, offset: o, len: l}},
           %Expr{name: :bitwise, data: %{mask: mask}},
           %Expr{name: :cmp, data: %{op: op, value: v}}
           | rest
         ],
         acc
       ) do
    field = payload_field(b, o, l)
    prefix = bitwise_prefix_len(mask)
    addr = render_address(v, l)
    stmt = stmt(field, render_op(op), "#{addr}/#{prefix}")
    do_format_exprs(rest, [stmt | acc])
  end

  # ---- payload + lookup → set ref / anon set ----
  defp do_format_exprs(
         [
           %Expr{name: :payload, data: %{base: b, offset: o, len: l}},
           %Expr{name: :lookup, data: %{set: name}}
           | rest
         ],
         acc
       ) do
    field = payload_field(b, o, l)
    do_format_exprs(rest, ["#{field} @#{name}" | acc])
  end

  defp do_format_exprs(
         [
           %Expr{name: :payload, data: %{base: b, offset: o, len: l}},
           %Expr{name: :__anon_set, data: %{values: vals, key_type: kt}}
           | rest
         ],
         acc
       ) do
    field = payload_field(b, o, l)
    rendered = vals |> Enum.map(&render_set_element(&1, kt)) |> Enum.join(", ")
    do_format_exprs(rest, ["#{field} { #{rendered} }" | acc])
  end

  # ---- meta + cmp ----
  defp do_format_exprs(
         [
           %Expr{name: :meta, data: %{key: key}},
           %Expr{name: :cmp, data: %{op: op, value: v}}
           | rest
         ],
         acc
       ) do
    rhs = render_meta_value(key, v)
    do_format_exprs(rest, [stmt("meta #{key}", render_op(op), rhs) | acc])
  end

  # ---- meta + __anon_set — inline-set match on a meta field
  # (e.g. `iifname { "eth0", "wg0" }`). The set's key_type tells
  # us whether to render elements as strings-with-quotes (:ifname)
  # or bare integers (:mark / :inet_proto / etc.). ----
  defp do_format_exprs(
         [
           %Expr{name: :meta, data: %{key: key}},
           %Expr{name: :__anon_set, data: %{values: vals, key_type: kt}}
           | rest
         ],
         acc
       ) do
    rendered = vals |> Enum.map(&render_set_element(&1, kt)) |> Enum.join(", ")
    do_format_exprs(rest, ["meta #{key} { #{rendered} }" | acc])
  end

  defp do_format_exprs(
         [
           %Expr{name: :meta, data: %{key: key}},
           %Expr{name: :lookup, data: %{set: name}}
           | rest
         ],
         acc
       ) do
    do_format_exprs(rest, ["meta #{key} @#{name}" | acc])
  end

  # ---- ct state (compiler emits bitwise + cmp_neq/eq_0 — the
  # kernel-correct bitmask check pattern). Decode by reading the
  # bitwise mask back into a list of state names and inverting the
  # cmp op (cmp_neq_0 means "user wrote :eq", cmp_eq_0 means
  # "user wrote :neq").
  defp do_format_exprs(
         [
           %Expr{name: :ct, data: %{key: :state}},
           %Expr{name: :bitwise, data: %{mask: mask}},
           %Expr{name: :cmp, data: %{op: cmp_op, value: cmp_v}}
           | rest
         ],
         acc
       ) do
    bits = :binary.decode_unsigned(mask)
    states = bits_to_ct_states(bits)
    user_op = invert_ct_cmp_op(cmp_op, :binary.decode_unsigned(cmp_v))
    rhs = if length(states) == 1, do: Enum.at(states, 0), else: "{ #{Enum.join(states, ", ")} }"
    do_format_exprs(rest, [stmt("ct state", render_op(user_op), rhs) | acc])
  end

  # Fallback for pulled-from-kernel ct state rules that may use
  # the older ct + cmp shape directly (older kernels / older nft
  # output).
  defp do_format_exprs(
         [
           %Expr{name: :ct, data: %{key: :state}},
           %Expr{name: :cmp, data: %{op: op, value: v}}
           | rest
         ],
         acc
       ) do
    bits = :binary.decode_unsigned(v)
    states = bits_to_ct_states(bits)
    rhs = if length(states) == 1, do: Enum.at(states, 0), else: "{ #{Enum.join(states, ", ")} }"
    do_format_exprs(rest, [stmt("ct state", render_op(op), rhs) | acc])
  end

  defp do_format_exprs(
         [
           %Expr{name: :ct, data: %{key: key}},
           %Expr{name: :cmp, data: %{op: op, value: v}}
           | rest
         ],
         acc
       ) do
    rhs = :binary.decode_unsigned(v)
    do_format_exprs(rest, [stmt("ct #{key}", render_op(op), Integer.to_string(rhs)) | acc])
  end

  defp invert_ct_cmp_op(:neq, 0), do: :eq
  defp invert_ct_cmp_op(:eq, 0), do: :neq
  defp invert_ct_cmp_op(other, _), do: other

  # ---- verdicts ----
  defp do_format_exprs([%Expr{name: :immediate, data: %Verdict{} = v} | rest], acc) do
    do_format_exprs(rest, [format_verdict(v) | acc])
  end

  defp do_format_exprs([%Expr{name: :immediate, data: %{value: %Verdict{} = v}} | rest], acc) do
    do_format_exprs(rest, [format_verdict(v) | acc])
  end

  # ---- counter ----
  defp do_format_exprs([%Expr{name: :counter, data: %{packets: 0, bytes: 0}} | rest], acc) do
    do_format_exprs(rest, ["counter" | acc])
  end

  defp do_format_exprs([%Expr{name: :counter, data: %{packets: p, bytes: b}} | rest], acc) do
    do_format_exprs(rest, ["counter packets #{p} bytes #{b}" | acc])
  end

  # ---- log ----
  defp do_format_exprs([%Expr{name: :log, data: data} | rest], acc) do
    parts =
      [
        if(data[:prefix], do: ~s/prefix "#{escape_string(data[:prefix])}"/, else: nil),
        if(data[:group], do: "group #{data[:group]}", else: nil),
        if(data[:level], do: "level #{data[:level]}", else: nil)
      ]
      |> Enum.reject(&is_nil/1)

    text = ["log" | parts] |> Enum.join(" ")
    do_format_exprs(rest, [text | acc])
  end

  # ---- reject ----
  defp do_format_exprs([%Expr{name: :reject, data: %{type: type}} | rest], acc) do
    text =
      case type do
        :tcp_reset -> "reject with tcp reset"
        :icmpx_unreach -> "reject"
        _ -> "reject"
      end

    do_format_exprs(rest, [text | acc])
  end

  # ---- masq / nat / redirect ----
  defp do_format_exprs([%Expr{name: :masq, data: %{flags: flags}} | rest], acc) do
    do_format_exprs(rest, [
      ["masquerade" | flag_strings(flags)] |> Enum.join(" ") |> String.trim() | acc
    ])
  end

  # NAT shape: immediate(addr) [immediate(port)] nat
  defp do_format_exprs(
         [
           %Expr{name: :immediate, data: %{value: addr_bytes, dreg: _}},
           %Expr{name: :nat, data: nat_data} | rest
         ],
         acc
       ) do
    text = format_nat(nat_data, addr_bytes, nil)
    do_format_exprs(rest, [text | acc])
  end

  defp do_format_exprs(
         [
           %Expr{name: :immediate, data: %{value: addr_bytes, dreg: _}},
           %Expr{name: :immediate, data: %{value: <<port::big-16>>, dreg: _}},
           %Expr{name: :nat, data: nat_data} | rest
         ],
         acc
       ) do
    text = format_nat(nat_data, addr_bytes, port)
    do_format_exprs(rest, [text | acc])
  end

  defp do_format_exprs([%Expr{name: :nat, data: nat_data} | rest], acc) do
    text = format_nat(nat_data, nil, nil)
    do_format_exprs(rest, [text | acc])
  end

  defp do_format_exprs([%Expr{name: :redir, data: %{flags: flags}} | rest], acc) do
    do_format_exprs(rest, [
      ["redirect" | flag_strings(flags)] |> Enum.join(" ") |> String.trim() | acc
    ])
  end

  # ---- catchall: emit an in-line comment so the output remains
  # valid nft and the gap is visible.
  defp do_format_exprs([expr | rest], acc) do
    do_format_exprs(rest, ["# <unsupported expression: #{inspect(expr.name)}>" | acc])
  end

  defp format_nat(%{type: type}, addr_bytes, port) do
    addr_text =
      case addr_bytes do
        nil -> ""
        bin when byte_size(bin) == 4 -> render_ipv4(bin)
        bin when byte_size(bin) == 16 -> render_ipv6(bin)
        _ -> "?"
      end

    port_text = if port, do: ":#{port}", else: ""

    "#{type} to #{addr_text}#{port_text}"
    |> String.trim_trailing(" to ")
    |> String.trim_trailing(" to")
  end

  defp format_verdict(%Verdict{kind: :accept}), do: "accept"
  defp format_verdict(%Verdict{kind: :drop}), do: "drop"
  defp format_verdict(%Verdict{kind: :continue}), do: "continue"
  defp format_verdict(%Verdict{kind: :return}), do: "return"
  defp format_verdict(%Verdict{kind: :queue}), do: "queue"
  defp format_verdict(%Verdict{kind: :jump, target: t}), do: "jump #{t}"
  defp format_verdict(%Verdict{kind: :goto, target: t}), do: "goto #{t}"
  defp format_verdict(%Verdict{kind: kind}), do: Atom.to_string(kind)

  defp flag_strings(flags) when is_list(flags) do
    flags |> Enum.map(&Atom.to_string/1)
  end

  defp flag_strings(_), do: []

  # ===========================================================
  # Payload / meta / address rendering
  # ===========================================================

  defp payload_field(:transport, 0, 2), do: "tcp sport"
  defp payload_field(:transport, 2, 2), do: "tcp dport"
  defp payload_field(:transport, 0, 1), do: "icmp type"
  defp payload_field(:transport, 1, 1), do: "icmp code"
  defp payload_field(:network, 9, 1), do: "ip protocol"
  defp payload_field(:network, 12, 4), do: "ip saddr"
  defp payload_field(:network, 16, 4), do: "ip daddr"
  defp payload_field(:network, 8, 16), do: "ip6 saddr"
  defp payload_field(:network, 24, 16), do: "ip6 daddr"
  defp payload_field(base, o, l), do: "@#{base},#{o},#{l}"

  defp render_payload_value(v, :transport, _o, 2),
    do: Integer.to_string(:binary.decode_unsigned(v))

  defp render_payload_value(v, :transport, _o, 1),
    do: Integer.to_string(:binary.decode_unsigned(v))

  defp render_payload_value(v, :network, _o, 4) when byte_size(v) == 4, do: render_ipv4(v)
  defp render_payload_value(v, :network, _o, 16) when byte_size(v) == 16, do: render_ipv6(v)
  defp render_payload_value(v, :network, 9, 1), do: render_ip_protocol(v)
  defp render_payload_value(v, _, _, _), do: inspect(v)

  defp render_address(v, 4) when byte_size(v) == 4, do: render_ipv4(v)
  defp render_address(v, 16) when byte_size(v) == 16, do: render_ipv6(v)
  defp render_address(v, _), do: inspect(v)

  defp render_ipv4(<<a, b, c, d>>), do: "#{a}.#{b}.#{c}.#{d}"

  defp render_ipv6(<<bytes::binary-size(16)>>) do
    Linx.IP.to_string(%Linx.IP{family: :inet6, bytes: bytes})
  end

  defp render_meta_value(:iifname, v) when is_binary(v), do: ~s/"#{trim_ifname(v)}"/
  defp render_meta_value(:oifname, v) when is_binary(v), do: ~s/"#{trim_ifname(v)}"/

  defp render_meta_value(_, v) when is_binary(v) and byte_size(v) <= 8,
    do: Integer.to_string(:binary.decode_unsigned(v))

  defp render_meta_value(_, v) when is_binary(v), do: inspect(v)

  defp trim_ifname(v) do
    v |> String.replace_trailing(<<0>>, "") |> String.trim_trailing(<<0>>)
  end

  defp render_ip_protocol(<<6>>), do: "tcp"
  defp render_ip_protocol(<<17>>), do: "udp"
  defp render_ip_protocol(<<1>>), do: "icmp"
  defp render_ip_protocol(<<58>>), do: "icmpv6"
  defp render_ip_protocol(<<n>>), do: Integer.to_string(n)

  # Counts the leading 1-bits of `mask` (assumes contiguous prefix
  # of 1-bits — the only shape produced by ipv4_mask/1 and
  # ipv6_mask/1 in the compiler).
  defp bitwise_prefix_len(mask) when is_binary(mask) do
    bits = byte_size(mask) * 8
    int = :binary.decode_unsigned(mask)
    count_leading_ones(int, bits)
  end

  defp count_leading_ones(0, _bits), do: 0

  defp count_leading_ones(int, bits) do
    Enum.reduce_while((bits - 1)..0//-1, 0, fn pos, acc ->
      if Bitwise.band(Bitwise.bsr(int, pos), 1) == 1 do
        {:cont, acc + 1}
      else
        {:halt, acc}
      end
    end)
  end

  # ===========================================================
  # ct state bits → atoms
  # ===========================================================

  defp bits_to_ct_states(bits) do
    [:new, :established, :related, :invalid, :untracked]
    |> Enum.filter(fn name ->
      try do
        Bitwise.band(bits, Wire.ct_state_bits(name)) != 0
      rescue
        _ -> false
      end
    end)
    |> Enum.map(&Atom.to_string/1)
  end

  # ===========================================================
  # Plumbing
  # ===========================================================

  defp render_op(:eq), do: nil
  defp render_op(:neq), do: "!="
  defp render_op(:lt), do: "<"
  defp render_op(:lte), do: "<="
  defp render_op(:gt), do: ">"
  defp render_op(:gte), do: ">="

  defp stmt(lhs, nil, rhs), do: "#{lhs} #{rhs}"
  defp stmt(lhs, op, rhs), do: "#{lhs} #{op} #{rhs}"

  defp escape_string(s), do: String.replace(s, ~s/"/, ~S/\"/)

  defp indent(text, n) do
    pad = String.duplicate(" ", n)

    text
    |> String.split("\n")
    |> Enum.map(fn line -> if line == "", do: "", else: pad <> line end)
    |> Enum.join("\n")
  end

  # ===========================================================
  # Mix.Tasks.Format behaviour — `mix format` plugin entry points
  # ===========================================================

  @impl Mix.Tasks.Format
  def features(_formatter_opts) do
    [sigils: [:NFT], extensions: [".nft"]]
  end

  @impl Mix.Tasks.Format
  def format(source, formatter_opts) when is_binary(source) do
    cond do
      formatter_opts[:sigil] == :NFT -> format_sigil_body(source, formatter_opts)
      formatter_opts[:extension] == ".nft" -> format_nft_file(source, formatter_opts)
      true -> source
    end
  end

  defp format_sigil_body(source, opts) do
    file = opts[:file] || "nofile"
    line = opts[:line] || 1

    # Detect interpolations by tokenizing in :interpolation? mode.
    # If any :elixir_expr tokens are present we leave the body
    # untouched — preserving `\#{…}` positions while reflowing the
    # rest is a richer formatter capability that hasn't been built
    # yet (it'd need an AST-to-source emitter; the existing
    # Formatter walks compiled %Expr{}s).
    case Tokenizer.tokenize(source, file: file, line: line, interpolation?: true) do
      {:ok, tokens} ->
        if has_interpolation?(tokens) do
          source
        else
          format_static_body(source, file)
        end

      {:error, _err} ->
        # Tokenization failure — pass through unchanged. The compile
        # run will surface the same error with better context.
        source
    end
  end

  defp format_nft_file(source, opts) do
    file = opts[:file] || "nofile"

    case Linx.NFT.parse(source, file: file) do
      {:ok, ruleset} -> format(ruleset)
      {:error, %ParseError{} = err} -> raise err
    end
  end

  defp format_static_body(source, file) do
    case Linx.NFT.parse(source, file: file) do
      {:ok, ruleset} ->
        # Sigil bodies live inside heredoc-style triple quotes;
        # trim the trailing newline that `format/1` always tacks
        # on so the closing `"""` doesn't end up with a blank line
        # in front of it.
        ruleset |> format() |> String.trim_trailing("\n")

      {:error, _err} ->
        # Same rationale as the tokenize-error branch above.
        source
    end
  end

  defp has_interpolation?(tokens) do
    Enum.any?(tokens, fn
      {:elixir_expr, _, _} -> true
      _ -> false
    end)
  end
end
