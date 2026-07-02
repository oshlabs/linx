defmodule Linx.NFT.Tokenizer do
  @moduledoc """
  Char-by-char lexer for the `~NFT` sigil and `.nft` files.

  Mirrors the architecture of `Phoenix.LiveView.TagEngine.Tokenizer`
  and of nft's own `src/scanner.l`: an explicit stack of
  **start conditions** (lex states) lets context-sensitive
  constructs add a new state without disturbing the rest of the
  lexer.

  The conditions in play:

    * `:default` — top-level lexing of keywords, identifiers,
      literals, operators, punctuation, statement separators.
    * `:line_comment` — `#` to end of line.
    * `:block_comment` — `/* ... */`; supports nesting. NOTE:
      block comments are a Linx extension — nft itself has *no*
      block comments (its `scanner.l` knows only `#` line
      comments), so files using them are not loadable with
      `nft -f`. Accepted inbound for convenience; the formatter
      never emits them.
    * `:string` — `"..."`. By default this matches nft's scanner
      exactly (`\\"[^"]*\\"`): **no escape processing** — a
      backslash is a literal byte and the string ends at the
      first `"`. With `escapes?: true` (set by the `~NFT` sigil)
      the Elixir-style escapes `\\\\`/`\\"`/`\\n`/`\\t`/`\\r`/`\\0`
      are processed — a documented sigil-only convenience.
      (String-internal Elixir interpolation is not yet
      supported — it'll push `:elixir_expr` from `:string` when
      added, no other change required.)
    * `:elixir_expr` — only enterable when the `:interpolation?`
      option is true. Scans an Elixir expression up to the
      matching `}`, skipping `}` characters that appear inside
      strings/charlists/comments inside the expression.

  ## Token shape

  Each token is a 2- or 3-tuple:

      {:kind, meta}                # punctuation with no payload
      {:kind, value, meta}         # everything else

  where `meta` is `%{line: pos_integer(), column: pos_integer()}`
  pointing at the *start* of the token.

  Identifiers are emitted as `{:identifier, "name", meta}` — the
  parser decides which names are keywords. (Pattern-matching on
  binaries is ergonomic in Elixir; this avoids a 200-entry
  keyword table here.)

  ## Statement separators

  In nft syntax, statements inside a `{ ... }` body are separated
  by either `;` or a newline. To keep parsing simple, the
  tokenizer emits a single `:stmt_sep` token for every `;` and
  for every (possibly multi-line) run of newlines, collapsing
  consecutive separators into one. Newlines that appear inside
  brackets are still emitted — the parser ignores spurious
  separators in positions where they're not meaningful.

  Line continuations (`\\\\\\n`) are consumed silently.

  ## Numeric / address literals

  Network primitives need a small lookahead to disambiguate:

    * `0x...` / `0X...` — hex integer.
    * `0b...` / `0B...` — binary integer (Linx extension; nft has
      no binary literals — the formatter never emits them).
    * `0...` (leading zero, more digits) — **octal** integer,
      matching nft's scanner (`scanner.l`: `base = yytext[0] ==
      '0' ? 8 : 10`). A leading-zero literal containing `8`/`9`
      is not a number (nft demotes it to a string) — it becomes
      a `:symbol` token here.
    * `\\d+` followed by no `.` or `:` or `/` — plain decimal integer.
    * `\\d+\\.\\d+\\.\\d+\\.\\d+` — IPv4 literal (optional `/N` CIDR).
    * IPv6: any run starting with hex chars that contains `:` and
      whose contents are valid IPv6 syntax.
    * MAC: six 2-char hex octets joined by `:`.
    * Time: nft's compound `timestring`
      (`([0-9]+d)?([0-9]+h)?([0-9]+m)?([0-9]+s)?([0-9]+ms)?`) —
      `30s`, `1h30m10s`, `250ms` — emitted as `{:time, ms, meta}`
      in **milliseconds** (the kernel's set-timeout unit).

  Identifiers that *happen* to begin with hex letters (e.g. `eth0`
  or even `fe80`) are still tagged as identifiers when not
  followed by `:`. If the identifier is all-hex and followed by
  `:` plus a hex char, the lexer rewinds and re-scans as an
  IPv6/MAC literal.

  Identifiers directly followed by `.`/`/` and more identifier
  characters continue as one token (`example.com`, `br-lan/wan0`),
  matching nft's bare-string pattern
  (`({letter}|[_.])({letter}|{digit}|[/\\-_\\.])*`). A spaced
  `.` is still the concatenation operator.

  ## Errors

  Following nft's design (its scanner cannot fail — stray bytes
  become a `JUNK` token the *grammar* rejects), a numeric-or-
  address-looking run the tokenizer can't classify is emitted as
  a `{:symbol, raw, meta}` token; the parser/compiler reject it
  with a located error where it isn't meaningful. Only structural
  problems (unterminated string/comment/interpolation, truly
  unexpected bytes) raise `Linx.NFT.ParseError` directly, carrying
  `{file, line, column}` and the offending source line. The caller
  (sigil macro, `parse/1`, `parse_file/1`) catches and either
  re-raises (compile-time) or returns `{:error, %ParseError{}}`.

  ## Extensibility

  All architectural decisions here were chosen for **incremental
  extension**, since the supported grammar is the common ~85%
  subset and the long tail of nft constructs (synproxy, secmark,
  osf, fib, jhash, advanced ct, dup/fwd, tproxy, xfrm, tunnel) will
  be added per-construct over time. Each addition becomes:

    1. (Optional) a new start condition pushed from somewhere in
       `:default` — add a clause and a step function.
    2. (Optional) a new token kind — extend the `@type token`
       union and the parser's pattern matches.

  The stack discipline means none of these touch existing
  conditions.
  """

  alias Linx.NFT.ParseError

  defmodule State do
    @moduledoc false

    @enforce_keys [
      :source,
      :original_source,
      :file,
      :line,
      :column,
      :tokens,
      :stack,
      :interpolation?
    ]

    defstruct [
      :source,
      :original_source,
      :file,
      :line,
      :column,
      :tokens,
      :stack,
      :interpolation?,
      escapes?: false,
      string_buf: nil,
      string_start: nil,
      expr_iodata: nil,
      expr_depth: 0,
      expr_start: nil
    ]
  end

  @type token_meta :: %{line: pos_integer(), column: pos_integer()}

  @type token ::
          {:identifier, String.t(), token_meta()}
          | {:integer, integer(), token_meta()}
          | {:string, String.t(), token_meta()}
          | {:ipv4, String.t(), token_meta()}
          | {:ipv6, String.t(), token_meta()}
          | {:mac, String.t(), token_meta()}
          | {:cidr_v4, String.t(), token_meta()}
          | {:cidr_v6, String.t(), token_meta()}
          | {:time, non_neg_integer(), token_meta()}
          | {:symbol, String.t(), token_meta()}
          | {:elixir_expr, String.t(), token_meta()}
          | {:stmt_sep, token_meta()}
          | {atom(), token_meta()}

  @doc """
  Tokenizes `source` into a flat list of tokens.

  ## Options

    * `:file` — source filename for error messages
      (default `"nofile"`).
    * `:line` — starting line number (default `1`); useful when
      called from a `~NFT` sigil with `__CALLER__.line` to make
      error locations line up with the surrounding `.ex` source.
    * `:column` — starting column number (default `1`).
    * `:interpolation?` — whether to recognize `\#{...}` Elixir
      interpolation (default `false`). The sigil sets this to
      `true`; `parse/1` / `parse_file/1` leave it `false`.
    * `:escapes?` — whether to process Elixir-style escape
      sequences inside `"..."` string literals (default `false`,
      which matches nft's scanner exactly: backslash is a literal
      byte, the string ends at the first `"`). The sigil sets
      this to `true`.

  Returns `{:ok, tokens}` or `{:error, %Linx.NFT.ParseError{}}`.
  """
  @spec tokenize(String.t(), keyword()) ::
          {:ok, [token()]} | {:error, ParseError.t()}
  def tokenize(source, opts \\ []) when is_binary(source) do
    state = %State{
      source: source,
      original_source: source,
      file: Keyword.get(opts, :file, "nofile"),
      line: Keyword.get(opts, :line, 1),
      column: Keyword.get(opts, :column, 1),
      tokens: [],
      stack: [:default],
      interpolation?: Keyword.get(opts, :interpolation?, false),
      escapes?: Keyword.get(opts, :escapes?, false)
    }

    try do
      {:ok, do_tokenize(state)}
    rescue
      e in ParseError -> {:error, e}
    end
  end

  # ===========================================================
  # Main loop
  # ===========================================================

  defp do_tokenize(%State{source: "", stack: [:default], tokens: tokens}) do
    Enum.reverse(tokens)
  end

  # EOF policy per state. Line comments terminate cleanly; the
  # rest are unterminated and become parse errors with the
  # *opening* token's location.
  defp do_tokenize(%State{source: "", stack: [:line_comment | _]} = state) do
    state |> pop_stack() |> do_tokenize()
  end

  defp do_tokenize(%State{source: "", stack: [:string | _]} = state) do
    raise_unterminated!(state, :string)
  end

  defp do_tokenize(%State{source: "", stack: [:block_comment | _]} = state) do
    raise_unterminated!(state, :block_comment)
  end

  defp do_tokenize(%State{source: "", stack: [:elixir_expr | _]} = state) do
    raise_unterminated!(state, :elixir_expr)
  end

  defp do_tokenize(%State{stack: [top | _]} = state) do
    state
    |> step(top)
    |> do_tokenize()
  end

  defp step(state, :default), do: default_step(state)
  defp step(state, :string), do: string_step(state)
  defp step(state, :line_comment), do: line_comment_step(state)
  defp step(state, :block_comment), do: block_comment_step(state)
  defp step(state, :elixir_expr), do: elixir_expr_step(state)

  # ===========================================================
  # :default state
  # ===========================================================

  defp default_step(state) do
    case state.source do
      # ----------- Newlines & line continuations -----------
      <<"\r\n", rest::binary>> ->
        state |> emit_stmt_sep() |> advance_line(rest)

      <<"\n", rest::binary>> ->
        state |> emit_stmt_sep() |> advance_line(rest)

      <<"\r", rest::binary>> ->
        state |> emit_stmt_sep() |> advance_line(rest)

      <<"\\", "\r\n", rest::binary>> ->
        advance_line(state, rest)

      <<"\\", "\n", rest::binary>> ->
        advance_line(state, rest)

      # ----------- Horizontal whitespace -----------
      <<" ", rest::binary>> ->
        advance_col(state, rest, 1)

      <<"\t", rest::binary>> ->
        advance_col(state, rest, 1)

      # ----------- Explicit statement separator -----------
      <<";", rest::binary>> ->
        state |> emit_stmt_sep() |> advance_col(rest, 1)

      # ----------- Block comment -----------
      <<"/*", rest::binary>> ->
        state |> push_stack(:block_comment) |> advance_col(rest, 2)

      # ----------- Elixir interpolation `#{...}` -----------
      # MUST come before the `#` line-comment clause.
      <<?#, ?{, rest::binary>> when state.interpolation? == true ->
        state
        |> push_stack(:elixir_expr)
        |> start_elixir_expr()
        |> advance_col(rest, 2)

      # ----------- Line comment `# ...` -----------
      <<"#", rest::binary>> ->
        state |> push_stack(:line_comment) |> advance_col(rest, 1)

      # ----------- String literal -----------
      <<"\"", rest::binary>> ->
        state |> push_stack(:string) |> start_string() |> advance_col(rest, 1)

      # ----------- Multi-char operators -----------
      <<"<<", rest::binary>> ->
        emit_punct(state, :lshift, rest, 2)

      <<">>", rest::binary>> ->
        emit_punct(state, :rshift, rest, 2)

      <<"<=", rest::binary>> ->
        emit_punct(state, :lte, rest, 2)

      <<">=", rest::binary>> ->
        emit_punct(state, :gte, rest, 2)

      <<"==", rest::binary>> ->
        emit_punct(state, :eq, rest, 2)

      <<"!=", rest::binary>> ->
        emit_punct(state, :neq, rest, 2)

      <<"&&", rest::binary>> ->
        emit_punct(state, :and_and, rest, 2)

      <<"||", rest::binary>> ->
        emit_punct(state, :or_or, rest, 2)

      # ----------- Single-char punctuation -----------
      <<"{", rest::binary>> ->
        emit_punct(state, :lbrace, rest, 1)

      <<"}", rest::binary>> ->
        emit_punct(state, :rbrace, rest, 1)

      <<"(", rest::binary>> ->
        emit_punct(state, :lparen, rest, 1)

      <<")", rest::binary>> ->
        emit_punct(state, :rparen, rest, 1)

      <<"[", rest::binary>> ->
        emit_punct(state, :lbracket, rest, 1)

      <<"]", rest::binary>> ->
        emit_punct(state, :rbracket, rest, 1)

      <<",", rest::binary>> ->
        emit_punct(state, :comma, rest, 1)

      <<"=", rest::binary>> ->
        emit_punct(state, :assign, rest, 1)

      <<"!", rest::binary>> ->
        emit_punct(state, :bang, rest, 1)

      <<"<", rest::binary>> ->
        emit_punct(state, :lt, rest, 1)

      <<">", rest::binary>> ->
        emit_punct(state, :gt, rest, 1)

      <<"&", rest::binary>> ->
        emit_punct(state, :amp, rest, 1)

      <<"|", rest::binary>> ->
        emit_punct(state, :pipe, rest, 1)

      <<"^", rest::binary>> ->
        emit_punct(state, :caret, rest, 1)

      <<"*", rest::binary>> ->
        emit_punct(state, :star, rest, 1)

      <<"-", rest::binary>> ->
        emit_punct(state, :dash, rest, 1)

      # `+` appears only in priority offsets (`priority filter + 10`).
      <<"+", rest::binary>> ->
        emit_punct(state, :plus, rest, 1)

      <<"/", rest::binary>> ->
        emit_punct(state, :slash, rest, 1)

      <<"@", rest::binary>> ->
        emit_punct(state, :at, rest, 1)

      <<"$", rest::binary>> ->
        emit_punct(state, :dollar, rest, 1)

      # A `.` that's followed by whitespace, identifier, or EOF —
      # type concatenation as in `type ipv4_addr . inet_service`.
      # The `.` inside numeric/address literals is consumed earlier
      # by `read_numeric_or_address` / `read_identifier`.
      <<".", rest::binary>> ->
        emit_punct(state, :dot, rest, 1)

      # ----------- Numeric literals -----------
      <<"0x", _::binary>> ->
        read_hex_integer(state)

      <<"0X", _::binary>> ->
        read_hex_integer(state)

      <<"0b", _::binary>> ->
        read_bin_integer(state)

      <<"0B", _::binary>> ->
        read_bin_integer(state)

      # A literal starting with `::` is an IPv6 address (e.g. `::1`,
      # `::/0`, the loopback shorthand `::`). Disambiguates from the
      # `:colon` vmap-key separator below.
      <<"::", _::binary>> ->
        read_numeric_or_address(state)

      <<c, _::binary>> when c >= ?0 and c <= ?9 ->
        read_numeric_or_address(state)

      # Stand-alone colon (vmap `key : value`, or other separators).
      <<":", rest::binary>> ->
        emit_punct(state, :colon, rest, 1)

      # ----------- Identifier -----------
      <<c, _::binary>>
      when (c >= ?a and c <= ?z) or (c >= ?A and c <= ?Z) or c == ?_ ->
        read_identifier(state)

      # ----------- Errors -----------
      <<c::utf8, _::binary>> ->
        raise_at!(state, "unexpected character #{inspect(<<c::utf8>>)}")
    end
  end

  # ===========================================================
  # :line_comment state — swallow to end of line
  # ===========================================================

  defp line_comment_step(%State{source: ""} = state) do
    pop_stack(state)
  end

  defp line_comment_step(%State{source: <<"\r\n", _::binary>>} = state) do
    pop_stack(state)
  end

  defp line_comment_step(%State{source: <<"\n", _::binary>>} = state) do
    pop_stack(state)
  end

  defp line_comment_step(%State{source: <<"\r", _::binary>>} = state) do
    pop_stack(state)
  end

  defp line_comment_step(%State{source: <<_::utf8, rest::binary>>} = state) do
    %{state | source: rest, column: state.column + 1}
  end

  # ===========================================================
  # :block_comment state — `/* ... */`, nests
  # ===========================================================

  defp block_comment_step(%State{source: <<"*/", rest::binary>>} = state) do
    state |> pop_stack() |> advance_col(rest, 2)
  end

  defp block_comment_step(%State{source: <<"/*", rest::binary>>} = state) do
    # Nest — push another :block_comment so we need a matching */.
    state |> push_stack(:block_comment) |> advance_col(rest, 2)
  end

  defp block_comment_step(%State{source: <<"\r\n", rest::binary>>} = state) do
    advance_line(state, rest)
  end

  defp block_comment_step(%State{source: <<"\n", rest::binary>>} = state) do
    advance_line(state, rest)
  end

  defp block_comment_step(%State{source: <<"\r", rest::binary>>} = state) do
    advance_line(state, rest)
  end

  defp block_comment_step(%State{source: <<_::utf8, rest::binary>>} = state) do
    %{state | source: rest, column: state.column + 1}
  end

  # ===========================================================
  # :string state
  # ===========================================================

  defp start_string(state) do
    %{state | string_buf: [], string_start: %{line: state.line, column: state.column}}
  end

  defp string_step(%State{source: <<"\"", rest::binary>>} = state) do
    value = state.string_buf |> Enum.reverse() |> IO.iodata_to_binary()
    meta = state.string_start

    %{
      state
      | tokens: [{:string, value, meta} | state.tokens],
        string_buf: nil,
        string_start: nil
    }
    |> pop_stack()
    |> advance_col(rest, 1)
  end

  # ---- escapes (sigil-only: `escapes?: true`) ----
  # In the default nft-exact mode a backslash is a literal byte
  # (nft's pattern is `\"[^"]*\"` — no escapes), handled by the
  # generic char clause below.
  defp string_step(%State{escapes?: true, source: <<"\\\"", rest::binary>>} = state) do
    %{state | source: rest, column: state.column + 2, string_buf: ["\"" | state.string_buf]}
  end

  defp string_step(%State{escapes?: true, source: <<"\\\\", rest::binary>>} = state) do
    %{state | source: rest, column: state.column + 2, string_buf: ["\\" | state.string_buf]}
  end

  defp string_step(%State{escapes?: true, source: <<"\\n", rest::binary>>} = state) do
    %{state | source: rest, column: state.column + 2, string_buf: ["\n" | state.string_buf]}
  end

  defp string_step(%State{escapes?: true, source: <<"\\t", rest::binary>>} = state) do
    %{state | source: rest, column: state.column + 2, string_buf: ["\t" | state.string_buf]}
  end

  defp string_step(%State{escapes?: true, source: <<"\\r", rest::binary>>} = state) do
    %{state | source: rest, column: state.column + 2, string_buf: ["\r" | state.string_buf]}
  end

  defp string_step(%State{escapes?: true, source: <<"\\0", rest::binary>>} = state) do
    %{state | source: rest, column: state.column + 2, string_buf: [<<0>> | state.string_buf]}
  end

  # Unknown escape: keep the char literally (lenient).
  defp string_step(%State{escapes?: true, source: <<"\\", c::utf8, rest::binary>>} = state) do
    %{
      state
      | source: rest,
        column: state.column + 2,
        string_buf: [<<c::utf8>> | state.string_buf]
    }
  end

  # Unterminated newline inside string literal — nft doesn't allow
  # raw newlines inside `"..."`. Report at the opening quote.
  defp string_step(%State{source: <<"\n", _::binary>>} = state) do
    ParseError.raise_syntax_error!(string_start_ctx(state), "unterminated string literal")
  end

  defp string_step(%State{source: <<"\r", _::binary>>} = state) do
    ParseError.raise_syntax_error!(string_start_ctx(state), "unterminated string literal")
  end

  defp string_step(%State{source: <<c::utf8, rest::binary>>} = state) do
    %{
      state
      | source: rest,
        column: state.column + 1,
        string_buf: [<<c::utf8>> | state.string_buf]
    }
  end

  defp string_step(%State{source: ""} = state) do
    ParseError.raise_syntax_error!(string_start_ctx(state), "unterminated string literal")
  end

  defp string_start_ctx(state) do
    %{
      file: state.file,
      line: state.string_start.line,
      column: state.string_start.column,
      snippet: snippet_for(state.original_source, state.string_start.line)
    }
  end

  # ===========================================================
  # :elixir_expr state
  # ===========================================================

  defp start_elixir_expr(state) do
    # `state.column` is the column of `#`; we record that as the
    # interpolation's opening location so unterminated-`}` errors
    # point at the right spot.
    %{
      state
      | expr_iodata: [],
        expr_depth: 1,
        expr_start: %{line: state.line, column: state.column}
    }
  end

  # The matching `}` for the opening `#{` — emit the captured raw
  # expression as a token and pop back to the caller condition.
  defp elixir_expr_step(%State{source: <<"}", rest::binary>>, expr_depth: 1} = state) do
    raw = state.expr_iodata |> Enum.reverse() |> IO.iodata_to_binary()
    meta = state.expr_start

    %{
      state
      | tokens: [{:elixir_expr, raw, meta} | state.tokens],
        expr_iodata: nil,
        expr_depth: 0,
        expr_start: nil
    }
    |> pop_stack()
    |> advance_col(rest, 1)
  end

  defp elixir_expr_step(%State{source: <<"}", rest::binary>>, expr_depth: d} = state) do
    %{
      state
      | source: rest,
        column: state.column + 1,
        expr_iodata: ["}" | state.expr_iodata],
        expr_depth: d - 1
    }
  end

  defp elixir_expr_step(%State{source: <<"{", rest::binary>>, expr_depth: d} = state) do
    %{
      state
      | source: rest,
        column: state.column + 1,
        expr_iodata: ["{" | state.expr_iodata],
        expr_depth: d + 1
    }
  end

  # Skip over Elixir string literals so `}` inside them doesn't
  # affect brace depth.
  defp elixir_expr_step(%State{source: <<"\"", rest::binary>>} = state) do
    consume_elixir_quoted(rest, "\"", "\"", state)
  end

  defp elixir_expr_step(%State{source: <<"'", rest::binary>>} = state) do
    consume_elixir_quoted(rest, "'", "'", state)
  end

  # Elixir `# ...` line comment inside the expression.
  defp elixir_expr_step(%State{source: <<"#", rest::binary>>} = state) do
    {consumed, rest_after, state2} = consume_elixir_line_comment(rest, ["#"], state)
    iodata = [Enum.reverse(consumed) | state2.expr_iodata]
    %{state2 | source: rest_after, expr_iodata: iodata}
  end

  defp elixir_expr_step(%State{source: <<"\r\n", rest::binary>>} = state) do
    %{
      state
      | source: rest,
        line: state.line + 1,
        column: 1,
        expr_iodata: ["\r\n" | state.expr_iodata]
    }
  end

  defp elixir_expr_step(%State{source: <<"\n", rest::binary>>} = state) do
    %{
      state
      | source: rest,
        line: state.line + 1,
        column: 1,
        expr_iodata: ["\n" | state.expr_iodata]
    }
  end

  defp elixir_expr_step(%State{source: <<c::utf8, rest::binary>>} = state) do
    %{
      state
      | source: rest,
        column: state.column + 1,
        expr_iodata: [<<c::utf8>> | state.expr_iodata]
    }
  end

  defp elixir_expr_step(%State{source: ""} = state) do
    ParseError.raise_syntax_error!(
      expr_start_ctx(state),
      ~s/unterminated Elixir interpolation '\#{...}': expected matching '}'/
    )
  end

  defp expr_start_ctx(state) do
    %{
      file: state.file,
      line: state.expr_start.line,
      column: state.expr_start.column,
      snippet: snippet_for(state.original_source, state.expr_start.line)
    }
  end

  # Greedily consume a quoted Elixir string/charlist into the
  # expression buffer. Handles `\\` and `\<quote>` escapes; lets
  # `#{...}` inside the Elixir string pass through verbatim
  # (we're not interpreting Elixir, just collecting bytes until
  # the matching closing quote so brace counting stays correct).
  defp consume_elixir_quoted(source, open, close, state) do
    iodata = [open | state.expr_iodata]
    column = state.column + 1
    do_consume_quoted(source, close, iodata, column, state)
  end

  defp do_consume_quoted("", _close, _iodata, _column, state) do
    ParseError.raise_syntax_error!(
      expr_start_ctx(state),
      "unterminated Elixir string/charlist inside interpolation"
    )
  end

  defp do_consume_quoted(<<"\\\\", rest::binary>>, close, iodata, column, state) do
    do_consume_quoted(rest, close, ["\\\\" | iodata], column + 2, state)
  end

  defp do_consume_quoted(<<"\\", c::utf8, rest::binary>>, close, iodata, column, state) do
    do_consume_quoted(rest, close, [<<c::utf8>>, "\\" | iodata], column + 2, state)
  end

  defp do_consume_quoted(<<"\n", rest::binary>>, close, iodata, _column, state) do
    state = %{state | line: state.line + 1}
    do_consume_quoted(rest, close, ["\n" | iodata], 1, state)
  end

  defp do_consume_quoted(<<c::utf8, rest::binary>>, close, iodata, column, state) do
    bin = <<c::utf8>>

    if bin == close do
      %{state | source: rest, column: column + 1, expr_iodata: [bin | iodata]}
    else
      do_consume_quoted(rest, close, [bin | iodata], column + 1, state)
    end
  end

  defp consume_elixir_line_comment("", acc, state), do: {acc, "", state}

  defp consume_elixir_line_comment(<<"\n", _::binary>> = rest, acc, state) do
    {acc, rest, state}
  end

  defp consume_elixir_line_comment(<<"\r", _::binary>> = rest, acc, state) do
    {acc, rest, state}
  end

  defp consume_elixir_line_comment(<<c::utf8, rest::binary>>, acc, state) do
    consume_elixir_line_comment(rest, [<<c::utf8>> | acc], %{state | column: state.column + 1})
  end

  # ===========================================================
  # Numeric & address literals
  # ===========================================================

  # `0x` with no hex digits: nft's scanner would lex `0` (a NUM)
  # and then `x...` as a separate string token — mirror that
  # instead of raising, per the lexer-never-rejects principle.
  defp read_hex_integer(%State{source: <<z, _::binary-size(1), rest::binary>>} = state) do
    {digits, rest2} = take_while(rest, &hex?/1)

    if digits == "" do
      <<^z, rest_from_x::binary>> = state.source

      %{
        state
        | tokens: [{:integer, 0, current_meta(state)} | state.tokens],
          source: rest_from_x,
          column: state.column + 1
      }
    else
      value = String.to_integer(digits, 16)
      meta = current_meta(state)
      width = 2 + byte_size(digits)

      %{
        state
        | tokens: [{:integer, value, meta} | state.tokens],
          source: rest2,
          column: state.column + width
      }
    end
  end

  defp read_bin_integer(%State{source: <<z, _::binary-size(1), rest::binary>>} = state) do
    {digits, rest2} = take_while(rest, &binary_digit?/1)

    if digits == "" do
      <<^z, rest_from_b::binary>> = state.source

      %{
        state
        | tokens: [{:integer, 0, current_meta(state)} | state.tokens],
          source: rest_from_b,
          column: state.column + 1
      }
    else
      value = String.to_integer(digits, 2)
      meta = current_meta(state)
      width = 2 + byte_size(digits)

      %{
        state
        | tokens: [{:integer, value, meta} | state.tokens],
          source: rest2,
          column: state.column + width
      }
    end
  end

  # First char is `[0-9]` — could be plain int, IPv4, CIDR, or
  # MAC/IPv6 (rare since MAC/IPv6 normally start with hex letters,
  # but `10::1` or `12:34:...` qualify), or a time literal.
  #
  # Time literals follow nft's `timestring` definition exactly
  # (`scanner.l:138`):
  #
  #     ([0-9]+d)?([0-9]+h)?([0-9]+m)?([0-9]+s)?([0-9]+ms)?
  #
  # i.e. compound (`1h30m10s`), strictly descending unit order,
  # `ms` supported, and NO week unit (`5w` is not a time literal
  # in nft; it lexes as `5` + string `w`, a downstream parse
  # error — we match that). The value is emitted in milliseconds,
  # the unit the kernel uses for set timeouts.
  #
  # Time vs address is resolved the way flex resolves overlapping
  # rules: **longest match wins**. `830d:ba45::1` matches the
  # timestring rule for 4 bytes (`830d`) but the IPv6 rule for the
  # whole address, so the address wins; `10s5m` matches no address
  # beyond `10`, so the timestring (`10s`) wins and `5m` lexes as
  # a second timestring. A tie (or a longer-but-unclassifiable
  # address run) goes to the timestring, since a matched
  # timestring is always meaningful while a random hex run is not.
  defp read_numeric_or_address(state) do
    case scan_time(state.source) do
      {:ok, ms, twidth, trest} ->
        {full, rest, awidth} = scan_address_chars(state.source)

        if awidth > twidth and classifiable?(full) do
          classify_address_or_integer(full, rest, awidth, state)
        else
          meta = current_meta(state)

          %{
            state
            | tokens: [{:time, ms, meta} | state.tokens],
              source: trest,
              column: state.column + twidth
          }
        end

      :error ->
        {full, rest, width} = scan_address_chars(state.source)
        classify_address_or_integer(full, rest, width, state)
    end
  end

  defp scan_address_chars(source) do
    {chars, rest} = take_while(source, &numeric_addr_char?/1)
    maybe_consume_cidr_suffix(chars, rest)
  end

  defp classifiable?(chars) do
    pure_decimal?(chars) or ipv4?(chars) or ipv4_cidr?(chars) or
      ipv6?(chars) or ipv6_cidr?(chars) or mac?(chars)
  end

  # ---- nft timestring scan ----

  @time_units [d: 86_400_000, h: 3_600_000, m: 60_000, s: 1_000, ms: 1]
  @time_unit_order Keyword.keys(@time_units)

  defp scan_time(source), do: do_scan_time(source, @time_unit_order, 0, 0)

  defp do_scan_time(source, allowed_units, acc_ms, width) do
    {digits, rest} = take_while(source, &digit?/1)

    with true <- digits != "",
         {:ok, unit, unit_width, rest2} <- scan_time_unit(rest),
         true <- unit in allowed_units do
      remaining = drop_units_through(allowed_units, unit)
      acc_ms = acc_ms + String.to_integer(digits) * Keyword.fetch!(@time_units, unit)
      width = width + byte_size(digits) + unit_width

      case do_scan_time(rest2, remaining, acc_ms, width) do
        {:ok, _, _, _} = more -> more
        :error -> {:ok, acc_ms, width, rest2}
      end
    else
      _ -> :error
    end
  end

  # `ms` must be checked before `m` (and its `m` must not itself
  # start another group's digits — `1m5s` is minutes+seconds, but
  # `1ms` is milliseconds since `s` isn't a digit).
  defp scan_time_unit(<<"ms", rest::binary>>), do: {:ok, :ms, 2, rest}
  defp scan_time_unit(<<"d", rest::binary>>), do: {:ok, :d, 1, rest}
  defp scan_time_unit(<<"h", rest::binary>>), do: {:ok, :h, 1, rest}
  defp scan_time_unit(<<"m", rest::binary>>), do: {:ok, :m, 1, rest}
  defp scan_time_unit(<<"s", rest::binary>>), do: {:ok, :s, 1, rest}
  defp scan_time_unit(_), do: :error

  defp drop_units_through([unit | rest], unit), do: rest
  defp drop_units_through([_ | rest], unit), do: drop_units_through(rest, unit)
  defp drop_units_through([], _unit), do: []

  # Identifier-or-IPv6/MAC. Letter-leading; if all-hex and followed
  # by `:hex...`, switch to address mode (rewind would be more
  # honest, but we just continue collection).
  #
  # nft's bare-string pattern allows `.` and `/` mid-string
  # (`({letter}|[_.])({letter}|{digit}|[/\-_\.])*`), so
  # `example.com` and `br-lan/wan0` are single tokens there. A
  # `.`/`/` directly attached to more identifier characters
  # continues the token; a spaced `.` remains the concatenation
  # operator.
  defp read_identifier(state) do
    {chars, rest} = take_while(state.source, &ident_char?/1)

    cond do
      String.starts_with?(rest, ":") and looks_like_address_start?(rest) and all_hex?(chars) ->
        # Continue collecting as numeric/address; `chars` is the prefix.
        {more, rest2} = take_while(rest, &numeric_addr_char?/1)
        full = chars <> more
        {full, rest3, width} = maybe_consume_cidr_suffix(full, rest2)
        classify_address_or_integer(full, rest3, width, state)

      bare_string_continues?(rest) ->
        {full, rest2} = continue_bare_string(chars, rest)
        meta = current_meta(state)

        %{
          state
          | tokens: [{:identifier, full, meta} | state.tokens],
            source: rest2,
            column: state.column + byte_size(full)
        }

      true ->
        meta = current_meta(state)
        width = byte_size(chars)

        %{
          state
          | tokens: [{:identifier, chars, meta} | state.tokens],
            source: rest,
            column: state.column + width
        }
    end
  end

  defp bare_string_continues?(<<sep, c, _::binary>>) when sep in [?., ?/],
    do: ident_char?(c)

  defp bare_string_continues?(_), do: false

  defp continue_bare_string(chars, rest) do
    if bare_string_continues?(rest) do
      <<sep, r::binary>> = rest
      {more, r2} = take_while(r, &ident_char?/1)
      continue_bare_string(chars <> <<sep>> <> more, r2)
    else
      {chars, rest}
    end
  end

  defp looks_like_address_start?(<<":", c::utf8, _::binary>>),
    do: hex?(c) or c == ?:

  defp looks_like_address_start?(_), do: false

  defp maybe_consume_cidr_suffix(chars, <<"/", c::utf8, _::binary>> = rest)
       when c >= ?0 and c <= ?9 do
    <<"/", rest_after_slash::binary>> = rest
    {prefix, rest2} = take_while(rest_after_slash, &digit?/1)
    full = chars <> "/" <> prefix
    {full, rest2, byte_size(full)}
  end

  defp maybe_consume_cidr_suffix(chars, rest), do: {chars, rest, byte_size(chars)}

  defp classify_address_or_integer(chars, rest, width, state) do
    meta = current_meta(state)

    cond do
      pure_decimal?(chars) ->
        case parse_integer_literal(chars) do
          {:ok, value} ->
            %{
              state
              | tokens: [{:integer, value, meta} | state.tokens],
                source: rest,
                column: state.column + width
            }

          :error ->
            # Leading-zero literal with 8/9 digits — nft's octal
            # strtoull stops mid-string and the lexeme demotes to
            # a plain string token (`scanner.l`: `if (errno != 0
            # || *end)`).
            emit_address(state, :symbol, chars, rest, width, meta)
        end

      ipv4_cidr?(chars) ->
        emit_address(state, :cidr_v4, chars, rest, width, meta)

      ipv4?(chars) ->
        emit_address(state, :ipv4, chars, rest, width, meta)

      ipv6_cidr?(chars) ->
        emit_address(state, :cidr_v6, chars, rest, width, meta)

      mac?(chars) ->
        emit_address(state, :mac, chars, rest, width, meta)

      ipv6?(chars) ->
        emit_address(state, :ipv6, chars, rest, width, meta)

      split = ipv4_port_split(chars) ->
        # `1.2.3.4:8080` (a NAT target) — nft's ip4addr regex
        # longest-matches just the address, leaving `:8080` to lex
        # as COLON + NUM. Our greedy scan glommed the run; split it
        # back the way flex would.
        {kind, prefix, suffix} = split

        %{
          state
          | tokens: [{kind, prefix, meta} | state.tokens],
            source: ":" <> suffix <> rest,
            column: state.column + byte_size(prefix)
        }

      true ->
        # Unclassifiable numeric/address-shaped run (`1.2.3.4.5`).
        # nft's scanner cannot fail — it emits the run as a string
        # token and lets the grammar/evaluation reject it with a
        # located error. Mirror that with a :symbol token.
        emit_address(state, :symbol, chars, rest, width, meta)
    end
  end

  defp ipv4_port_split(chars) do
    case String.split(chars, ":", parts: 2) do
      [prefix, suffix] when suffix != "" ->
        cond do
          ipv4?(prefix) -> {:ipv4, prefix, suffix}
          ipv4_cidr?(prefix) -> {:cidr_v4, prefix, suffix}
          true -> nil
        end

      _ ->
        nil
    end
  end

  # nft's decstring: base 8 when the literal has a leading zero,
  # base 10 otherwise (`scanner.l:930-941`). `0` alone is zero;
  # a leading-zero literal containing non-octal digits fails the
  # conversion and is not a number.
  defp parse_integer_literal("0"), do: {:ok, 0}

  defp parse_integer_literal(<<"0", rest::binary>>) do
    if binary_all?(rest, &octal_digit?/1) do
      {:ok, String.to_integer(rest, 8)}
    else
      :error
    end
  end

  defp parse_integer_literal(chars), do: {:ok, String.to_integer(chars)}

  defp octal_digit?(c), do: c >= ?0 and c <= ?7

  defp emit_address(state, kind, value, rest, width, meta) do
    %{
      state
      | tokens: [{kind, value, meta} | state.tokens],
        source: rest,
        column: state.column + width
    }
  end

  # ===========================================================
  # Character classifiers
  # ===========================================================

  defp digit?(c), do: c >= ?0 and c <= ?9

  defp hex?(c),
    do: digit?(c) or (c >= ?a and c <= ?f) or (c >= ?A and c <= ?F)

  defp binary_digit?(c), do: c == ?0 or c == ?1

  defp numeric_addr_char?(c), do: hex?(c) or c == ?. or c == ?:

  defp ident_char?(c) do
    (c >= ?a and c <= ?z) or
      (c >= ?A and c <= ?Z) or
      digit?(c) or
      c == ?_ or
      c == ?-
  end

  # Returns true iff every byte of `bin` is a hex digit. Called
  # only on non-empty binaries (the empty-binary base case means
  # we've consumed every char without finding a non-hex one).
  defp all_hex?(""), do: true
  defp all_hex?(<<c, rest::binary>>) when c >= ?0 and c <= ?9, do: all_hex?(rest)
  defp all_hex?(<<c, rest::binary>>) when c >= ?a and c <= ?f, do: all_hex?(rest)
  defp all_hex?(<<c, rest::binary>>) when c >= ?A and c <= ?F, do: all_hex?(rest)
  defp all_hex?(_), do: false

  defp pure_decimal?(s), do: s != "" and binary_all?(s, &digit?/1)

  defp binary_all?(<<>>, _pred), do: true
  defp binary_all?(<<c, rest::binary>>, pred), do: pred.(c) and binary_all?(rest, pred)

  defp ipv4?(s) do
    case String.split(s, ".") do
      [a, b, c, d] -> Enum.all?([a, b, c, d], &ipv4_octet?/1)
      _ -> false
    end
  end

  defp ipv4_octet?(s) do
    pure_decimal?(s) and byte_size(s) <= 3 and
      String.to_integer(s) in 0..255
  end

  defp ipv4_cidr?(s) do
    case String.split(s, "/") do
      [addr, prefix] ->
        ipv4?(addr) and pure_decimal?(prefix) and String.to_integer(prefix) in 0..32

      _ ->
        false
    end
  end

  defp ipv6_cidr?(s) do
    case String.split(s, "/") do
      [addr, prefix] ->
        ipv6?(addr) and pure_decimal?(prefix) and String.to_integer(prefix) in 0..128

      _ ->
        false
    end
  end

  defp mac?(s) do
    case String.split(s, ":") do
      [a, b, c, d, e, f] -> Enum.all?([a, b, c, d, e, f], &mac_octet?/1)
      _ -> false
    end
  end

  defp mac_octet?(s) do
    byte_size(s) == 2 and binary_all?(s, &hex?/1)
  end

  defp ipv6?(s) do
    cond do
      not String.contains?(s, ":") -> false
      String.contains?(s, "::") -> ipv6_compressed?(s)
      true -> ipv6_full?(s)
    end
  end

  defp ipv6_full?(s) do
    parts = String.split(s, ":")
    length(parts) == 8 and Enum.all?(parts, &ipv6_group?/1)
  end

  defp ipv6_compressed?(s) do
    case String.split(s, "::") do
      [left, right] ->
        left_parts = if left == "", do: [], else: String.split(left, ":")
        right_parts = if right == "", do: [], else: String.split(right, ":")

        length(left_parts) + length(right_parts) < 8 and
          Enum.all?(left_parts, &ipv6_group?/1) and
          Enum.all?(right_parts, &ipv6_group?/1)

      _ ->
        false
    end
  end

  defp ipv6_group?(s) do
    n = byte_size(s)
    n in 1..4 and binary_all?(s, &hex?/1)
  end

  # ===========================================================
  # Helpers
  # ===========================================================

  defp take_while(source, pred), do: do_take(source, pred, [])

  defp do_take(<<c, rest::binary>>, pred, acc) do
    if pred.(c) do
      do_take(rest, pred, [<<c>> | acc])
    else
      {acc |> Enum.reverse() |> IO.iodata_to_binary(), <<c, rest::binary>>}
    end
  end

  defp do_take(<<>>, _pred, acc) do
    {acc |> Enum.reverse() |> IO.iodata_to_binary(), ""}
  end

  defp current_meta(state), do: %{line: state.line, column: state.column}

  defp advance_col(state, rest, n) do
    %{state | source: rest, column: state.column + n}
  end

  defp advance_line(state, rest) do
    %{state | source: rest, line: state.line + 1, column: 1}
  end

  defp emit_punct(state, kind, rest, width) do
    %{
      state
      | tokens: [{kind, current_meta(state)} | state.tokens],
        source: rest,
        column: state.column + width
    }
  end

  defp emit_stmt_sep(state) do
    case state.tokens do
      [{:stmt_sep, _} | _] -> state
      _ -> %{state | tokens: [{:stmt_sep, current_meta(state)} | state.tokens]}
    end
  end

  defp push_stack(state, condition) do
    %{state | stack: [condition | state.stack]}
  end

  defp pop_stack(state) do
    %{state | stack: tl(state.stack)}
  end

  defp snippet_for(source, line) do
    source
    |> String.split(["\r\n", "\n", "\r"])
    |> Enum.at(line - 1)
  end

  defp raise_at!(state, message) do
    ParseError.raise_syntax_error!(
      %{
        file: state.file,
        line: state.line,
        column: state.column,
        snippet: snippet_for(state.original_source, state.line)
      },
      message
    )
  end

  defp raise_unterminated!(state, :string) do
    ctx = string_start_ctx(state)
    ParseError.raise_syntax_error!(ctx, "unterminated string literal")
  end

  defp raise_unterminated!(state, :block_comment) do
    ParseError.raise_syntax_error!(
      %{file: state.file, line: state.line, column: state.column, snippet: nil},
      "unterminated block comment: expected `*/`"
    )
  end

  defp raise_unterminated!(state, :elixir_expr) do
    ctx = expr_start_ctx(state)

    ParseError.raise_syntax_error!(
      ctx,
      ~s/unterminated Elixir interpolation '\#{...}': expected matching '}'/
    )
  end
end
