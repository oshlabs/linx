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
    * `:block_comment` — `/* ... */`; supports nesting (nft itself
      doesn't, but supporting nesting costs ~5 lines and prevents
      a real footgun on hand-edited files).
    * `:string` — `"..."` with `\\\\`/`\\"`/`\\n`/`\\t`/`\\r`/`\\0`
      escapes. (String-internal Elixir interpolation is not yet
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
    * `0b...` / `0B...` — binary integer.
    * `\\d+` followed by no `.` or `:` or `/` — plain decimal integer.
    * `\\d+\\.\\d+\\.\\d+\\.\\d+` — IPv4 literal (optional `/N` CIDR).
    * IPv6: any run starting with hex chars that contains `:` and
      whose contents are valid IPv6 syntax.
    * MAC: six 2-char hex octets joined by `:`.

  Identifiers that *happen* to begin with hex letters (e.g. `eth0`
  or even `fe80`) are still tagged as identifiers when not
  followed by `:`. If the identifier is all-hex and followed by
  `:` plus a hex char, the lexer rewinds and re-scans as an
  IPv6/MAC literal.

  ## Errors

  Anything the tokenizer can't classify raises a
  `Linx.NFT.ParseError` with `{file, line, column}` and the
  offending source line. The caller (sigil macro, `parse/1`,
  `parse_file/1`) catches and either re-raises (compile-time) or
  returns `{:error, %ParseError{}}`.

  ## Extensibility

  All architectural decisions here were chosen for **incremental
  extension**, since the N8 grammar scope is the ~85% subset and
  the long tail of nft constructs (synproxy, secmark, osf, fib,
  jhash, advanced ct, dup/fwd, tproxy, xfrm, tunnel) will be added
  per-construct over time. Each addition becomes:

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
      interpolation?: Keyword.get(opts, :interpolation?, false)
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
      <<" ", rest::binary>> -> advance_col(state, rest, 1)
      <<"\t", rest::binary>> -> advance_col(state, rest, 1)

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
      <<"<<", rest::binary>> -> emit_punct(state, :lshift, rest, 2)
      <<">>", rest::binary>> -> emit_punct(state, :rshift, rest, 2)
      <<"<=", rest::binary>> -> emit_punct(state, :lte, rest, 2)
      <<">=", rest::binary>> -> emit_punct(state, :gte, rest, 2)
      <<"==", rest::binary>> -> emit_punct(state, :eq, rest, 2)
      <<"!=", rest::binary>> -> emit_punct(state, :neq, rest, 2)
      <<"&&", rest::binary>> -> emit_punct(state, :and_and, rest, 2)
      <<"||", rest::binary>> -> emit_punct(state, :or_or, rest, 2)

      # ----------- Single-char punctuation -----------
      <<"{", rest::binary>> -> emit_punct(state, :lbrace, rest, 1)
      <<"}", rest::binary>> -> emit_punct(state, :rbrace, rest, 1)
      <<"(", rest::binary>> -> emit_punct(state, :lparen, rest, 1)
      <<")", rest::binary>> -> emit_punct(state, :rparen, rest, 1)
      <<"[", rest::binary>> -> emit_punct(state, :lbracket, rest, 1)
      <<"]", rest::binary>> -> emit_punct(state, :rbracket, rest, 1)
      <<",", rest::binary>> -> emit_punct(state, :comma, rest, 1)
      <<"=", rest::binary>> -> emit_punct(state, :assign, rest, 1)
      <<"!", rest::binary>> -> emit_punct(state, :bang, rest, 1)
      <<"<", rest::binary>> -> emit_punct(state, :lt, rest, 1)
      <<">", rest::binary>> -> emit_punct(state, :gt, rest, 1)
      <<"&", rest::binary>> -> emit_punct(state, :amp, rest, 1)
      <<"|", rest::binary>> -> emit_punct(state, :pipe, rest, 1)
      <<"^", rest::binary>> -> emit_punct(state, :caret, rest, 1)
      <<"*", rest::binary>> -> emit_punct(state, :star, rest, 1)
      <<"-", rest::binary>> -> emit_punct(state, :dash, rest, 1)
      <<"/", rest::binary>> -> emit_punct(state, :slash, rest, 1)
      <<"@", rest::binary>> -> emit_punct(state, :at, rest, 1)
      <<"$", rest::binary>> -> emit_punct(state, :dollar, rest, 1)

      # ----------- Numeric literals -----------
      <<"0x", _::binary>> -> read_hex_integer(state)
      <<"0X", _::binary>> -> read_hex_integer(state)
      <<"0b", _::binary>> -> read_bin_integer(state)
      <<"0B", _::binary>> -> read_bin_integer(state)

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

  # ---- escapes ----
  defp string_step(%State{source: <<"\\\"", rest::binary>>} = state) do
    %{state | source: rest, column: state.column + 2, string_buf: ["\"" | state.string_buf]}
  end

  defp string_step(%State{source: <<"\\\\", rest::binary>>} = state) do
    %{state | source: rest, column: state.column + 2, string_buf: ["\\" | state.string_buf]}
  end

  defp string_step(%State{source: <<"\\n", rest::binary>>} = state) do
    %{state | source: rest, column: state.column + 2, string_buf: ["\n" | state.string_buf]}
  end

  defp string_step(%State{source: <<"\\t", rest::binary>>} = state) do
    %{state | source: rest, column: state.column + 2, string_buf: ["\t" | state.string_buf]}
  end

  defp string_step(%State{source: <<"\\r", rest::binary>>} = state) do
    %{state | source: rest, column: state.column + 2, string_buf: ["\r" | state.string_buf]}
  end

  defp string_step(%State{source: <<"\\0", rest::binary>>} = state) do
    %{state | source: rest, column: state.column + 2, string_buf: [<<0>> | state.string_buf]}
  end

  # Unknown escape: keep the char literally (lenient).
  defp string_step(%State{source: <<"\\", c::utf8, rest::binary>>} = state) do
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

  defp read_hex_integer(%State{source: <<_::binary-size(2), rest::binary>>} = state) do
    {digits, rest2} = take_while(rest, &hex?/1)

    if digits == "" do
      raise_at!(state, "expected hex digits after `0x`")
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

  defp read_bin_integer(%State{source: <<_::binary-size(2), rest::binary>>} = state) do
    {digits, rest2} = take_while(rest, &binary_digit?/1)

    if digits == "" do
      raise_at!(state, "expected binary digits after `0b`")
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
  # but `10::1` or `12:34:...` qualify).
  defp read_numeric_or_address(state) do
    {chars, rest} = take_while(state.source, &numeric_addr_char?/1)
    {chars, rest, width} = maybe_consume_cidr_suffix(chars, rest)
    classify_address_or_integer(chars, rest, width, state)
  end

  # Identifier-or-IPv6/MAC. Letter-leading; if all-hex and followed
  # by `:hex...`, switch to address mode (rewind would be more
  # honest, but we just continue collection).
  defp read_identifier(state) do
    {chars, rest} = take_while(state.source, &ident_char?/1)

    cond do
      String.starts_with?(rest, ":") and looks_like_address_start?(rest) and all_hex?(chars) ->
        # Continue collecting as numeric/address; `chars` is the prefix.
        {more, rest2} = take_while(rest, &numeric_addr_char?/1)
        full = chars <> more
        {full, rest3, width} = maybe_consume_cidr_suffix(full, rest2)
        classify_address_or_integer(full, rest3, width, state)

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
        value = String.to_integer(chars)

        %{
          state
          | tokens: [{:integer, value, meta} | state.tokens],
            source: rest,
            column: state.column + width
        }

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

      true ->
        raise_at!(state, "unrecognised numeric or address literal: #{inspect(chars)}")
    end
  end

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
      [addr, prefix] -> ipv4?(addr) and pure_decimal?(prefix) and String.to_integer(prefix) in 0..32
      _ -> false
    end
  end

  defp ipv6_cidr?(s) do
    case String.split(s, "/") do
      [addr, prefix] -> ipv6?(addr) and pure_decimal?(prefix) and String.to_integer(prefix) in 0..128
      _ -> false
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
    ParseError.raise_syntax_error!(ctx, ~s/unterminated Elixir interpolation '\#{...}': expected matching '}'/)
  end
end
