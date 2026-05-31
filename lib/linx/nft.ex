defmodule Linx.NFT do
  @moduledoc """
  The public entry point for the `~NFT` sigil and the file-mode
  parser. Plumbs source → `Linx.NFT.Tokenizer` →
  `Linx.NFT.Parser` → `Linx.NFT.Compiler` →
  `%Linx.Netfilter.Ruleset{}`, plus a canonical emit going the
  other way (`format/1`).

  Three peer authoring surfaces produce the same `%Ruleset{}` via
  the same validator-setter functions (`Linx.Netfilter.Ruleset.
  add_table!/3`, `add_chain!/4`, `add_rule!/4`, etc.):

    * **Pipeline DSL** — direct `Ruleset.new() |> add_table!(…)`
      calls. Best for programmatic construction.
    * **`~NFT` sigil** — inline nft syntax, parsed at compile
      time. Best for hand-authoring a ruleset alongside Elixir
      code (Nerves boot scripts, container compositions).
    * **`Linx.NFT.parse_file/1`** — same parser/compiler, file
      input. Best for importing an existing `nftables.conf`.

  Round-trip:

      iex> import Linx.NFT
      iex> rs = ~NFT\"\"\"
      ...> table inet myapp {
      ...>   chain input {
      ...>     type filter hook input priority 0
      ...>     policy drop
      ...>     tcp dport 22 accept
      ...>   }
      ...> }
      ...> \"\"\"
      iex> emitted = Linx.NFT.format(rs)
      iex> {:ok, rs2} = Linx.NFT.parse(emitted)
      iex> rs == rs2
      true

  ## Compile-time errors

  Parse or compile errors inside a `~NFT` sigil raise
  `Linx.NFT.ParseError` **at compile time**, with the
  Elixir-compiler-style caret rendering keyed off the surrounding
  `.ex` file's line numbers (the tokenizer's `:line` option lines
  up with `__CALLER__.line`):

      ** (Linx.NFT.ParseError) lib/myapp/firewall.ex:42:14: ...
      |
      | tcp dport ? accept
      |           ^

  ## Scope

  The grammar slice currently supported matches the
  `Linx.NFT.Compiler` capabilities (see that module's `@moduledoc`).
  It targets the common ~85% subset; the long tail (`synproxy`,
  `secmark`, `osf`, `fib`, `jhash`, advanced ct fields,
  `dup`/`fwd`, ipsec contexts) is not yet implemented (see
  `docs/netfilter/DESIGN.md`).

  ## Interpolation

  `~NFT` is an uppercase sigil, so Elixir's parser leaves
  `\#{...}` alone and the macro receives the literal binary —
  the same pattern Phoenix HEEx uses for `~H`. Our own
  `Linx.NFT.Tokenizer` recognises `\#{...}` as an interpolation
  marker (its `:interpolation?` mode is enabled by the sigil
  always), captures the raw Elixir source between the braces,
  and emits an `:elixir_expr` token at that position.

  When any `:elixir_expr` tokens are present, the macro switches
  to `Linx.NFT.RuntimeCompiler`, which emits Elixir code that
  builds the Ruleset at runtime. At each interpolation position,
  the emitted code calls into `Linx.NFT.Runtime` with the field
  kind the surrounding nft syntax expects (`{:int, _}`, `:ipv4`,
  `:ipv6`, `:ifname`) — that's where the **runtime type check**
  happens. Pass an integer where a port is expected and you get a
  `<<port::big-16>>` bytestring; pass a binary where it shouldn't
  be and you get a runtime `ArgumentError` naming the kind.

  Supported interpolation positions today:

    * Match RHS — `tcp dport \#{port}`, `ip saddr \#{addr}`,
      `meta iifname \#{name}`.

  Interpolations in keyword positions (table name, chain name,
  family, hook, …) raise a `ParseError` — they'd require
  per-validator wiring that hasn't landed yet.

  Sigil bodies with NO interpolations stay on the compile-time
  static path — the `%Ruleset{}` is computed at macro-expansion
  time and emitted as a literal value.
  """

  alias Linx.NFT.{Compiler, Formatter, ParseError, Parser, RuntimeCompiler, Tokenizer}
  alias Linx.Netfilter.Ruleset

  @doc """
  Parses a binary holding nft syntax into a `%Ruleset{}`.

  ## Options

    * `:file` — source filename for error messages
      (default `"nofile"`).

  Returns `{:ok, Ruleset.t()} | {:error, ParseError.t()}`.
  """
  @spec parse(String.t(), keyword()) ::
          {:ok, Ruleset.t()} | {:error, ParseError.t()}
  def parse(source, opts \\ []) when is_binary(source) do
    file = Keyword.get(opts, :file, "nofile")

    with {:ok, tokens} <- Tokenizer.tokenize(source, file: file),
         {:ok, ast} <- Parser.parse(tokens, file: file, source: source),
         {:ok, rs} <- Compiler.compile(ast, file: file, source: source) do
      {:ok, rs}
    end
  end

  @doc """
  Reads a `.nft` file and parses it into a `%Ruleset{}`.

  Returns `{:ok, Ruleset.t()} | {:error, ParseError.t() | File.posix()}`.
  """
  @spec parse_file(Path.t()) ::
          {:ok, Ruleset.t()} | {:error, ParseError.t() | File.posix()}
  def parse_file(path) do
    case File.read(path) do
      {:ok, source} -> parse(source, file: path)
      {:error, posix} -> {:error, posix}
    end
  end

  @doc """
  Emits a `%Ruleset{}` as canonical nft syntax.

  The output is syntactically valid `nftables.conf`-compatible
  source that parses back to an equivalent `%Ruleset{}` (modulo
  comments, blank lines, and the original ordering of unrelated
  items — trivia preservation is a v2 enhancement). See
  `Linx.NFT.Formatter` for the per-construct emit policy.
  """
  @spec format(Ruleset.t()) :: String.t()
  def format(%Ruleset{} = rs), do: Formatter.format(rs)

  @doc """
  The `~NFT` sigil. Parses inline nft syntax at compile time and
  returns a `%Linx.Netfilter.Ruleset{}`. Bodies with `\#{...}`
  interpolations are compiled to runtime-evaluating code; bodies
  without interpolations are compiled to a literal value.

  Raises `Linx.NFT.ParseError` at compile time on syntax or
  compile errors.

  ## Examples

      iex> import Linx.NFT
      iex> rs = ~NFT"table inet x { }"
      iex> rs.tables |> map_size()
      1

  Modifierless.
  """
  defmacro sigil_NFT({:<<>>, _meta, [literal]}, _modifiers) when is_binary(literal) do
    file = __CALLER__.file
    line = __CALLER__.line

    case tokenize_with_interp(literal, file, line) do
      {:ok, tokens} ->
        if has_interpolation?(tokens) do
          emit_runtime(tokens, literal, file)
        else
          emit_static(tokens, literal, file)
        end

      {:error, %ParseError{} = err} ->
        raise err
    end
  end

  defp tokenize_with_interp(source, file, line) do
    Tokenizer.tokenize(source, file: file, line: line, interpolation?: true)
  end

  defp has_interpolation?(tokens) do
    Enum.any?(tokens, fn
      {:elixir_expr, _, _} -> true
      _ -> false
    end)
  end

  defp emit_static(tokens, source, file) do
    with {:ok, ast} <- Parser.parse(tokens, file: file, source: source),
         {:ok, rs} <- Compiler.compile(ast, file: file, source: source) do
      Macro.escape(rs)
    else
      {:error, %ParseError{} = err} -> raise err
    end
  end

  defp emit_runtime(tokens, source, file) do
    with {:ok, ast} <- Parser.parse(tokens, file: file, source: source),
         {:ok, quoted} <- RuntimeCompiler.emit(ast, file: file, source: source) do
      quoted
    else
      {:error, %ParseError{} = err} -> raise err
    end
  end
end
