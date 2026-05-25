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
  `Linx.NFT.Compiler` capabilities (see that module's `@moduledoc`
  and `docs/netfilter/COVERAGE.md` for the up-to-date table). The
  N8 milestone targets the ~85% subset; the long tail
  (`synproxy`, `secmark`, `osf`, `fib`, `jhash`, advanced ct
  fields, `dup`/`fwd`, ipsec contexts) lands as later
  per-construct additions.

  ## Interpolation status

  Sigil-time Elixir interpolation (`\#{port}` inside a `~NFT`
  body) is recognised by the tokenizer but is **not yet wired up**
  in this milestone: `~NFT` accepts only literal binaries today
  and raises `CompileError` if any interpolation is present. The
  full type-aware compile-time-checked interpolation flow lands
  as a follow-up commit on top of N8d.
  """

  alias Linx.NFT.{Compiler, Formatter, ParseError, Parser, Tokenizer}
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
  The `~NFT` sigil. Compiles inline nft syntax to a
  `%Linx.Netfilter.Ruleset{}` at compile time, raising
  `Linx.NFT.ParseError` on syntax or compile errors.

  ## Examples

      iex> import Linx.NFT
      iex> rs = ~NFT"table inet x { }"
      iex> rs.tables |> map_size()
      1

  Modifierless. Interpolation (`\#{...}`) inside the sigil body
  raises `CompileError` for now — wiring runtime-evaluated
  bindings into the AST is a follow-up.
  """
  defmacro sigil_NFT({:<<>>, _meta, [literal]}, _modifiers) when is_binary(literal) do
    file = __CALLER__.file
    line = __CALLER__.line

    case parse_sigil(literal, file, line) do
      {:ok, rs} -> Macro.escape(rs)
      {:error, %ParseError{} = err} -> raise err
    end
  end

  defmacro sigil_NFT({:<<>>, meta, _parts}, _modifiers) do
    line = Keyword.get(meta, :line, __CALLER__.line)

    raise CompileError,
      file: __CALLER__.file,
      line: line,
      description:
        "~NFT does not yet support Elixir interpolation inside the sigil body — " <>
          "use the pipeline DSL (Linx.Netfilter.Ruleset.add_*!) for now"
  end

  defp parse_sigil(source, file, line) do
    with {:ok, tokens} <- Tokenizer.tokenize(source, file: file, line: line),
         {:ok, ast} <- Parser.parse(tokens, file: file, source: source),
         {:ok, rs} <- Compiler.compile(ast, file: file, source: source) do
      {:ok, rs}
    end
  end
end
