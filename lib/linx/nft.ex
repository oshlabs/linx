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
  `NFT-PLAN.md` for the parity roadmap and
  `docs/netfilter/netfilter-overview.md` for design notes).

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

  # nft caps include nesting at MAX_INCLUDE_DEPTH (16); we add
  # cycle detection on top (nft only has the depth cap).
  @max_include_depth 16

  @doc """
  Parses a binary holding nft syntax into a `%Ruleset{}`.

  ## Options

    * `:file` — source filename for error messages
      (default `"nofile"`).
    * `:include_dir` — base directory for resolving relative
      `include` paths (default: the current working directory;
      `parse_file/2` sets it to the including file's directory,
      matching `nft -f`).
    * `:include_paths` — additional search directories tried in
      order after `:include_dir` (nft's `-I`).

  `include "path"` directives are resolved during parsing (like
  nft): relative to `:include_dir`, then each of
  `:include_paths`. Glob patterns are supported — a wildcard
  matching nothing is fine, a literal path matching nothing is an
  error. Nesting is capped at #{@max_include_depth} levels and
  include cycles are detected.

  Returns `{:ok, Ruleset.t()} | {:error, ParseError.t()}`.
  """
  @spec parse(String.t(), keyword()) ::
          {:ok, Ruleset.t()} | {:error, ParseError.t()}
  def parse(source, opts \\ []) when is_binary(source) do
    file = Keyword.get(opts, :file, "nofile")

    ctx = %{
      base_dir: Keyword.get(opts, :include_dir, File.cwd!()),
      include_paths: Keyword.get(opts, :include_paths, []),
      depth: 0,
      seen: MapSet.new()
    }

    with {:ok, ast} <- parse_to_ast(source, file, ctx),
         {:ok, rs} <- Compiler.compile(ast, file: file, source: source) do
      {:ok, rs}
    end
  end

  @doc """
  Reads a `.nft` file and parses it into a `%Ruleset{}`. Relative
  `include` paths resolve against the file's own directory, like
  `nft -f`. Accepts the same options as `parse/2`.

  Returns `{:ok, Ruleset.t()} | {:error, ParseError.t() | File.posix()}`.
  """
  @spec parse_file(Path.t(), keyword()) ::
          {:ok, Ruleset.t()} | {:error, ParseError.t() | File.posix()}
  def parse_file(path, opts \\ []) do
    case File.read(path) do
      {:ok, source} ->
        opts =
          opts
          |> Keyword.put(:file, path)
          |> Keyword.put_new(:include_dir, Path.dirname(Path.expand(path)))

        parse(source, opts)

      {:error, posix} ->
        {:error, posix}
    end
  end

  # ===========================================================
  # include resolution
  # ===========================================================

  defp parse_to_ast(source, file, ctx) do
    with {:ok, tokens} <- Tokenizer.tokenize(source, file: file),
         {:ok, ast} <- Parser.parse(tokens, file: file, source: source) do
      expand_includes(ast, file, source, ctx)
    end
  end

  defp expand_includes(items, file, source, ctx) do
    items
    |> Enum.reduce_while({:ok, []}, fn
      {:include, path, meta}, {:ok, acc} ->
        case resolve_include(path, meta, file, source, ctx) do
          {:ok, included_items} -> {:cont, {:ok, acc ++ included_items}}
          {:error, _} = err -> {:halt, err}
        end

      item, {:ok, acc} ->
        {:cont, {:ok, acc ++ [item]}}
    end)
  end

  defp resolve_include(path, meta, file, source, ctx) do
    cond do
      ctx.depth >= @max_include_depth ->
        include_error(file, source, meta, "include nesting deeper than #{@max_include_depth}")

      true ->
        case include_matches(path, ctx) do
          [] ->
            if glob_pattern?(path) do
              # A wildcard matching nothing is not an error (glob(3)
              # semantics, same as nft).
              {:ok, []}
            else
              include_error(file, source, meta, "include: file not found: #{path}")
            end

          matches ->
            Enum.reduce_while(matches, {:ok, []}, fn match, {:ok, acc} ->
              case include_one(match, meta, file, source, ctx) do
                {:ok, items} -> {:cont, {:ok, acc ++ items}}
                {:error, _} = err -> {:halt, err}
              end
            end)
        end
    end
  end

  defp include_matches(path, ctx) do
    search_dirs =
      if Path.type(path) == :absolute do
        [nil]
      else
        [ctx.base_dir | ctx.include_paths]
      end

    search_dirs
    |> Enum.flat_map(fn
      nil -> Path.wildcard(path)
      dir -> Path.wildcard(Path.join(dir, path))
    end)
    |> Enum.uniq()
    |> Enum.filter(&File.regular?/1)
    # nft processes glob matches in alphabetical order.
    |> Enum.sort()
    |> case do
      [] -> []
      # Only the first search dir that yields matches wins, like
      # nft's -I path ordering — but since we flat_map across all
      # dirs, dedupe keeps this simple and permissive.
      matches -> matches
    end
  end

  defp glob_pattern?(path), do: String.contains?(path, ["*", "?", "["])

  defp include_one(abs_path, meta, file, source, ctx) do
    expanded = Path.expand(abs_path)

    cond do
      MapSet.member?(ctx.seen, expanded) ->
        include_error(file, source, meta, "include cycle: #{abs_path} includes itself")

      true ->
        case File.read(expanded) do
          {:ok, included_source} ->
            nested_ctx = %{
              ctx
              | base_dir: Path.dirname(expanded),
                depth: ctx.depth + 1,
                seen: MapSet.put(ctx.seen, expanded)
            }

            parse_to_ast(included_source, abs_path, nested_ctx)

          {:error, posix} ->
            include_error(file, source, meta, "include: cannot read #{abs_path}: #{posix}")
        end
    end
  end

  defp include_error(file, source, meta, message) do
    snippet =
      case source |> String.split(["\r\n", "\n", "\r"]) |> Enum.at(meta.line - 1) do
        nil -> nil
        line -> line
      end

    {:error,
     %ParseError{
       file: file,
       line: meta.line,
       column: meta.column,
       snippet: snippet,
       message: message
     }}
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
    # `escapes?: true` — Elixir-style string escapes are a
    # sigil-only convenience; `parse/1` / `parse_file/1` stay
    # byte-for-byte compatible with nft's scanner (no escapes).
    Tokenizer.tokenize(source, file: file, line: line, interpolation?: true, escapes?: true)
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
