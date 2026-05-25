defmodule Linx.NFT.ParseError do
  @moduledoc """
  Syntax error raised by the `~NFT` sigil, by `Linx.NFT.parse/1` /
  `parse_file/1`, and by the AST-walker compiler.

  Carries the source location (`{file, line, column}`) plus the
  offending source line for caret rendering — modelled on the
  Elixir compiler's own error output and on
  `Phoenix.LiveView.TagEngine.Tokenizer.ParseError`.

  ## Fields

    * `:file` — source file name (or `"nofile"` for sigils without
      explicit location).
    * `:line` — 1-based line number of the offending token.
    * `:column` — 1-based column.
    * `:snippet` — the source line as it appears (no trailing
      newline), shown above the caret. May be `nil` when the
      tokenizer wasn't carrying source context.
    * `:message` — short, human-readable description.

  ## Rendering

  `Exception.message/1` produces a multi-line message of the form:

      myapp.nft:42:5: unexpected character '?'
      |
      | tcp dport ? accept
      |           ^

  matching the look of compiler diagnostics elsewhere in the
  Elixir ecosystem.
  """

  defexception [:file, :line, :column, :snippet, :message]

  @type t :: %__MODULE__{
          file: String.t(),
          line: pos_integer(),
          column: pos_integer(),
          snippet: String.t() | nil,
          message: String.t()
        }

  @impl true
  def message(%__MODULE__{file: file, line: line, column: column, snippet: snip, message: msg}) do
    header = "#{file}:#{line}:#{column}: #{msg}"

    case code_snippet(snip, column) do
      "" -> header
      rendered -> header <> "\n" <> rendered
    end
  end

  @doc """
  Renders the offending source line plus a caret pointing at the
  given (1-based) `column`, in the same format the Elixir compiler
  uses for syntax errors:

      |
      | tcp dport 22
      |     ^

  Returns the empty string when `line` is `nil` (no source context
  was captured).
  """
  @spec code_snippet(String.t() | nil, pos_integer()) :: String.t()
  def code_snippet(nil, _col), do: ""

  def code_snippet(line, col) when is_binary(line) and is_integer(col) and col >= 1 do
    pad = String.duplicate(" ", max(col - 1, 0))

    """
    |
    | #{line}
    | #{pad}^\
    """
  end

  @doc """
  Convenience constructor used by the tokenizer / parser / compiler.

  `ctx` is any map carrying `:file`, `:line`, `:column`, and
  optionally `:snippet`. Always raises — never returns.
  """
  @spec raise_syntax_error!(map(), String.t()) :: no_return()
  def raise_syntax_error!(ctx, message) when is_binary(message) do
    raise __MODULE__,
      file: Map.get(ctx, :file, "nofile"),
      line: Map.get(ctx, :line, 1),
      column: Map.get(ctx, :column, 1),
      snippet: Map.get(ctx, :snippet),
      message: message
  end
end
