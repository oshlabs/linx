defmodule Linx.Netfilter.Rule do
  @moduledoc """
  A single nftables rule — an ordered list of expressions that the
  kernel evaluates against each packet visiting the rule's chain.

  ## Fields

    * `:expressions` — ordered list of `%Linx.Netfilter.Expr{}`.
      The terminator is typically a verdict-bearing `immediate`
      expression; if absent, falls through to the next rule.

    * `:chain` — name (string) of the chain this rule belongs to.
      `nil` for free-standing rules; populated when the rule is
      inserted into a chain (and when pulled from the kernel).

    * `:handle` — the kernel-assigned rule handle (positive
      integer). `nil` for authoring-time rules; populated on the
      first successful `push/2` and round-tripped on `pull/1..2`.
      Required for in-place `:replace` / `:delete` of rules without
      a tag.

    * `:tag` — Linx-side stable identity (atom). The basis of
      `:reconcile` mode's diffing: a Rule keeps its identity across
      pushes regardless of position or handle, as long as the tag
      matches. `nil` is allowed; untagged rules fall back to
      positional identity (and forfeit `:reconcile` diffability).

    * `:comment` — a user-supplied comment string, round-tripped via
      the kernel's `NFTNL_RULE_USERDATA` opaque slot.

  ## Construction

  Use `build/1` or `build/2` with an expression list. The list may
  include verdict sugar — atoms (`:accept`), tuples (`{:jump, name}`),
  or `%Linx.Netfilter.Verdict{}` values — which are normalised to
  `Expr.immediate/1` calls so the resulting Rule is uniform.

      iex> Rule.build([Expr.immediate(:accept)])
      {:ok, #Linx.Netfilter.Rule<[immediate accept]>}

      iex> Rule.build([:drop], tag: :default_deny, comment: "block-all")
      {:ok, #Linx.Netfilter.Rule<:default_deny [immediate drop]>}

      iex> Rule.build([{:jump, "input_extras"}])
      {:ok, #Linx.Netfilter.Rule<[immediate jump "input_extras"]>}

  Bang variant `build!/2` raises `ArgumentError` on validation
  failure. The non-bang form returns `{:error, {:bad_rule, reason}}`.

  ## Inspect

  Compact: tag (if set) then bracketed expressions. Comment +
  handle are omitted from the brief rendering; pattern-match on
  the struct fields if you need the full detail.
  """

  alias Linx.Netfilter.{Expr, Verdict}

  @enforce_keys [:expressions]
  defstruct [:expressions, :chain, :handle, :tag, :comment]

  @type t :: %__MODULE__{
          expressions: [Expr.t()],
          chain: String.t() | nil,
          handle: pos_integer() | nil,
          tag: atom() | nil,
          comment: String.t() | nil
        }

  @type expression_input :: Expr.t() | Verdict.t() | Verdict.input()

  @doc """
  Builds a Rule from a list of expressions (or verdict-sugar).

  Options:

    * `:chain` — the owning chain's name; usually set by the
      chain-level helpers, but allowed at build time for round-trip
      from a `pull/1..2`.
    * `:handle` — the kernel-assigned handle; usually `nil` until
      the first `push/2`.
    * `:tag` — atom identity (for `:reconcile`-mode diffing).
    * `:comment` — round-trips via `NFTNL_RULE_USERDATA`.
  """
  @spec build([expression_input()], keyword()) ::
          {:ok, t()} | {:error, {:bad_rule, term()}}
  def build(expressions, opts \\ [])

  def build(expressions, opts) when is_list(expressions) and is_list(opts) do
    with {:ok, normalized} <- normalize_expressions(expressions),
         :ok <- validate_tag(Keyword.get(opts, :tag)),
         :ok <- validate_handle(Keyword.get(opts, :handle)),
         :ok <- validate_comment(Keyword.get(opts, :comment)),
         :ok <- validate_chain(Keyword.get(opts, :chain)) do
      {:ok,
       %__MODULE__{
         expressions: normalized,
         chain: Keyword.get(opts, :chain),
         handle: Keyword.get(opts, :handle),
         tag: Keyword.get(opts, :tag),
         comment: Keyword.get(opts, :comment)
       }}
    end
  end

  def build(_other, _opts), do: {:error, {:bad_rule, :expressions_not_a_list}}

  @doc """
  Bang variant of `build/2` — returns the rule or raises
  `ArgumentError` describing the failure.
  """
  @spec build!([expression_input()], keyword()) :: t()
  def build!(expressions, opts \\ []) do
    case build(expressions, opts) do
      {:ok, r} -> r
      {:error, {:bad_rule, reason}} -> raise ArgumentError, "invalid rule: #{inspect(reason)}"
    end
  end

  @doc """
  Returns the rule's terminal verdict, if any — the trailing
  verdict-bearing expression. `nil` for fall-through rules.
  """
  @spec verdict(t()) :: Verdict.t() | nil
  def verdict(%__MODULE__{expressions: exprs}) do
    case List.last(exprs) do
      %Expr{name: :immediate, data: %Verdict{} = v} -> v
      _ -> nil
    end
  end

  # Flattens one level of nesting so that helpers returning a list
  # of `%Expr{}` (e.g. `Expr.dnat_to/3`, `Expr.masquerade/1`) can be
  # dropped straight into a rule's expression list without manual
  # `++` splicing.
  defp normalize_expressions(expressions) do
    expressions
    |> Enum.flat_map(fn
      list when is_list(list) -> list
      other -> [other]
    end)
    |> Enum.reduce_while({:ok, []}, fn item, {:ok, acc} ->
      case normalize_one(item) do
        {:ok, expr} -> {:cont, {:ok, [expr | acc]}}
        {:error, reason} -> {:halt, {:error, {:bad_rule, reason}}}
      end
    end)
    |> case do
      {:ok, rev} -> {:ok, Enum.reverse(rev)}
      err -> err
    end
  end

  defp normalize_one(%Expr{} = e), do: {:ok, e}
  defp normalize_one(%Verdict{} = v), do: {:ok, Expr.immediate(v)}

  defp normalize_one(input) do
    case Verdict.new(input) do
      {:ok, v} -> {:ok, Expr.immediate(v)}
      {:error, _} -> {:error, {:not_an_expression, input}}
    end
  end

  defp validate_tag(nil), do: :ok
  defp validate_tag(tag) when is_atom(tag), do: :ok
  defp validate_tag(other), do: {:error, {:bad_rule, {:tag_not_atom, other}}}

  defp validate_handle(nil), do: :ok
  defp validate_handle(h) when is_integer(h) and h > 0, do: :ok
  defp validate_handle(other), do: {:error, {:bad_rule, {:handle_not_pos_int, other}}}

  # 253 = the kernel's NFT_USERDATA_MAXLEN (256) minus the TLV type
  # and length bytes and the trailing NUL. Longer would also wrap the
  # encoder's 8-bit TLV length byte and corrupt the userdata stream.
  defp validate_comment(nil), do: :ok
  defp validate_comment(c) when is_binary(c) and byte_size(c) <= 253, do: :ok

  defp validate_comment(c) when is_binary(c),
    do: {:error, {:bad_rule, {:comment_too_long, byte_size(c)}}}

  defp validate_comment(other), do: {:error, {:bad_rule, {:comment_not_binary, other}}}

  defp validate_chain(nil), do: :ok
  defp validate_chain(c) when is_binary(c), do: :ok
  defp validate_chain(other), do: {:error, {:bad_rule, {:chain_not_binary, other}}}

  defimpl Inspect do
    alias Linx.Netfilter.Expr, as: E
    alias Linx.Netfilter.Verdict, as: V

    def inspect(%Linx.Netfilter.Rule{expressions: exprs, tag: tag}, _opts) do
      tag_part = if tag, do: "#{inspect(tag)} ", else: ""
      "#Linx.Netfilter.Rule<#{tag_part}[#{exprs |> Enum.map(&render/1) |> Enum.join(", ")}]>"
    end

    defp render(%E{name: :immediate, data: %V{kind: k, target: nil}}), do: "immediate #{k}"

    defp render(%E{name: :immediate, data: %V{kind: k, target: t}}) when is_binary(t),
      do: "immediate #{k} #{inspect(t)}"

    defp render(%E{name: :immediate, data: %V{kind: k, target: t}}) when is_integer(t),
      do: "immediate #{k} #{t}"

    defp render(%E{name: name}), do: "#{name}"
  end
end
