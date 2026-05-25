defmodule Linx.Netfilter.Expr do
  @moduledoc """
  A single netfilter expression — one node in a rule's expression
  list.

  Expressions are the kernel's per-rule building blocks: a payload
  extraction, a comparison, a lookup, a verdict load. Each carries
  a `:name` (the kernel's expression-type string, e.g. `"payload"`,
  `"cmp"`, `"immediate"`, `"lookup"`) and `:data` (kind-specific
  arguments — a keyword list, a map, a verdict, …).

  ## N1 scope

  N1 ships the struct shape and a small set of constructors:

    * `immediate/1` — load a verdict (or, in N2+, a constant) into
      the kernel's register 0.
    * `new/2` — generic constructor for arbitrary `(name, data)`
      pairs. Useful for callers building expressions Linx doesn't
      yet have a dedicated helper for.

  The full constructor set (`cmp/3`, `payload/3`, `meta/2`,
  `bitwise/3`, `ct/2`, `lookup/2`, `reject/2`, `counter/1`, NAT
  helpers) lands in N2/N3 alongside the wire encoder. At the
  value-type level the struct shape is final today — the additional
  constructors are extra entry points, not extra fields.

  ## Inspect

      iex> Expr.immediate(Verdict.accept())
      #Linx.Netfilter.Expr<immediate accept>

      iex> Expr.new(:counter, %{packets: 0, bytes: 0})
      #Linx.Netfilter.Expr<counter>

  ## References

    * [`Documentation/networking/netlink_spec/nftables` — Expression
      types](https://docs.kernel.org/networking/netlink_spec/nftables.html)
  """

  alias Linx.Netfilter.Verdict

  @enforce_keys [:name]
  defstruct [:name, :data]

  @type t :: %__MODULE__{name: atom() | String.t(), data: term()}

  @doc """
  Generic constructor: an expression named `name` carrying `data`.

  Most callers want one of the kind-specific helpers (`immediate/1`
  here; `cmp/3` / `payload/3` / etc. landing in N2). Use `new/2`
  when you're constructing an expression Linx doesn't yet have a
  dedicated helper for.
  """
  @spec new(atom() | String.t(), term()) :: t()
  def new(name, data \\ nil) when is_atom(name) or is_binary(name),
    do: %__MODULE__{name: name, data: data}

  @doc """
  An `immediate` expression — load a verdict into register 0.

  The data is the verdict struct itself. Accepts a `%Verdict{}` or
  any input form `Verdict.new!/1` understands.

  In N2 this constructor also accepts a constant (a binary or
  integer) for loading a value into a register prior to a `cmp` —
  the kernel uses the same expression for both forms.

      iex> Expr.immediate(Verdict.accept())
      #Linx.Netfilter.Expr<immediate accept>

      iex> Expr.immediate(:drop)
      #Linx.Netfilter.Expr<immediate drop>
  """
  @spec immediate(Verdict.input()) :: t()
  def immediate(%Verdict{} = v), do: %__MODULE__{name: :immediate, data: v}
  def immediate(other), do: %__MODULE__{name: :immediate, data: Verdict.new!(other)}

  @doc """
  Returns `true` if `expr` is an `immediate` expression carrying a
  `%Verdict{}` — i.e. a terminal expression in a rule.

  N2 will broaden the verdict-extraction logic to recognise other
  terminal expressions (`reject`, …). For N1 this single shape is
  the only verdict-producing expression we mint.
  """
  @spec verdict?(t()) :: boolean()
  def verdict?(%__MODULE__{name: :immediate, data: %Verdict{}}), do: true
  def verdict?(%__MODULE__{}), do: false

  defimpl Inspect do
    def inspect(
          %Linx.Netfilter.Expr{name: :immediate, data: %Linx.Netfilter.Verdict{} = v},
          _opts
        ) do
      target = if v.target, do: " #{format_target(v.target)}", else: ""
      "#Linx.Netfilter.Expr<immediate #{v.kind}#{target}>"
    end

    def inspect(%Linx.Netfilter.Expr{name: name, data: nil}, _opts),
      do: "#Linx.Netfilter.Expr<#{name}>"

    def inspect(%Linx.Netfilter.Expr{name: name}, _opts),
      do: "#Linx.Netfilter.Expr<#{name}>"

    defp format_target(t) when is_binary(t), do: inspect(t)
    defp format_target(t) when is_integer(t), do: Integer.to_string(t)
  end
end
