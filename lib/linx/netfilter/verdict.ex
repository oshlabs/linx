defmodule Linx.Netfilter.Verdict do
  @moduledoc """
  A netfilter verdict — the terminal result of a rule's evaluation.

  Verdicts are the kernel's per-packet decisions. The simple
  verdicts (`:accept`, `:drop`, `:continue`, `:return`) take no
  target; `:jump` and `:goto` target another chain by name;
  `:queue` targets a userspace queue number.

  ## Verdict kinds

    * `:accept` — let the packet through; further chains may still
      see it.
    * `:drop` — silently drop the packet.
    * `:continue` — fall through to the next rule (the implicit
      default when no rule matches).
    * `:return` — return from the current chain (only meaningful
      inside a chain reached via `:jump`).
    * `:jump` — call into another chain; control returns when that
      chain `:return`s or runs out of rules.
    * `:goto` — tail-call another chain; control does not return.
    * `:queue` — hand the packet to a userspace queue (NFQUEUE
      consumer — `Linx.Netfilter.Queue` is deferred post-v1).

  `:reject` is not a verdict — it's a statement that constructs an
  ICMP/TCP-RST/ICMPX response *then* drops. Construct it via
  `Linx.Netfilter.Expr.reject` (N2).

  ## Construction

      iex> Verdict.accept()
      #Linx.Netfilter.Verdict<accept>

      iex> Verdict.jump("input_extras")
      #Linx.Netfilter.Verdict<jump "input_extras">

      iex> Verdict.new(:drop)
      #Linx.Netfilter.Verdict<drop>

      iex> Verdict.new({:goto, "drop_quietly"})
      #Linx.Netfilter.Verdict<goto "drop_quietly">

  ## Validation

  `new/1` returns `{:error, {:bad_verdict, reason}}` for unknown
  kinds, missing chain targets on `:jump`/`:goto`, or non-integer
  queue numbers. The bang variant raises `ArgumentError`.

  Wire encoding (the integer codes the kernel expects in
  `NFT_DATA_VERDICT`) is N2's concern — this struct is pure data.

  ## References

    * [`enum nft_verdicts`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/netfilter/nf_tables.h)
      — kernel's verdict integers.
  """

  @enforce_keys [:kind]
  defstruct [:kind, :target]

  @type kind :: :accept | :drop | :continue | :return | :jump | :goto | :queue
  @type target :: nil | String.t() | non_neg_integer()
  @type t :: %__MODULE__{kind: kind(), target: target()}

  @typedoc """
  The user-facing input forms `new/1` accepts.
  """
  @type input ::
          :accept
          | :drop
          | :continue
          | :return
          | {:jump, String.t()}
          | {:goto, String.t()}
          | {:queue, non_neg_integer()}
          | t()

  @simple_kinds [:accept, :drop, :continue, :return]

  @doc "Verdict: let the packet through."
  @spec accept() :: t()
  def accept, do: %__MODULE__{kind: :accept}

  @doc "Verdict: silently drop the packet."
  @spec drop() :: t()
  def drop, do: %__MODULE__{kind: :drop}

  @doc "Verdict: fall through to the next rule."
  @spec continue() :: t()
  def continue, do: %__MODULE__{kind: :continue}

  @doc "Verdict: return from the current chain."
  @spec return() :: t()
  def return, do: %__MODULE__{kind: :return}

  @doc """
  Verdict: call into `chain_name`. Control returns when that chain
  `:return`s or runs out of rules.
  """
  @spec jump(String.t()) :: t()
  def jump(chain_name) when is_binary(chain_name) and chain_name != "",
    do: %__MODULE__{kind: :jump, target: chain_name}

  @doc """
  Verdict: tail-call `chain_name`. Control does not return.
  """
  @spec goto(String.t()) :: t()
  def goto(chain_name) when is_binary(chain_name) and chain_name != "",
    do: %__MODULE__{kind: :goto, target: chain_name}

  @doc """
  Verdict: hand the packet to userspace queue `num`.
  """
  @spec queue(non_neg_integer()) :: t()
  def queue(num) when is_integer(num) and num >= 0,
    do: %__MODULE__{kind: :queue, target: num}

  @doc """
  Constructs a verdict from a user-friendly input form.

  Accepts an atom for simple verdicts, a `{kind, target}` tuple
  for parameterised verdicts, or an existing `%Verdict{}` (returned
  as-is — convenient for pipeline code that doesn't know which form
  it was handed).
  """
  @spec new(input()) :: {:ok, t()} | {:error, {:bad_verdict, term()}}
  def new(%__MODULE__{} = v), do: {:ok, v}
  def new(kind) when kind in @simple_kinds, do: {:ok, %__MODULE__{kind: kind}}

  def new({:jump, chain}) when is_binary(chain) and chain != "",
    do: {:ok, %__MODULE__{kind: :jump, target: chain}}

  def new({:goto, chain}) when is_binary(chain) and chain != "",
    do: {:ok, %__MODULE__{kind: :goto, target: chain}}

  def new({:queue, num}) when is_integer(num) and num >= 0,
    do: {:ok, %__MODULE__{kind: :queue, target: num}}

  def new(other), do: {:error, {:bad_verdict, other}}

  @doc """
  Bang variant of `new/1` — returns the verdict or raises
  `ArgumentError` describing the failure.
  """
  @spec new!(input()) :: t()
  def new!(input) do
    case new(input) do
      {:ok, v} -> v
      {:error, {:bad_verdict, bad}} -> raise ArgumentError, "invalid verdict: #{inspect(bad)}"
    end
  end

  @doc """
  Returns `true` if `v` is a well-formed verdict.
  """
  @spec valid?(t()) :: boolean()
  def valid?(%__MODULE__{kind: k, target: nil}) when k in @simple_kinds, do: true

  def valid?(%__MODULE__{kind: k, target: t})
      when k in [:jump, :goto] and is_binary(t) and t != "",
      do: true

  def valid?(%__MODULE__{kind: :queue, target: n}) when is_integer(n) and n >= 0, do: true
  def valid?(_), do: false

  defimpl Inspect do
    def inspect(%Linx.Netfilter.Verdict{kind: k, target: nil}, _opts),
      do: "#Linx.Netfilter.Verdict<#{k}>"

    def inspect(%Linx.Netfilter.Verdict{kind: k, target: t}, _opts) when is_binary(t),
      do: "#Linx.Netfilter.Verdict<#{k} #{inspect(t)}>"

    def inspect(%Linx.Netfilter.Verdict{kind: k, target: t}, _opts) when is_integer(t),
      do: "#Linx.Netfilter.Verdict<#{k} #{t}>"
  end
end
