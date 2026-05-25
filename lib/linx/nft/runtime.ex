defmodule Linx.NFT.Runtime do
  @moduledoc """
  Runtime helpers for `~NFT` sigils that contain `\#{...}`
  interpolations.

  When the sigil body has no interpolations, `Linx.NFT.Compiler`
  produces a `%Linx.Netfilter.Ruleset{}` at compile time and the
  macro emits it as a literal. When there are interpolations, the
  static value isn't knowable until runtime, so
  `Linx.NFT.RuntimeCompiler` emits Elixir code that constructs the
  Ruleset at runtime. At each `\#{expr}` position, it calls into
  one of the helpers here — they take an evaluated Elixir value
  plus the **field kind** the surrounding nft syntax expects
  (`{:int, 1|2|4|8}`, `:ipv4`, `:ipv6`, `:ifname`), validate, and
  return either an encoded `%Expr{}` ready to splice into the
  rule's expression list or the raw bytes to use as a comparison
  value.

  Errors at runtime raise `ArgumentError` with a message naming
  the expected kind and the actual value — there's no
  source-location context here (the macro keeps the AST node's
  meta on the static side, but the runtime helper just sees the
  value), so test the interpolated values close to the sigil
  call site.

  ## Supported value kinds

    * `{:int, width}` — `width` ∈ `1, 2, 4, 8` bytes, big-endian
      encoded. Accepts any non-negative integer that fits.
    * `:ipv4` — `Linx.IP.parse/1`-able string, 4-tuple
      `{a, b, c, d}`, raw 4-byte binary, or `%Linx.IP{family:
      :inet}`. Returns 4 bytes.
    * `:ipv6` — same shape extended: parse-able string, 8-tuple
      of `0..0xFFFF`, raw 16-byte binary, or `%Linx.IP{family:
      :inet6}`. Returns 16 bytes.
    * `:ifname` — binary, padded/truncated to IFNAMSIZ (16
      bytes) with trailing zero bytes.

  Each kind has a matching `encode_*!/1` helper that returns the
  raw bytes, plus the convenience `cmp!/3` that wraps the bytes
  in an `%Expr{name: :cmp}` ready to splice into a rule.
  """

  alias Linx.Netfilter.Expr

  import Bitwise

  @doc """
  Encodes `value` for the given `kind`, then builds an
  `%Expr{name: :cmp}` with `op`. Returns the `%Expr{}`. Raises
  `ArgumentError` if `value` doesn't match the expected kind.
  """
  @spec cmp!(atom(), term(), {:int, 1 | 2 | 4 | 8} | :ipv4 | :ipv6 | :ifname) :: Expr.t()
  def cmp!(op, value, kind) when is_atom(op) do
    Expr.cmp(op, encode!(value, kind))
  end

  @doc """
  Encodes `value` to a binary suitable for the given kind. Raises
  `ArgumentError` on type mismatch / out-of-range.
  """
  @spec encode!(term(), {:int, 1 | 2 | 4 | 8} | :ipv4 | :ipv6 | :ifname) :: binary()
  def encode!(value, {:int, width}) when width in [1, 2, 4, 8],
    do: encode_int!(value, width)

  def encode!(value, :ipv4), do: encode_ipv4!(value)
  def encode!(value, :ipv6), do: encode_ipv6!(value)
  def encode!(value, :ifname), do: encode_ifname!(value)

  def encode!(_value, kind),
    do: raise(ArgumentError, "Linx.NFT.Runtime: unknown field kind #{inspect(kind)}")

  @doc "Encodes an integer to a `width`-byte big-endian binary."
  @spec encode_int!(integer(), 1 | 2 | 4 | 8) :: binary()
  def encode_int!(n, width)
      when is_integer(n) and n >= 0 and n < 1 <<< (width * 8) and width in [1, 2, 4, 8] do
    case width do
      1 -> <<n>>
      2 -> <<n::big-16>>
      4 -> <<n::big-32>>
      8 -> <<n::big-64>>
    end
  end

  def encode_int!(value, width) do
    raise ArgumentError,
          "Linx.NFT.Runtime: expected non-negative integer fitting in #{width} bytes, got: #{inspect(value)}"
  end

  @doc "Encodes an IPv4 input to its 4-byte big-endian form."
  @spec encode_ipv4!(term()) :: <<_::32>>
  def encode_ipv4!({a, b, c, d}) when a in 0..255 and b in 0..255 and c in 0..255 and d in 0..255 do
    <<a, b, c, d>>
  end

  def encode_ipv4!(<<_::32>> = bin), do: bin

  def encode_ipv4!(%Linx.IP{family: :inet, bytes: bytes}), do: bytes

  def encode_ipv4!(string) when is_binary(string) do
    case Linx.IP.parse(string) do
      {:ok, %Linx.IP{family: :inet, bytes: bytes}} ->
        bytes

      _ ->
        raise ArgumentError, "Linx.NFT.Runtime: invalid IPv4 address: #{inspect(string)}"
    end
  end

  def encode_ipv4!(other),
    do: raise(ArgumentError, "Linx.NFT.Runtime: expected IPv4 value, got: #{inspect(other)}")

  @doc "Encodes an IPv6 input to its 16-byte big-endian form."
  @spec encode_ipv6!(term()) :: <<_::128>>
  def encode_ipv6!({a, b, c, d, e, f, g, h})
      when a in 0..0xFFFF and b in 0..0xFFFF and c in 0..0xFFFF and d in 0..0xFFFF and
             e in 0..0xFFFF and f in 0..0xFFFF and g in 0..0xFFFF and h in 0..0xFFFF do
    <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>
  end

  def encode_ipv6!(<<_::128>> = bin), do: bin

  def encode_ipv6!(%Linx.IP{family: :inet6, bytes: bytes}), do: bytes

  def encode_ipv6!(string) when is_binary(string) do
    case Linx.IP.parse(string) do
      {:ok, %Linx.IP{family: :inet6, bytes: bytes}} ->
        bytes

      _ ->
        raise ArgumentError, "Linx.NFT.Runtime: invalid IPv6 address: #{inspect(string)}"
    end
  end

  def encode_ipv6!(other),
    do: raise(ArgumentError, "Linx.NFT.Runtime: expected IPv6 value, got: #{inspect(other)}")

  @doc """
  Pads an interface-name binary out to IFNAMSIZ (16 bytes) with
  trailing zeros. Truncates if longer (matches kernel behaviour —
  the trailing bytes are ignored).
  """
  @spec encode_ifname!(binary()) :: <<_::128>>
  def encode_ifname!(s) when is_binary(s) do
    cond do
      byte_size(s) == 16 -> s
      byte_size(s) < 16 -> s <> :binary.copy(<<0>>, 16 - byte_size(s))
      true -> binary_part(s, 0, 16)
    end
  end

  def encode_ifname!(other),
    do: raise(ArgumentError, "Linx.NFT.Runtime: expected ifname string, got: #{inspect(other)}")
end
