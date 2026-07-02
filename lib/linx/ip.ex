defmodule Linx.IP do
  @moduledoc """
  An IPv4 or IPv6 address.

  ## Construction

      iex> Linx.IP.parse("10.0.0.5")
      {:ok, ~IP"10.0.0.5"}

      iex> Linx.IP.parse("fc00::1")
      {:ok, ~IP"fc00::1"}

  ## The `~IP` sigil

  `import Linx.IP` and build addresses (or subnets, when the literal
  contains `/`) at compile time:

      iex> import Linx.IP
      iex> ~IP"10.0.0.5"
      ~IP"10.0.0.5"
      iex> ~IP"10.0.0.0/24"
      ~IP"10.0.0.0/24"

  Invalid input raises at compile time, so a bad literal can never reach the
  kernel.

  ## Inspect

  An IP renders as the same sigil that would build it — `~IP"10.0.0.5"` —
  so iex output round-trips back into source code.

  ## Wire codec

  `encode/1` and `decode/1` are the `Linx.Netlink.Codec` entry points: a
  `Linx.IP` serializes to its raw bytes (4 for IPv4, 16 for IPv6), and the
  family is recovered on decode from the byte length.
  """

  @enforce_keys [:family, :bytes]
  defstruct [:family, :bytes]

  @type family :: :inet | :inet6
  @type t :: %__MODULE__{family: family, bytes: binary}

  @doc """
  Parses a string into an `Linx.IP` — IPv4 or IPv6.

  Strict: IPv4 must be a full dotted quad. The classful shorthands
  `:inet.parse_address/1` accepts (`"10.0.0"` → `10.0.0.0`, `"10.1"` →
  `10.0.0.1`) are rejected — a typo'd address handed to `Address.add`
  or `Route.add` must error, not install a valid-but-wrong address.
  """
  @spec parse(binary) :: {:ok, t} | {:error, term}
  def parse(string) when is_binary(string) do
    case :inet.parse_strict_address(String.to_charlist(string)) do
      {:ok, {a, b, c, d}} ->
        {:ok, %__MODULE__{family: :inet, bytes: <<a, b, c, d>>}}

      {:ok, {a, b, c, d, e, f, g, h}} ->
        bytes = <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>
        {:ok, %__MODULE__{family: :inet6, bytes: bytes}}

      {:error, _} ->
        {:error, {:bad_address, string}}
    end
  end

  @doc """
  Renders an `Linx.IP` as a string — dotted-quad for IPv4, canonical
  compressed for IPv6 (`fc00::1`, not `fc00:0:0:0:0:0:0:1`).
  """
  @spec to_string(t) :: binary
  def to_string(%__MODULE__{family: :inet, bytes: <<a, b, c, d>>}) do
    List.to_string(:inet.ntoa({a, b, c, d}))
  end

  def to_string(%__MODULE__{family: :inet6, bytes: bytes}) do
    <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>> = bytes
    List.to_string(:inet.ntoa({a, b, c, d, e, f, g, h}))
  end

  @doc """
  The `~IP` sigil: builds an `Linx.IP` (or `Linx.IP.Subnet` if the literal
  contains `/`) at compile time. Invalid input raises `ArgumentError`.
  """
  defmacro sigil_IP({:<<>>, _meta, [string]}, _modifiers) when is_binary(string) do
    case parse_any(string) do
      {:ok, value} ->
        Macro.escape(value)

      {:error, reason} ->
        raise ArgumentError, "invalid ~IP sigil #{inspect(string)}: #{inspect(reason)}"
    end
  end

  defp parse_any(string) do
    if String.contains?(string, "/") do
      Linx.IP.Subnet.parse(string)
    else
      parse(string)
    end
  end

  # --- Linx.Netlink.Codec entry points ---------------------------------------

  @doc false
  @spec encode(t) :: binary
  def encode(%__MODULE__{bytes: bytes}), do: bytes

  @doc false
  # 4 or 16 bytes decode to an address. Anything else — a zero-length or
  # truncated attribute in a kernel dump — decodes to nil rather than
  # crashing the decoder (mirrors Linx.MAC.decode/1; callers treat nil
  # as "no address").
  @spec decode(binary) :: t | nil
  def decode(<<_::32>> = bytes), do: %__MODULE__{family: :inet, bytes: bytes}
  def decode(<<_::128>> = bytes), do: %__MODULE__{family: :inet6, bytes: bytes}
  def decode(_other), do: nil

  defimpl Inspect do
    def inspect(ip, _opts), do: ~s|~IP"#{Linx.IP.to_string(ip)}"|
  end
end
