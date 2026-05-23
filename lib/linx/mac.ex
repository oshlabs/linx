defmodule Linx.MAC do
  @moduledoc """
  A 48-bit MAC (link-layer) address.

  ## Construction

      iex> Linx.MAC.parse("00:11:22:33:44:55")
      {:ok, ~MAC"00:11:22:33:44:55"}

  ## The `~MAC` sigil

  `import Linx.MAC` and build MAC literals at compile time:

      iex> import Linx.MAC
      iex> ~MAC"02:aa:bb:cc:dd:ee"
      ~MAC"02:aa:bb:cc:dd:ee"

  ## Inspect

  A MAC renders as the same sigil that would build it —
  `~MAC"02:aa:bb:cc:dd:ee"` — so iex output round-trips into source.

  ## Wire codec

  `encode/1` and `decode/1` are the `Linx.Netlink.Codec` entry points: a
  `Linx.MAC` serializes to its 6 raw bytes; decode reads 6 bytes back.
  """

  @enforce_keys [:bytes]
  defstruct [:bytes]

  @type t :: %__MODULE__{bytes: <<_::48>>}

  @doc """
  Parses a colon-separated hex string into an `Linx.MAC`.
  """
  @spec parse(binary) :: {:ok, t} | {:error, term}
  def parse(string) when is_binary(string) do
    case String.split(string, ":") do
      [_, _, _, _, _, _] = parts -> parse_pairs(parts, <<>>, string)
      _ -> {:error, {:bad_mac, string}}
    end
  end

  defp parse_pairs([], acc, _orig), do: {:ok, %__MODULE__{bytes: acc}}

  defp parse_pairs([h | t], acc, orig) do
    case Integer.parse(h, 16) do
      {n, ""} when n in 0..255 -> parse_pairs(t, acc <> <<n>>, orig)
      _ -> {:error, {:bad_mac, orig}}
    end
  end

  @doc """
  Renders a `Linx.MAC` as a colon-separated hex string.
  """
  @spec to_string(t) :: binary
  def to_string(%__MODULE__{bytes: <<a, b, c, d, e, f>>}) do
    [a, b, c, d, e, f]
    |> Enum.map_join(
      ":",
      &(Integer.to_string(&1, 16) |> String.pad_leading(2, "0") |> String.downcase())
    )
  end

  @doc """
  The `~MAC` sigil: builds a `Linx.MAC` at compile time. Invalid input
  raises `ArgumentError`.
  """
  defmacro sigil_MAC({:<<>>, _meta, [string]}, _modifiers) when is_binary(string) do
    case parse(string) do
      {:ok, value} ->
        Macro.escape(value)

      {:error, reason} ->
        raise ArgumentError, "invalid ~MAC sigil #{inspect(string)}: #{inspect(reason)}"
    end
  end

  # --- Linx.Netlink.Codec entry points ---------------------------------------

  @doc false
  @spec encode(t) :: binary
  def encode(%__MODULE__{bytes: bytes}), do: bytes

  @doc false
  @spec decode(<<_::48>>) :: t
  def decode(<<_::48>> = bytes), do: %__MODULE__{bytes: bytes}

  defimpl Inspect do
    def inspect(mac, _opts), do: ~s|~MAC"#{Linx.MAC.to_string(mac)}"|
  end
end
