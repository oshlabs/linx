defmodule Linx.IP.Subnet do
  @moduledoc """
  An IPv4 or IPv6 subnet — a network address and a prefix length, parsed
  from CIDR notation.

      iex> Linx.IP.Subnet.parse("10.0.0.0/24")
      {:ok, ~IP"10.0.0.0/24"}

      iex> import Linx.IP
      iex> ~IP"fc00::/16"
      ~IP"fc00::/16"

  ## Subnet operations

      iex> import Linx.IP
      iex> Linx.IP.Subnet.contains?(~IP"10.0.0.0/8", ~IP"10.99.0.5")
      true
      iex> Linx.IP.Subnet.network(~IP"10.0.42.5/24")
      ~IP"10.0.42.0"
      iex> Linx.IP.Subnet.broadcast(~IP"10.0.42.5/24")
      ~IP"10.0.42.255"
  """

  import Bitwise
  alias Linx.IP

  @enforce_keys [:address, :prefix]
  defstruct [:address, :prefix]

  @type t :: %__MODULE__{address: IP.t(), prefix: 0..128}

  @doc """
  Parses a CIDR string (`"10.0.0.0/24"`, `"fc00::/16"`) into a subnet.
  """
  @spec parse(binary) :: {:ok, t} | {:error, term}
  def parse(string) when is_binary(string) do
    case String.split(string, "/") do
      [ip_str, prefix_str] ->
        with {prefix, ""} <- Integer.parse(prefix_str),
             {:ok, %IP{family: family} = ip} <- IP.parse(ip_str),
             :ok <- check_prefix(family, prefix) do
          {:ok, %__MODULE__{address: ip, prefix: prefix}}
        else
          _ -> {:error, {:bad_subnet, string}}
        end

      _ ->
        {:error, {:bad_subnet, string}}
    end
  end

  @doc """
  Returns whether `subnet` contains `ip`.

  False when the address families differ.
  """
  @spec contains?(t, IP.t()) :: boolean
  def contains?(
        %__MODULE__{address: %IP{family: family, bytes: net}, prefix: prefix},
        %IP{family: family, bytes: addr}
      )
      when bit_size(net) == bit_size(addr) do
    <<net_bits::bits-size(prefix), _::bits>> = net
    <<addr_bits::bits-size(prefix), _::bits>> = addr
    net_bits == addr_bits
  end

  def contains?(_, _), do: false

  @doc """
  Returns `subnet`'s network address — the input address with host bits
  zeroed.
  """
  @spec network(t) :: IP.t()
  def network(%__MODULE__{address: %IP{family: family, bytes: bytes}, prefix: prefix}) do
    host_bits = bit_size(bytes) - prefix
    <<net::bits-size(prefix), _::bits-size(host_bits)>> = bytes
    %IP{family: family, bytes: <<net::bits, 0::size(host_bits)>>}
  end

  @doc """
  Returns the IPv4 broadcast address of `subnet`, or `nil` for IPv6 (which
  has no broadcast).
  """
  @spec broadcast(t) :: IP.t() | nil
  def broadcast(%__MODULE__{address: %IP{family: :inet, bytes: bytes}, prefix: prefix}) do
    host_bits = 32 - prefix
    <<net::bits-size(prefix), _::bits-size(host_bits)>> = bytes
    ones = if host_bits == 0, do: 0, else: (1 <<< host_bits) - 1
    %IP{family: :inet, bytes: <<net::bits, ones::size(host_bits)>>}
  end

  def broadcast(%__MODULE__{address: %IP{family: :inet6}}), do: nil

  defp check_prefix(:inet, p) when p in 0..32, do: :ok
  defp check_prefix(:inet6, p) when p in 0..128, do: :ok
  defp check_prefix(_, _), do: :error

  defimpl Inspect do
    def inspect(%{address: ip, prefix: prefix}, _opts) do
      ~s|~IP"#{Linx.IP.to_string(ip)}/#{prefix}"|
    end
  end
end
