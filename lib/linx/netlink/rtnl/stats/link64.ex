defmodule Linx.Netlink.Rtnl.Stats.Link64 do
  @moduledoc """
  Per-interface counters as the kernel reports them in
  `IFLA_STATS_LINK_64` — `struct rtnl_link_stats64`, a packed array of
  64-bit counters defined in `include/uapi/linux/if_link.h`.

  The struct grew over time. The first 24 counters
  (`rx_packets` .. `rx_nohandler`) have been there since the 64-bit
  stats were introduced; `rx_otherhost_dropped` was added in Linux 5.19,
  so on older kernels its field is `nil`.

  This module implements the value-type contract the `Linx.Netlink.Codec`
  DSL expects (`encode/1` and `decode/1`). `decode/1` accepts both the
  192-byte (24-counter) and 200-byte (25-counter) layouts, and tolerates
  extra trailing bytes from a still-newer kernel.
  """

  # The field order is the wire order — packed `__u64` counters from
  # `struct rtnl_link_stats64`. Keep this list in lockstep with the UAPI
  # header.
  @counters [
    :rx_packets,
    :tx_packets,
    :rx_bytes,
    :tx_bytes,
    :rx_errors,
    :tx_errors,
    :rx_dropped,
    :tx_dropped,
    :multicast,
    :collisions,
    :rx_length_errors,
    :rx_over_errors,
    :rx_crc_errors,
    :rx_frame_errors,
    :rx_fifo_errors,
    :rx_missed_errors,
    :tx_aborted_errors,
    :tx_carrier_errors,
    :tx_fifo_errors,
    :tx_heartbeat_errors,
    :tx_window_errors,
    :rx_compressed,
    :tx_compressed,
    :rx_nohandler,
    :rx_otherhost_dropped
  ]

  defstruct Enum.map(@counters, &{&1, nil})

  @type counter :: non_neg_integer | nil
  @type t :: %__MODULE__{}

  @doc false
  def __counters__, do: @counters

  @doc """
  Encodes a `t:t/0` into the packed `rtnl_link_stats64` bytes — always
  the full 25-counter (200-byte) form; a `nil` counter is written as 0.
  """
  @spec encode(t()) :: binary
  def encode(%__MODULE__{} = stats) do
    for name <- @counters,
        into: <<>>,
        do: <<(Map.fetch!(stats, name) || 0)::native-unsigned-64>>
  end

  @doc """
  Decodes a packed `rtnl_link_stats64` payload.

  Accepts the 24-counter (192-byte) layout from kernels < 5.19, the
  25-counter (200-byte) layout from 5.19+, and tolerates extra trailing
  bytes from a still-newer kernel. Counters the payload does not carry
  remain `nil`.
  """
  @spec decode(binary) :: t()
  def decode(payload) when is_binary(payload),
    do: decode(payload, @counters, %__MODULE__{})

  defp decode(_rest, [], acc), do: acc
  defp decode(<<>>, [_ | _], acc), do: acc

  defp decode(<<value::native-unsigned-64, rest::binary>>, [name | names], acc),
    do: decode(rest, names, Map.put(acc, name, value))
end
