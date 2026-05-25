defmodule Linx.Netfilter.Vmap do
  @moduledoc """
  Constructor sugar for verdict maps — a `Linx.Netfilter.Map` with
  `:data_type` fixed to `:verdict`.

  Verdict maps (vmaps) are the kernel's rule-dispatch primitive:
  one lookup turns "if dport is 22 jump ssh, if 80 jump http, if
  443 jump https, ..." from a wall of rules into a single hash
  lookup. The Kubernetes kube-proxy nftables backend leans on this
  shape; so does any non-trivial firewall.

  ## Construction

      iex> Vmap.new("port_dispatch", key_type: :inet_service,
      ...>          elements: [{22, :jump_ssh_in}, {80, :jump_http_in}])

  In the example above the values are passed in the user-friendly
  verdict-input form; `Linx.Netfilter.Map` normalises each to
  `%Linx.Netfilter.Verdict{}` (the `:verdict` data_type accepts any
  input `Verdict.new!/1` understands).

  Returns a `%Linx.Netfilter.Map{}` (with `data_type: :verdict`) —
  there is no separate `%Vmap{}` struct, just this constructor and
  the underlying map.
  """

  alias Linx.Netfilter.Map, as: NMap

  @doc """
  Builds a verdict map. Accepts the same options as
  `Linx.Netfilter.Map.new/2` except `:data_type` (which is forced
  to `:verdict`).
  """
  @spec new(String.t(), keyword()) :: {:ok, NMap.t()} | {:error, {:bad_map, term()}}
  def new(name, opts) when is_binary(name) and is_list(opts) do
    NMap.new(name, Keyword.put(opts, :data_type, :verdict))
  end

  @doc "Bang variant of `new/2`."
  @spec new!(String.t(), keyword()) :: NMap.t()
  def new!(name, opts), do: NMap.new!(name, Keyword.put(opts, :data_type, :verdict))
end
