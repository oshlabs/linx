defmodule Linx.Netfilter.Flowtable do
  @moduledoc """
  An nftables flowtable — a connection-offload fast path that
  shortcuts the netfilter hooks for established flows.

  A flowtable is attached to a base chain (forward hook,
  family-dependent) and lists devices on which to offload. Once a
  flow is in the table, subsequent packets bypass the rest of
  netfilter — software offload by default; hardware offload with
  `:hw_offload` flag if the NIC supports it.

  ## Fields

    * `:name` — flowtable name (unique within the table).
    * `:table` — owning table's name.
    * `:hook` — kernel-side, flowtables can only attach to the
      forward / ingress hooks; Linx stores whatever you set.
    * `:priority` — integer or named atom; same shape as `Chain`'s
      priority.
    * `:devices` — list of interface name strings.
    * `:flags` — list. `:hw_offload` is the common one.
    * `:handle` — kernel-assigned handle; `nil` until pushed.

  ## Construction

      iex> Flowtable.new("ft1", hook: :ingress, priority: 0,
      ...>                devices: ["eth0", "eth1"])
      {:ok, %Linx.Netfilter.Flowtable{name: "ft1", ...}}

  Errors: `{:error, {:bad_flowtable, reason}}`.

  ## References

    * [`Documentation/networking/nf_flowtable`](https://docs.kernel.org/networking/nf_flowtable.html)
  """

  @enforce_keys [:name]
  defstruct [:name, :table, :hook, :priority, :handle, devices: [], flags: []]

  @type t :: %__MODULE__{
          name: String.t(),
          table: String.t() | nil,
          hook: atom() | nil,
          priority: integer() | atom() | {atom(), integer()} | nil,
          devices: [String.t()],
          flags: [atom()],
          handle: pos_integer() | nil
        }

  @valid_flags [:hw_offload]

  @doc "Builds a flowtable."
  @spec new(String.t(), keyword()) :: {:ok, t()} | {:error, {:bad_flowtable, term()}}
  def new(name, opts \\ []) when is_binary(name) and is_list(opts) do
    devices = Keyword.get(opts, :devices, [])
    flags = Keyword.get(opts, :flags, [])

    with :ok <- validate_name(name),
         :ok <- validate_devices(devices),
         :ok <- validate_flags(flags) do
      {:ok,
       %__MODULE__{
         name: name,
         table: Keyword.get(opts, :table),
         hook: Keyword.get(opts, :hook),
         priority: Keyword.get(opts, :priority),
         devices: devices,
         flags: flags,
         handle: Keyword.get(opts, :handle)
       }}
    end
  end

  @doc "Bang variant."
  @spec new!(String.t(), keyword()) :: t()
  def new!(name, opts \\ []) do
    case new(name, opts) do
      {:ok, ft} ->
        ft

      {:error, {:bad_flowtable, reason}} ->
        raise ArgumentError, "invalid flowtable: #{inspect(reason)}"
    end
  end

  defp validate_name(""), do: {:error, {:bad_flowtable, :name_empty}}
  defp validate_name(_), do: :ok

  defp validate_devices(list) when is_list(list) do
    Enum.reduce_while(list, :ok, fn
      d, :ok when is_binary(d) and d != "" -> {:cont, :ok}
      bad, :ok -> {:halt, {:error, {:bad_flowtable, {:bad_device, bad}}}}
    end)
  end

  defp validate_devices(other), do: {:error, {:bad_flowtable, {:devices_not_list, other}}}

  defp validate_flags(flags) when is_list(flags) do
    Enum.reduce_while(flags, :ok, fn flag, :ok ->
      if flag in @valid_flags do
        {:cont, :ok}
      else
        {:halt, {:error, {:bad_flowtable, {:unknown_flag, flag}}}}
      end
    end)
  end

  defp validate_flags(other), do: {:error, {:bad_flowtable, {:flags_not_list, other}}}
end
