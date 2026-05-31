defmodule Linx.Netfilter.Object do
  @moduledoc """
  An nftables named object — counters, quotas, limits, ct helpers,
  ct timeouts, secmarks, synproxies.

  Named objects are stateful primitives that rules reference. A
  counter accumulates packet/byte counts across all rules that
  reference it; a quota fires when its threshold is hit; a ct
  helper enables an ALG (FTP, SIP, …) on specific traffic. The
  value lives in the table; rules carry references.

  ## Fields

    * `:name` — object name (unique within the table for its kind).
    * `:table` — owning table's name.
    * `:kind` — object kind atom. The canonical kinds are accepted;
      per-kind data shapes are not yet validated.
    * `:data` — kind-specific value (map / keyword / struct).
      Opaque to the validator; per-kind shape validation is not yet
      implemented.
    * `:handle` — kernel-assigned handle; `nil` until pushed.
    * `:comment` — round-trips via object userdata.

  ## Object kinds

    * `:counter` — packet/byte counter. Data: `%{packets: int,
      bytes: int}`.
    * `:quota` — quota object. Data: `%{bytes: int, used: int,
      flags: [:inv]}`.
    * `:limit` — rate limit. Data: `%{rate: int, unit: atom, ...}`.
    * `:ct_helper` — connection-tracking helper (ALG). Data:
      `%{type: "ftp", protocol: :tcp, l3proto: :inet}`.
    * `:ct_timeout` — per-flow timeout policy.
    * `:ct_expectation` — explicit expected connection.
    * `:secmark` — SELinux/SMACK label.
    * `:synproxy` — SYN proxy parameters.

  ## Construction

      iex> Object.new(:counter, "ssh_attempts", %{packets: 0, bytes: 0})
      {:ok, %Linx.Netfilter.Object{kind: :counter, name: "ssh_attempts", ...}}

      iex> Object.new(:ct_helper, "ftp_helper",
      ...>             %{type: "ftp", protocol: :tcp, l3proto: :inet})
      {:ok, %Linx.Netfilter.Object{kind: :ct_helper, ...}}

  Errors: `{:error, {:bad_object, reason}}`.
  """

  @enforce_keys [:kind, :name]
  defstruct [:kind, :name, :table, :data, :handle, :comment]

  @type kind ::
          :counter
          | :quota
          | :limit
          | :ct_helper
          | :ct_timeout
          | :ct_expectation
          | :secmark
          | :synproxy

  @type t :: %__MODULE__{
          kind: kind(),
          name: String.t(),
          table: String.t() | nil,
          data: term(),
          handle: pos_integer() | nil,
          comment: String.t() | nil
        }

  @valid_kinds [
    :counter,
    :quota,
    :limit,
    :ct_helper,
    :ct_timeout,
    :ct_expectation,
    :secmark,
    :synproxy
  ]

  @doc """
  Builds an object of the given kind.

  `data` is kind-specific; it's stored opaquely (per-kind shape
  validation is not yet implemented).
  """
  @spec new(kind(), String.t(), term(), keyword()) ::
          {:ok, t()} | {:error, {:bad_object, term()}}
  def new(kind, name, data \\ nil, opts \\ [])
      when is_atom(kind) and is_binary(name) and is_list(opts) do
    with :ok <- validate_kind(kind),
         :ok <- validate_name(name) do
      {:ok,
       %__MODULE__{
         kind: kind,
         name: name,
         table: Keyword.get(opts, :table),
         data: data,
         handle: Keyword.get(opts, :handle),
         comment: Keyword.get(opts, :comment)
       }}
    end
  end

  @doc "Bang variant."
  @spec new!(kind(), String.t(), term(), keyword()) :: t()
  def new!(kind, name, data \\ nil, opts \\ []) do
    case new(kind, name, data, opts) do
      {:ok, o} -> o
      {:error, {:bad_object, reason}} -> raise ArgumentError, "invalid object: #{inspect(reason)}"
    end
  end

  defp validate_kind(k) when k in @valid_kinds, do: :ok
  defp validate_kind(other), do: {:error, {:bad_object, {:unknown_kind, other}}}

  defp validate_name(""), do: {:error, {:bad_object, :name_empty}}
  defp validate_name(_), do: :ok
end
