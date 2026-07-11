defmodule Linx.Netfilter.Map do
  @moduledoc """
  An nftables map — a set with associated data per element.

  A map is a set where each element is `{key, value}`. The key
  matches the set's `:key_type` and the value matches the map's
  `:data_type`. When the `:data_type` is `:verdict`, the map is
  what nft calls a **verdict map** (vmap) — rule dispatch by
  lookup.

  See `Linx.Netfilter.Vmap` for the verdict-map-specific constructor
  helper that wraps `Map.new/2` with `data_type: :verdict`.

  ## Fields

  Same as `Linx.Netfilter.Set`, plus:

    * `:data_type` — value-type atom. The basic atomic types or
      `:verdict`. Concatenations are not yet implemented.

  ## Construction

      iex> Map.new("port_to_chain", key_type: :inet_service, data_type: :verdict,
      ...>          elements: [{22, Linx.Netfilter.Verdict.jump("ssh_in")},
      ...>                     {80, Linx.Netfilter.Verdict.jump("http_in")}])
      {:ok, %Linx.Netfilter.Map{name: "port_to_chain", data_type: :verdict, ...}}

      iex> Map.new("dnat_targets", key_type: :inet_service, data_type: :ipv4_addr)
      {:ok, %Linx.Netfilter.Map{...}}

  Errors: `{:error, {:bad_map, reason}}`. Element-shape errors:
  `{:error, {:bad_map_element, reason}}`.
  """

  alias Linx.Netfilter.{Set, Verdict}

  @enforce_keys [:name, :key_type, :data_type]
  defstruct [
    :name,
    :table,
    :key_type,
    :data_type,
    :timeout,
    :gc_interval,
    :size,
    :handle,
    :comment,
    flags: [],
    elements: []
  ]

  @type data_type :: Set.key_type() | :verdict
  @type t :: %__MODULE__{
          name: String.t(),
          table: String.t() | nil,
          key_type: Set.key_type(),
          data_type: data_type(),
          flags: [Set.flag()],
          elements: [{term(), term()}],
          timeout: pos_integer() | nil,
          gc_interval: pos_integer() | nil,
          size: pos_integer() | nil,
          handle: pos_integer() | nil,
          comment: String.t() | nil
        }

  @valid_data_types [
    :ipv4_addr,
    :ipv6_addr,
    :ether_addr,
    :inet_proto,
    :inet_service,
    :mark,
    :ifname,
    :verdict
  ]

  @valid_flags [:constant, :interval, :timeout, :dynamic, :auto_merge, :anonymous]
  @valid_key_types [
    :ipv4_addr,
    :ipv6_addr,
    :ether_addr,
    :inet_proto,
    :inet_service,
    :mark,
    :ifname,
    :ct_state
  ]

  @doc "Builds a map."
  @spec new(String.t(), keyword()) :: {:ok, t()} | {:error, {:bad_map, term()}}
  def new(name, opts) when is_binary(name) and is_list(opts) do
    key_type = Keyword.get(opts, :key_type)
    data_type = Keyword.get(opts, :data_type)
    flags = Keyword.get(opts, :flags, [])
    elements = Keyword.get(opts, :elements, [])

    with :ok <- validate_name(name),
         :ok <- validate_key_type(key_type),
         :ok <- validate_data_type(data_type),
         :ok <- validate_flags(flags),
         {:ok, normalized} <- validate_elements(elements, key_type, data_type),
         :ok <- validate_pos_int_or_nil(:timeout, Keyword.get(opts, :timeout)),
         :ok <- validate_pos_int_or_nil(:gc_interval, Keyword.get(opts, :gc_interval)),
         :ok <- validate_pos_int_or_nil(:size, Keyword.get(opts, :size)),
         :ok <- validate_pos_int_or_nil(:handle, Keyword.get(opts, :handle)) do
      {:ok,
       %__MODULE__{
         name: name,
         table: Keyword.get(opts, :table),
         key_type: key_type,
         data_type: data_type,
         flags: flags,
         elements: normalized,
         timeout: Keyword.get(opts, :timeout),
         gc_interval: Keyword.get(opts, :gc_interval),
         size: Keyword.get(opts, :size),
         handle: Keyword.get(opts, :handle),
         comment: Keyword.get(opts, :comment)
       }}
    end
  end

  @doc "Bang variant of `new/2`."
  @spec new!(String.t(), keyword()) :: t()
  def new!(name, opts) do
    case new(name, opts) do
      {:ok, m} -> m
      {:error, {:bad_map, reason}} -> raise ArgumentError, "invalid map: #{inspect(reason)}"
    end
  end

  @doc """
  Adds elements to a map, validating each `{key, value}` against
  the map's `:key_type` / `:data_type`. For verdict maps, values
  are accepted as `%Verdict{}` or any input form `Verdict.new!/1`
  understands (and normalised to `%Verdict{}` in the result).
  """
  @spec add_elements(t(), [{term(), term()}]) ::
          {:ok, t()} | {:error, {:bad_map_element, term()}}
  def add_elements(%__MODULE__{} = map, new_elements) when is_list(new_elements) do
    case validate_elements(new_elements, map.key_type, map.data_type) do
      {:ok, normalized} ->
        {:ok, %__MODULE__{map | elements: map.elements ++ normalized}}

      {:error, {:bad_map, reason}} ->
        {:error, {:bad_map_element, reason}}
    end
  end

  @doc """
  Removes elements from a map by key — both `{key, value}` and
  bare `key` are accepted.
  """
  @spec delete_elements(t(), [term()]) :: {:ok, t()}
  def delete_elements(%__MODULE__{} = map, to_remove) when is_list(to_remove) do
    keys =
      Enum.map(to_remove, fn
        {k, _v} -> k
        k -> k
      end)

    remaining = Enum.reject(map.elements, fn {k, _v} -> k in keys end)
    {:ok, %__MODULE__{map | elements: remaining}}
  end

  # ----- validators -----

  defp validate_name(""), do: {:error, {:bad_map, :name_empty}}
  defp validate_name(_), do: :ok

  defp validate_key_type(nil), do: {:error, {:bad_map, :key_type_required}}
  defp validate_key_type(t) when t in @valid_key_types, do: :ok

  # Concatenated key (`type ipv4_addr . inet_service`), same shape
  # Linx.Netfilter.Set accepts: a tuple of atomic key types, elements
  # are lists with one part per field.
  defp validate_key_type({:concat, types}) when is_list(types) and length(types) >= 2 do
    if Enum.all?(types, &(&1 in @valid_key_types)) do
      :ok
    else
      {:error, {:bad_map, {:unknown_key_type, {:concat, types}}}}
    end
  end

  defp validate_key_type(other), do: {:error, {:bad_map, {:unknown_key_type, other}}}

  defp validate_data_type(nil), do: {:error, {:bad_map, :data_type_required}}
  defp validate_data_type(t) when t in @valid_data_types, do: :ok
  defp validate_data_type(other), do: {:error, {:bad_map, {:unknown_data_type, other}}}

  defp validate_flags(flags) when is_list(flags) do
    Enum.reduce_while(flags, :ok, fn flag, :ok ->
      if flag in @valid_flags do
        {:cont, :ok}
      else
        {:halt, {:error, {:bad_map, {:unknown_flag, flag}}}}
      end
    end)
  end

  defp validate_flags(other), do: {:error, {:bad_map, {:flags_not_list, other}}}

  defp validate_elements(elements, key_type, data_type) when is_list(elements) do
    Enum.reduce_while(elements, {:ok, []}, fn item, {:ok, acc} ->
      case normalize_element(item, key_type, data_type) do
        {:ok, normalized} -> {:cont, {:ok, [normalized | acc]}}
        {:error, reason} -> {:halt, {:error, {:bad_map, reason}}}
      end
    end)
    |> case do
      {:ok, rev} -> {:ok, Enum.reverse(rev)}
      err -> err
    end
  end

  defp validate_elements(other, _, _), do: {:error, {:bad_map, {:elements_not_list, other}}}

  defp normalize_element({k, v}, key_type, data_type) do
    with :ok <- Linx.Netfilter.Set.Element.check(k, key_type),
         {:ok, v2} <- normalize_value(v, data_type) do
      {:ok, {k, v2}}
    else
      {:error, reason} -> {:error, {:bad_element, {k, v}, reason}}
    end
  end

  defp normalize_element(other, _, _), do: {:error, {:element_not_tuple, other}}

  defp normalize_value(v, :verdict) do
    case Verdict.new(v) do
      {:ok, %Verdict{} = nv} -> {:ok, nv}
      {:error, {:bad_verdict, _} = e} -> {:error, e}
    end
  end

  defp normalize_value(v, data_type) do
    case Linx.Netfilter.Set.Element.check(v, data_type) do
      :ok -> {:ok, v}
      err -> err
    end
  end

  defp validate_pos_int_or_nil(_, nil), do: :ok
  defp validate_pos_int_or_nil(_, n) when is_integer(n) and n > 0, do: :ok

  defp validate_pos_int_or_nil(field, other),
    do: {:error, {:bad_map, {:bad_field, field, other}}}

  defimpl Inspect do
    def inspect(%Linx.Netfilter.Map{} = m, _opts) do
      "#Linx.Netfilter.Map<#{m.name}(#{m.key_type}→#{m.data_type}): " <>
        "#{length(m.elements)} elements>"
    end
  end
end
