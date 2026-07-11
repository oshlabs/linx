defmodule Linx.Netfilter.Set do
  @moduledoc """
  An nftables set — a named collection of elements with a uniform
  key type, used for O(1) lookups in rules.

  Sets are the kernel's high-performance match primitive: a rule
  saying "if source IP is in @blocklist drop" hashes once into the
  set rather than scanning a hundred individual rules.
  Concatenations, dynamic sets, and intervals are not yet
  implemented (see `docs/netfilter/netfilter-overview.md`).

  ## Fields

    * `:name` — set name (unique within the table).
    * `:table` — owning table's name; `nil` for free-standing sets.
    * `:key_type` — element-type atom. The basic atomic types are
      accepted: `:ipv4_addr`, `:ipv6_addr`, `:ether_addr`,
      `:inet_proto`, `:inet_service`, `:mark`, `:ifname`.
      Concatenations (`{:concat, [type1, type2, ...]}`) are not yet
      implemented.
    * `:flags` — list. Currently accepted: `:constant`,
      `:interval`, `:timeout`, `:dynamic`, `:auto_merge`,
      `:anonymous`. The timeout / dynamic / interval flags are not
      yet fully implemented; the value-type slot is here today.
    * `:elements` — list of element values matching `:key_type`.
      Element-type validation is a basic check; strict validation
      is not yet implemented.
    * `:timeout` — default element lifetime in ms; `nil` for no
      timeout (default).
    * `:gc_interval` — kernel's gc cadence in ms; `nil` to let the
      kernel choose.
    * `:size` — maximum element count; `nil` for unbounded.
    * `:handle` — kernel-assigned handle; `nil` until pushed.
    * `:comment` — round-trips via set userdata.

  ## Construction

      iex> Set.new("blocklist", key_type: :ipv4_addr)
      {:ok, %Linx.Netfilter.Set{name: "blocklist", key_type: :ipv4_addr, ...}}

      iex> Set.new("ssh_clients", key_type: :ipv4_addr,
      ...>          flags: [:timeout], timeout: 60_000)
      {:ok, %Linx.Netfilter.Set{...}}

  Errors come back as `{:error, {:bad_set, reason}}`.
  Element-shape errors as `{:error, {:bad_set_element, reason}}`.

  ## References

    * [wiki.nftables.org — Sets](https://wiki.nftables.org/wiki-nftables/index.php/Sets)
  """

  @enforce_keys [:name, :key_type]
  defstruct [
    :name,
    :table,
    :key_type,
    :timeout,
    :gc_interval,
    :size,
    :handle,
    :comment,
    flags: [],
    elements: []
  ]

  @type key_type ::
          :ipv4_addr | :ipv6_addr | :ether_addr | :inet_proto | :inet_service | :mark | :ifname

  @type flag :: :constant | :interval | :timeout | :dynamic | :auto_merge | :anonymous

  @type t :: %__MODULE__{
          name: String.t(),
          table: String.t() | nil,
          key_type: key_type(),
          flags: [flag()],
          elements: [term()],
          timeout: pos_integer() | nil,
          gc_interval: pos_integer() | nil,
          size: pos_integer() | nil,
          handle: pos_integer() | nil,
          comment: String.t() | nil
        }

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

  @valid_flags [:constant, :interval, :timeout, :dynamic, :auto_merge, :anonymous]

  @doc "Builds a set."
  @spec new(String.t(), keyword()) :: {:ok, t()} | {:error, {:bad_set, term()}}
  def new(name, opts) when is_binary(name) and is_list(opts) do
    key_type = Keyword.get(opts, :key_type)
    flags = Keyword.get(opts, :flags, [])
    elements = Keyword.get(opts, :elements, [])

    with :ok <- validate_name(name),
         :ok <- validate_key_type(key_type),
         :ok <- validate_flags(flags),
         :ok <- validate_elements(elements, key_type),
         :ok <- validate_pos_int_or_nil(:timeout, Keyword.get(opts, :timeout)),
         :ok <- validate_pos_int_or_nil(:gc_interval, Keyword.get(opts, :gc_interval)),
         :ok <- validate_pos_int_or_nil(:size, Keyword.get(opts, :size)),
         :ok <- validate_pos_int_or_nil(:handle, Keyword.get(opts, :handle)) do
      {:ok,
       %__MODULE__{
         name: name,
         table: Keyword.get(opts, :table),
         key_type: key_type,
         flags: flags,
         elements: elements,
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
      {:ok, s} -> s
      {:error, {:bad_set, reason}} -> raise ArgumentError, "invalid set: #{inspect(reason)}"
    end
  end

  @doc """
  Adds elements to a set, validating each against the set's
  `:key_type`. Returns the updated set or
  `{:error, {:bad_set_element, reason}}`.
  """
  @spec add_elements(t(), [term()]) :: {:ok, t()} | {:error, {:bad_set_element, term()}}
  def add_elements(%__MODULE__{} = set, new_elements) when is_list(new_elements) do
    case validate_elements(new_elements, set.key_type) do
      :ok -> {:ok, %__MODULE__{set | elements: set.elements ++ new_elements}}
      {:error, {:bad_set, reason}} -> {:error, {:bad_set_element, reason}}
    end
  end

  @doc """
  Removes elements from a set. No validation — removes whichever
  elements match by equality.
  """
  @spec delete_elements(t(), [term()]) :: {:ok, t()}
  def delete_elements(%__MODULE__{} = set, to_remove) when is_list(to_remove) do
    {:ok, %__MODULE__{set | elements: set.elements -- to_remove}}
  end

  # ----- validators -----

  defp validate_name(""), do: {:error, {:bad_set, :name_empty}}
  defp validate_name(_), do: :ok

  defp validate_key_type(nil), do: {:error, {:bad_set, :key_type_required}}
  defp validate_key_type(t) when t in @valid_key_types, do: :ok

  # Concatenated key (`type ipv4_addr . inet_service`): a tuple of
  # atomic key types. Elements are lists with one part per field.
  defp validate_key_type({:concat, types}) when is_list(types) and length(types) >= 2 do
    if Enum.all?(types, &(&1 in @valid_key_types)) do
      :ok
    else
      {:error, {:bad_set, {:unknown_key_type, {:concat, types}}}}
    end
  end

  defp validate_key_type(other), do: {:error, {:bad_set, {:unknown_key_type, other}}}

  defp validate_flags(flags) when is_list(flags) do
    Enum.reduce_while(flags, :ok, fn flag, :ok ->
      if flag in @valid_flags do
        {:cont, :ok}
      else
        {:halt, {:error, {:bad_set, {:unknown_flag, flag}}}}
      end
    end)
  end

  defp validate_flags(other), do: {:error, {:bad_set, {:flags_not_list, other}}}

  defp validate_elements(elements, key_type) when is_list(elements) do
    Enum.reduce_while(elements, :ok, fn el, :ok ->
      case Linx.Netfilter.Set.Element.check(el, key_type) do
        :ok -> {:cont, :ok}
        {:error, reason} -> {:halt, {:error, {:bad_set, {:bad_element, el, reason}}}}
      end
    end)
  end

  defp validate_elements(other, _), do: {:error, {:bad_set, {:elements_not_list, other}}}

  defp validate_pos_int_or_nil(_, nil), do: :ok
  defp validate_pos_int_or_nil(_, n) when is_integer(n) and n > 0, do: :ok

  defp validate_pos_int_or_nil(field, other),
    do: {:error, {:bad_set, {:bad_field, field, other}}}

  defimpl Inspect do
    def inspect(%Linx.Netfilter.Set{} = s, _opts) do
      kt =
        case s.key_type do
          {:concat, types} -> Enum.join(types, " . ")
          atom -> to_string(atom)
        end

      "#Linx.Netfilter.Set<#{s.name}(#{kt}): #{length(s.elements)} elements>"
    end
  end
end

defmodule Linx.Netfilter.Set.Element do
  @moduledoc false

  # Loose element-shape checking — just catches obvious mismatches
  # at construction time. Strict validation is not yet implemented.

  # `{:range, lo, hi}` — an interval element (the canonical form for
  # `22-25` / CIDR-in-set). Both bounds must pass the scalar check; the
  # encoder emits the start/end pair.
  def check({:range, lo, hi}, type) do
    with :ok <- check(lo, type), do: check(hi, type)
  end

  # Concatenated key element: one part per field, each checked
  # against its field's type. Range/CIDR parts are fine — with the
  # `:interval` flag they become pipapo intervals (the encoder
  # emits NFTA_SET_ELEM_KEY_END bounds).
  def check(parts, {:concat, types}) when is_list(parts) do
    if length(parts) != length(types) do
      {:error, {:concat_arity, length(parts), length(types)}}
    else
      parts
      |> Enum.zip(types)
      |> Enum.reduce_while(:ok, fn {part, type}, :ok ->
        case check(part, type) do
          :ok -> {:cont, :ok}
          {:error, reason} -> {:halt, {:error, reason}}
        end
      end)
    end
  end

  def check(el, :ipv4_addr) do
    cond do
      is_binary(el) and byte_size(el) == 4 ->
        :ok

      match?({a, b, c, d} when a in 0..255 and b in 0..255 and c in 0..255 and d in 0..255, el) ->
        :ok

      # textual "1.2.3.4" form — accepted, parsed later
      is_binary(el) ->
        :ok

      true ->
        {:error, {:not_ipv4, el}}
    end
  end

  def check(el, :ipv6_addr) do
    cond do
      is_binary(el) and byte_size(el) == 16 -> :ok
      # textual "::1" form
      is_binary(el) -> :ok
      true -> {:error, {:not_ipv6, el}}
    end
  end

  def check(el, :ether_addr) do
    cond do
      is_binary(el) and byte_size(el) == 6 -> :ok
      # textual "aa:bb:..." form
      is_binary(el) -> :ok
      true -> {:error, {:not_ether, el}}
    end
  end

  def check(el, :inet_proto) when is_integer(el) and el in 0..255, do: :ok
  def check(el, :inet_proto) when is_atom(el), do: :ok
  def check(el, :inet_proto), do: {:error, {:not_inet_proto, el}}

  def check(el, :inet_service) when is_integer(el) and el in 0..65_535, do: :ok

  def check({lo, hi}, :inet_service)
      when is_integer(lo) and is_integer(hi) and lo in 0..65_535 and hi in 0..65_535,
      do: :ok

  def check(el, :inet_service), do: {:error, {:not_inet_service, el}}

  def check(el, :mark) when is_integer(el) and el >= 0 and el < 0x1_0000_0000, do: :ok
  def check(el, :mark), do: {:error, {:not_mark, el}}

  def check(el, :ifname) when is_binary(el), do: :ok
  def check(el, :ifname), do: {:error, {:not_ifname, el}}

  # ct state keys are the state's bit value (u32).
  def check(el, :ct_state) when is_integer(el) and el >= 0 and el < 0x1_0000_0000, do: :ok
  def check(el, :ct_state), do: {:error, {:not_ct_state, el}}
end
