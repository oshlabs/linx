defmodule Linx.Netfilter.Table do
  @moduledoc """
  An nftables table — the top-level container for chains, sets,
  maps, objects, and flowtables, scoped to one family.

  ## Fields

    * `:family` — `:ip` | `:ip6` | `:inet` | `:arp` | `:bridge` |
      `:netdev`.
    * `:name` — table name (unique within the family in the netns).
    * `:flags` — list. `:owner` enables `NFT_TABLE_F_OWNER` (the
      table auto-destroys when the owning socket closes); `:persist`
      sets `NFT_TABLE_F_PERSIST` (table survives even when
      unreferenced — owner's opt-out, kernel 6.9+); `:dormant`
      sets `NFT_TABLE_F_DORMANT` (table loaded but inactive).
    * `:use_count` — kernel-reported reference count, only set on
      pulled tables; `nil` for authoring-time tables.
    * `:handle` — kernel handle; `nil` until pushed.
    * `:chains` — `%{chain_name => %Linx.Netfilter.Chain{}}`.
    * `:sets` — `%{set_name => %Linx.Netfilter.Set{}}`.
    * `:maps` — `%{map_name => %Linx.Netfilter.Map{}}`.
    * `:objects` — `%{{kind, name} => %Linx.Netfilter.Object{}}` —
      objects are scoped by `(kind, name)` since kinds don't share
      a namespace (a `:counter` and a `:quota` of the same name
      coexist).
    * `:flowtables` — `%{ft_name => %Linx.Netfilter.Flowtable{}}`.

  ## Construction

      iex> Table.new(:inet, "myapp")
      {:ok, %Linx.Netfilter.Table{family: :inet, name: "myapp", flags: [], ...}}

      iex> Table.new(:inet, "myapp", flags: [:owner])
      {:ok, %Linx.Netfilter.Table{flags: [:owner], ...}}

  Errors: `{:error, {:bad_table, reason}}`.

  Container mutations (`add_chain/2`, `add_set/2`, …) come with
  uniqueness checks and route the entity through its family's
  validation. They return the updated table or
  `{:error, {:bad_table, …}}` (for uniqueness collisions) /
  `{:error, {:bad_chain, …}}` (for entity-shape failures).

  ## References

    * [wiki.nftables.org — Configuring tables](https://wiki.nftables.org/wiki-nftables/index.php/Configuring_tables)
  """

  alias Linx.Netfilter.{Chain, Flowtable, Object, Set}
  alias Linx.Netfilter.Map, as: NMap

  @enforce_keys [:family, :name]
  defstruct [
    :family,
    :name,
    :use_count,
    :handle,
    flags: [],
    chains: %{},
    sets: %{},
    maps: %{},
    objects: %{},
    flowtables: %{}
  ]

  @type family :: :ip | :ip6 | :inet | :arp | :bridge | :netdev
  @type flag :: :owner | :persist | :dormant

  @type t :: %__MODULE__{
          family: family(),
          name: String.t(),
          flags: [flag()],
          use_count: non_neg_integer() | nil,
          handle: pos_integer() | nil,
          chains: %{optional(String.t()) => Chain.t()},
          sets: %{optional(String.t()) => Set.t()},
          maps: %{optional(String.t()) => NMap.t()},
          objects: %{optional({Object.kind(), String.t()}) => Object.t()},
          flowtables: %{optional(String.t()) => Flowtable.t()}
        }

  @valid_families [:ip, :ip6, :inet, :arp, :bridge, :netdev]
  @valid_flags [:owner, :persist, :dormant]

  @doc "Builds a table."
  @spec new(family(), String.t(), keyword()) ::
          {:ok, t()} | {:error, {:bad_table, term()}}
  def new(family, name, opts \\ []) when is_atom(family) and is_binary(name) and is_list(opts) do
    flags = Keyword.get(opts, :flags, [])

    with :ok <- validate_family(family),
         :ok <- validate_name(name),
         :ok <- validate_flags(flags) do
      {:ok,
       %__MODULE__{
         family: family,
         name: name,
         flags: flags,
         use_count: Keyword.get(opts, :use_count),
         handle: Keyword.get(opts, :handle)
       }}
    end
  end

  @doc "Bang variant."
  @spec new!(family(), String.t(), keyword()) :: t()
  def new!(family, name, opts \\ []) do
    case new(family, name, opts) do
      {:ok, t} -> t
      {:error, {:bad_table, reason}} -> raise ArgumentError, "invalid table: #{inspect(reason)}"
    end
  end

  @doc """
  Adds a chain to the table. Validates the chain against the
  table's family and that the chain name is unique within the
  table.

  Sets the chain's `:table` field to this table's name (so
  free-standing chains pick up their context when inserted).
  """
  @spec add_chain(t(), Chain.t()) ::
          {:ok, t()} | {:error, {:bad_table | :bad_chain, term()}}
  def add_chain(%__MODULE__{} = table, %Chain{} = chain) do
    with :ok <- check_unique(table.chains, chain.name, :chain),
         :ok <- Chain.validate_for_family(chain, table.family) do
      bound = %Chain{chain | table: table.name}
      {:ok, %__MODULE__{table | chains: Map.put(table.chains, chain.name, bound)}}
    end
  end

  @doc """
  Adds a set to the table. Validates set name uniqueness within
  the table.
  """
  @spec add_set(t(), Set.t()) :: {:ok, t()} | {:error, {:bad_table, term()}}
  def add_set(%__MODULE__{} = table, %Set{} = set) do
    case check_unique(table.sets, set.name, :set) do
      :ok ->
        bound = %Set{set | table: table.name}
        {:ok, %__MODULE__{table | sets: Map.put(table.sets, set.name, bound)}}

      err ->
        err
    end
  end

  @doc """
  Adds a map (or vmap) to the table. Validates map name uniqueness
  within the table (sets and maps share a namespace at the kernel
  level — a set and a map of the same name collide).
  """
  @spec add_map(t(), NMap.t()) :: {:ok, t()} | {:error, {:bad_table, term()}}
  def add_map(%__MODULE__{} = table, %NMap{} = map) do
    cond do
      Map.has_key?(table.maps, map.name) ->
        {:error, {:bad_table, {:duplicate_map, map.name}}}

      Map.has_key?(table.sets, map.name) ->
        {:error, {:bad_table, {:set_map_name_collision, map.name}}}

      true ->
        bound = %NMap{map | table: table.name}
        {:ok, %__MODULE__{table | maps: Map.put(table.maps, map.name, bound)}}
    end
  end

  @doc """
  Adds an object to the table. Uniqueness is by `(kind, name)` —
  objects of different kinds may share a name.
  """
  @spec add_object(t(), Object.t()) :: {:ok, t()} | {:error, {:bad_table, term()}}
  def add_object(%__MODULE__{} = table, %Object{} = obj) do
    key = {obj.kind, obj.name}

    if Map.has_key?(table.objects, key) do
      {:error, {:bad_table, {:duplicate_object, key}}}
    else
      bound = %Object{obj | table: table.name}
      {:ok, %__MODULE__{table | objects: Map.put(table.objects, key, bound)}}
    end
  end

  @doc """
  Adds a flowtable to the table. Validates name uniqueness.
  """
  @spec add_flowtable(t(), Flowtable.t()) ::
          {:ok, t()} | {:error, {:bad_table, term()}}
  def add_flowtable(%__MODULE__{} = table, %Flowtable{} = ft) do
    case check_unique(table.flowtables, ft.name, :flowtable) do
      :ok ->
        bound = %Flowtable{ft | table: table.name}
        {:ok, %__MODULE__{table | flowtables: Map.put(table.flowtables, ft.name, bound)}}

      err ->
        err
    end
  end

  @doc """
  Looks up a chain by name. Returns `{:ok, chain}` or
  `{:error, :no_such_chain}`.
  """
  @spec fetch_chain(t(), String.t()) :: {:ok, Chain.t()} | {:error, :no_such_chain}
  def fetch_chain(%__MODULE__{chains: chains}, name) do
    case Map.fetch(chains, name) do
      {:ok, c} -> {:ok, c}
      :error -> {:error, :no_such_chain}
    end
  end

  @doc """
  Replaces a chain in the table. The chain must already exist by
  name (intended for use after mutating one with `Chain.add_rule/2`
  or similar).
  """
  @spec put_chain(t(), Chain.t()) :: {:ok, t()} | {:error, {:bad_table, term()}}
  def put_chain(%__MODULE__{} = table, %Chain{} = chain) do
    if Map.has_key?(table.chains, chain.name) do
      {:ok, %__MODULE__{table | chains: Map.put(table.chains, chain.name, chain)}}
    else
      {:error, {:bad_table, {:no_such_chain, chain.name}}}
    end
  end

  # ----- helpers -----

  defp check_unique(collection, name, kind) do
    if Map.has_key?(collection, name) do
      {:error, {:bad_table, {:"duplicate_#{kind}", name}}}
    else
      :ok
    end
  end

  defp validate_family(f) when f in @valid_families, do: :ok
  defp validate_family(other), do: {:error, {:bad_table, {:unknown_family, other}}}

  defp validate_name(""), do: {:error, {:bad_table, :name_empty}}
  defp validate_name(_), do: :ok

  defp validate_flags(flags) when is_list(flags) do
    Enum.reduce_while(flags, :ok, fn flag, :ok ->
      if flag in @valid_flags do
        {:cont, :ok}
      else
        {:halt, {:error, {:bad_table, {:unknown_flag, flag}}}}
      end
    end)
  end

  defp validate_flags(other), do: {:error, {:bad_table, {:flags_not_list, other}}}
end
