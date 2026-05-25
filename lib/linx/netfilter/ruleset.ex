defmodule Linx.Netfilter.Ruleset do
  @moduledoc """
  The top-level netfilter value type — a netns-shaped collection of
  tables (and everything inside them) as plain data.

  A `%Ruleset{}` is what `push/2` writes to the kernel, what
  `pull/1..2` reads back, and what `diff/2` takes pairs of. The
  pipeline DSL — `new/0`, `add_table/3`, `add_chain/4`,
  `add_rule/4`, `add_set/3`, `add_map/3`, `add_object/3`,
  `add_flowtable/3` — is how authoring-time code builds one. The
  `~NFT` sigil (N8) compiles to the same DSL calls.

  ## Fields

    * `:tables` — `%{{family, name} => %Linx.Netfilter.Table{}}`.
      Tables are uniquely identified by `(family, name)` at the
      kernel level — `inet mytable` and `ip mytable` coexist as
      distinct tables.

  ## Pipeline DSL

  Two flavours of every mutator:

    * Plain (e.g. `add_table/3`) — returns
      `{:ok, Ruleset.t()} | {:error, {:bad_X, reason}}`. Validator-
      setter shape; compose via `with`.
    * Bang (e.g. `add_table!/3`) — returns `Ruleset.t()` or raises
      `ArgumentError`. Pipeline-friendly for inline construction.

      ruleset =
        Ruleset.new()
        |> Ruleset.add_table!(:inet, "myapp")
        |> Ruleset.add_chain!("myapp", "input",
             type: :filter, hook: :input, priority: 0, policy: :drop)
        |> Ruleset.add_rule!("myapp", "input",
             Rule.build!([Expr.immediate(:accept)], tag: :allow_all))

  ## Table references

  Most mutators accept either a bare name string (when unambiguous)
  or a `{family, name}` tuple. A bare name raises / errors with
  `:ambiguous_table_name` if the ruleset has multiple tables of
  that name across families.

      add_chain!(rs, "myapp", "input", ...)          # name → unambiguous
      add_chain!(rs, {:inet, "myapp"}, "input", ...) # tuple → explicit

  ## Errors

  Validator-setter functions return tagged-tuple errors so callers
  can pattern-match on the *kind* of failure:

    * `{:bad_table, _}` — bad family / flag / duplicate name.
    * `{:bad_chain, _}` — bad hook/type, missing device on ingress,
      etc. (from `Chain.new/2` and `Chain.validate_for_family/2`).
    * `{:bad_rule, _}` — bad expression list, duplicate tag.
    * `{:bad_set, _}` / `{:bad_set_element, _}` — set shape /
      element type mismatch.
    * `{:bad_map, _}` / `{:bad_map_element, _}` — map shape /
      element shape (including non-verdict data in vmaps).
    * `{:bad_object, _}` / `{:bad_flowtable, _}`.
    * `{:no_such_table, ref}` / `{:no_such_chain, ref}` /
      `{:ambiguous_table_name, name}` — navigation failures.

  Kernel-rejection errors come back as `%Linx.Netfilter.Error{}` —
  always distinct from the value-type errors above.
  """

  alias Linx.Netfilter.{Chain, Flowtable, Object, Rule, Set, Table}
  alias Linx.Netfilter.Map, as: NMap

  defstruct tables: %{}

  @type table_ref :: String.t() | {Table.family(), String.t()}
  @type t :: %__MODULE__{tables: %{optional({Table.family(), String.t()}) => Table.t()}}

  @doc "An empty ruleset."
  @spec new() :: t()
  def new, do: %__MODULE__{}

  # ===========================================================
  # Tables
  # ===========================================================

  @doc """
  Adds a new table to the ruleset. Builds the table via
  `Table.new/3`, checks `(family, name)` uniqueness, inserts.
  """
  @spec add_table(t(), Table.family(), String.t(), keyword()) ::
          {:ok, t()} | {:error, {:bad_table, term()}}
  def add_table(%__MODULE__{} = rs, family, name, opts \\ []) do
    key = {family, name}

    cond do
      Map.has_key?(rs.tables, key) ->
        {:error, {:bad_table, {:duplicate_table, key}}}

      true ->
        with {:ok, table} <- Table.new(family, name, opts) do
          {:ok, %__MODULE__{rs | tables: Map.put(rs.tables, key, table)}}
        end
    end
  end

  @doc "Bang variant of `add_table/4`."
  @spec add_table!(t(), Table.family(), String.t(), keyword()) :: t()
  def add_table!(%__MODULE__{} = rs, family, name, opts \\ []) do
    bang(add_table(rs, family, name, opts))
  end

  @doc """
  Removes a table from the ruleset by reference. Returns
  `{:error, {:no_such_table, ref}}` if absent.
  """
  @spec delete_table(t(), table_ref()) :: {:ok, t()} | {:error, term()}
  def delete_table(%__MODULE__{} = rs, ref) do
    with {:ok, key} <- resolve_table_key(rs, ref) do
      {:ok, %__MODULE__{rs | tables: Map.delete(rs.tables, key)}}
    end
  end

  @doc "Bang variant of `delete_table/2`."
  @spec delete_table!(t(), table_ref()) :: t()
  def delete_table!(rs, ref), do: bang(delete_table(rs, ref))

  @doc "Fetches a table by reference."
  @spec fetch_table(t(), table_ref()) :: {:ok, Table.t()} | {:error, term()}
  def fetch_table(%__MODULE__{} = rs, ref) do
    with {:ok, key} <- resolve_table_key(rs, ref) do
      Map.fetch!(rs.tables, key) |> then(&{:ok, &1})
    end
  end

  @doc """
  Lists tables — `[{family, name, %Table{}}, ...]`.
  """
  @spec tables(t()) :: [{Table.family(), String.t(), Table.t()}]
  def tables(%__MODULE__{tables: tables}) do
    Enum.map(tables, fn {{f, n}, t} -> {f, n, t} end)
  end

  # ===========================================================
  # Chains
  # ===========================================================

  @doc """
  Adds a chain to a table, building it inline via `Chain.new/2`.

  `table_ref` is a bare name string (unambiguous case) or a
  `{family, name}` tuple.
  """
  @spec add_chain(t(), table_ref(), String.t(), keyword()) ::
          {:ok, t()} | {:error, term()}
  def add_chain(%__MODULE__{} = rs, table_ref, chain_name, opts \\ []) do
    with {:ok, key, table} <- resolve_table(rs, table_ref),
         {:ok, chain} <- Chain.new(chain_name, opts),
         {:ok, table2} <- Table.add_chain(table, chain) do
      {:ok, %__MODULE__{rs | tables: Map.put(rs.tables, key, table2)}}
    end
  end

  @doc "Bang variant."
  @spec add_chain!(t(), table_ref(), String.t(), keyword()) :: t()
  def add_chain!(rs, table_ref, chain_name, opts \\ []) do
    bang(add_chain(rs, table_ref, chain_name, opts))
  end

  @doc """
  Inserts a pre-built `%Chain{}` into a table.
  """
  @spec put_chain(t(), table_ref(), Chain.t()) :: {:ok, t()} | {:error, term()}
  def put_chain(%__MODULE__{} = rs, table_ref, %Chain{} = chain) do
    with {:ok, key, table} <- resolve_table(rs, table_ref),
         {:ok, table2} <- Table.add_chain(table, chain) do
      {:ok, %__MODULE__{rs | tables: Map.put(rs.tables, key, table2)}}
    end
  end

  @doc "Bang variant."
  @spec put_chain!(t(), table_ref(), Chain.t()) :: t()
  def put_chain!(rs, table_ref, chain), do: bang(put_chain(rs, table_ref, chain))

  # ===========================================================
  # Rules
  # ===========================================================

  @doc """
  Appends a rule to a chain inside a table.

  `rule_or_exprs` is either a pre-built `%Rule{}` or a list of
  expressions (passed to `Rule.build/2`). When `rule_or_exprs` is a
  list, `opts` are forwarded to `Rule.build/2` (tag / comment /
  handle).

  Tag uniqueness within the chain is enforced — a rule with a
  duplicate tag returns `{:error, {:bad_rule, {:duplicate_tag, _}}}`.
  Untagged rules are always accepted.
  """
  @spec add_rule(t(), table_ref(), String.t(), Rule.t() | [Rule.expression_input()], keyword()) ::
          {:ok, t()} | {:error, term()}
  def add_rule(%__MODULE__{} = rs, table_ref, chain_name, rule_or_exprs, opts \\ []) do
    with {:ok, key, table} <- resolve_table(rs, table_ref),
         {:ok, chain} <- Table.fetch_chain(table, chain_name) |> wrap_chain(chain_name),
         {:ok, rule} <- coerce_rule(rule_or_exprs, opts),
         :ok <- check_unique_tag(chain, rule),
         {:ok, chain2} <- Chain.add_rule(chain, rule),
         {:ok, table2} <- Table.put_chain(table, chain2) do
      {:ok, %__MODULE__{rs | tables: Map.put(rs.tables, key, table2)}}
    end
  end

  @doc "Bang variant."
  @spec add_rule!(t(), table_ref(), String.t(), Rule.t() | [Rule.expression_input()], keyword()) :: t()
  def add_rule!(rs, table_ref, chain_name, rule_or_exprs, opts \\ []) do
    bang(add_rule(rs, table_ref, chain_name, rule_or_exprs, opts))
  end

  # ===========================================================
  # Sets / maps / objects / flowtables
  # ===========================================================

  @doc "Adds a set to a table."
  @spec add_set(t(), table_ref(), Set.t()) :: {:ok, t()} | {:error, term()}
  def add_set(%__MODULE__{} = rs, table_ref, %Set{} = set) do
    with {:ok, key, table} <- resolve_table(rs, table_ref),
         {:ok, table2} <- Table.add_set(table, set) do
      {:ok, %__MODULE__{rs | tables: Map.put(rs.tables, key, table2)}}
    end
  end

  @doc "Bang variant."
  @spec add_set!(t(), table_ref(), Set.t()) :: t()
  def add_set!(rs, table_ref, set), do: bang(add_set(rs, table_ref, set))

  @doc "Adds a map (or vmap) to a table."
  @spec add_map(t(), table_ref(), NMap.t()) :: {:ok, t()} | {:error, term()}
  def add_map(%__MODULE__{} = rs, table_ref, %NMap{} = map) do
    with {:ok, key, table} <- resolve_table(rs, table_ref),
         {:ok, table2} <- Table.add_map(table, map) do
      {:ok, %__MODULE__{rs | tables: Map.put(rs.tables, key, table2)}}
    end
  end

  @doc "Bang variant."
  @spec add_map!(t(), table_ref(), NMap.t()) :: t()
  def add_map!(rs, table_ref, map), do: bang(add_map(rs, table_ref, map))

  @doc "Adds an object to a table."
  @spec add_object(t(), table_ref(), Object.t()) :: {:ok, t()} | {:error, term()}
  def add_object(%__MODULE__{} = rs, table_ref, %Object{} = obj) do
    with {:ok, key, table} <- resolve_table(rs, table_ref),
         {:ok, table2} <- Table.add_object(table, obj) do
      {:ok, %__MODULE__{rs | tables: Map.put(rs.tables, key, table2)}}
    end
  end

  @doc "Bang variant."
  @spec add_object!(t(), table_ref(), Object.t()) :: t()
  def add_object!(rs, table_ref, obj), do: bang(add_object(rs, table_ref, obj))

  @doc "Adds a flowtable to a table."
  @spec add_flowtable(t(), table_ref(), Flowtable.t()) :: {:ok, t()} | {:error, term()}
  def add_flowtable(%__MODULE__{} = rs, table_ref, %Flowtable{} = ft) do
    with {:ok, key, table} <- resolve_table(rs, table_ref),
         {:ok, table2} <- Table.add_flowtable(table, ft) do
      {:ok, %__MODULE__{rs | tables: Map.put(rs.tables, key, table2)}}
    end
  end

  @doc "Bang variant."
  @spec add_flowtable!(t(), table_ref(), Flowtable.t()) :: t()
  def add_flowtable!(rs, table_ref, ft), do: bang(add_flowtable(rs, table_ref, ft))

  # ===========================================================
  # Internals
  # ===========================================================

  defp resolve_table(rs, ref) do
    with {:ok, key} <- resolve_table_key(rs, ref) do
      {:ok, key, Map.fetch!(rs.tables, key)}
    end
  end

  defp resolve_table_key(rs, {family, name}) when is_atom(family) and is_binary(name) do
    key = {family, name}

    if Map.has_key?(rs.tables, key) do
      {:ok, key}
    else
      {:error, {:no_such_table, key}}
    end
  end

  defp resolve_table_key(rs, name) when is_binary(name) do
    matches =
      rs.tables
      |> Enum.filter(fn {{_, n}, _} -> n == name end)
      |> Enum.map(fn {key, _} -> key end)

    case matches do
      [key] -> {:ok, key}
      [] -> {:error, {:no_such_table, name}}
      _ -> {:error, {:ambiguous_table_name, name}}
    end
  end

  defp resolve_table_key(_rs, other), do: {:error, {:no_such_table, other}}

  defp wrap_chain({:ok, chain}, _name), do: {:ok, chain}
  defp wrap_chain({:error, :no_such_chain}, name), do: {:error, {:no_such_chain, name}}

  defp coerce_rule(%Rule{} = r, _opts), do: {:ok, r}
  defp coerce_rule(exprs, opts) when is_list(exprs), do: Rule.build(exprs, opts)
  defp coerce_rule(other, _), do: {:error, {:bad_rule, {:not_a_rule_or_list, other}}}

  defp check_unique_tag(_chain, %Rule{tag: nil}), do: :ok

  defp check_unique_tag(%Chain{rules: rules}, %Rule{tag: tag}) do
    if Enum.any?(rules, &(&1.tag == tag)) do
      {:error, {:bad_rule, {:duplicate_tag, tag}}}
    else
      :ok
    end
  end

  defp bang({:ok, value}), do: value

  defp bang({:error, reason}) do
    raise ArgumentError,
          "Linx.Netfilter.Ruleset operation failed: #{inspect(reason)}"
  end
end
