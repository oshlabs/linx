defmodule Linx.Reconcile.FlatKV do
  @moduledoc false

  @type key :: term()
  @type value :: term()
  @type ownership :: %{applied: value(), original: value() | nil}
  @type last_applied :: %{optional(key()) => ownership()}
  @type op :: {:set, key(), value()} | {:revert, key(), value()} | {:release, key()}

  @doc false
  @spec relevant_keys(map(), last_applied()) :: [key()]
  def relevant_keys(desired, last_applied) when is_map(desired) and is_map(last_applied) do
    Enum.uniq(Map.keys(desired) ++ Map.keys(last_applied))
  end

  @doc false
  @spec diff(map(), map(), last_applied(), boolean(), (value(), value() -> boolean())) :: [op()]
  def diff(observed, desired, last_applied, revert?, same_value?)
      when is_map(observed) and is_map(desired) and is_map(last_applied) and
             is_boolean(revert?) and is_function(same_value?, 2) do
    sets =
      for {key, value} <- desired,
          not converged?(observed, key, value, same_value?),
          do: {:set, key, value}

    releases =
      for {key, ownership} <- last_applied, not Map.has_key?(desired, key) do
        case {revert?, ownership[:original]} do
          {true, original} when not is_nil(original) -> {:revert, key, original}
          _ -> {:release, key}
        end
      end

    sets ++ releases
  end

  @doc false
  @spec apply(
          [op()],
          map(),
          map(),
          last_applied(),
          (op() -> :ok | {:error, term()}),
          module(),
          module()
        ) :: struct()
  def apply(ops, observed, desired, last_applied, run_op, report_module, error_module)
      when is_list(ops) and is_function(run_op, 1) and is_atom(report_module) and
             is_atom(error_module) do
    results = Enum.map(ops, fn op -> {op, run_op.(op)} end)
    applied = for {op, :ok} <- results, do: op

    failed =
      for {op, {:error, error}} <- results, is_struct(error, error_module), do: {op, error}

    struct!(report_module,
      converged?: failed == [],
      applied: applied,
      failed: failed,
      pending: [],
      last_applied: next_last_applied(results, observed, desired, last_applied)
    )
  end

  defp converged?(observed, key, desired_value, same_value?) do
    case Map.fetch(observed, key) do
      {:ok, raw} -> same_value?.(raw, desired_value)
      :error -> false
    end
  end

  # Capture the pre-management value once. Failed sets retain prior ownership,
  # and failed reverts remain owned so the next pass retries them.
  defp next_last_applied(results, observed, desired, last_applied) do
    failed_sets = MapSet.new(for {{:set, key, _}, {:error, _}} <- results, do: key)

    owned =
      for {key, value} <- desired, not MapSet.member?(failed_sets, key), into: %{} do
        {key, %{applied: value, original: original_for(key, last_applied, observed)}}
      end

    preserved =
      for {key, _value} <- desired,
          MapSet.member?(failed_sets, key),
          Map.has_key?(last_applied, key),
          into: %{},
          do: {key, last_applied[key]}

    kept_reverts =
      for {{:revert, key, _}, {:error, _}} <- results,
          Map.has_key?(last_applied, key),
          into: %{},
          do: {key, last_applied[key]}

    owned |> Map.merge(preserved) |> Map.merge(kept_reverts)
  end

  defp original_for(key, last_applied, observed) do
    case last_applied do
      %{^key => %{original: original}} -> original
      _ -> Map.get(observed, key)
    end
  end
end
