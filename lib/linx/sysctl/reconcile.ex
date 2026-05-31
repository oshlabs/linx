defmodule Linx.Sysctl.Reconcile do
  @moduledoc """
  Single-shot declarative reconciliation for sysctls — observe, diff, apply
  once, and return what happened.

  This is the *mechanism* half of declarative config: caller-driven, holds no
  long-lived state, owns no process. The long-lived control loop, `.conf`
  parsing, and reload policy stay out — they belong to a consumer (or the
  opt-in reconcile loop). `Linx.Sysctl` remains pure primitives; this module
  composes them into the observe → diff → converge triad.

  Sysctl is the simplest declarative subsystem — a flat `%{key => value}` map
  with no ordering or identity subtlety — so it is also the proving ground for
  the reconcile discipline that the harder subsystems (rtnl) reuse. The
  function shapes here (`observe`/`diff`/`reconcile`) deliberately match the
  contract a generic reconcile loop will drive.

  ## Desired state

  A plain map from dot-form key to the value you want, using the same value
  types `Linx.Sysctl.write/3` accepts:

      %{
        "net.ipv4.ip_forward" => 1,
        "kernel.printk" => [4, 4, 1, 7],
        "kernel.hostname" => "ct0"
      }

  ## `last_applied` — three-way ownership

  Convergence alone (write where observed differs from desired) is two-way and
  needs no history. The third input, `last_applied`, is what lets reconcile do
  the right thing when a key *leaves* the desired set — the sysctl analogue of
  `kubectl apply`'s last-applied-configuration. It is a map:

      %{key => %{applied: value_we_wrote, original: value_before_we_touched_it}}

  It is **reconciler-held** state: returned in the report as
  `report.last_applied`, threaded by the caller into the next pass, and never
  persisted (it dies with the node — see the reconcile design notes). Start
  from `%{}`.

  When a key in `last_applied` is no longer in `desired` it is *released*:

    * default — the kernel value is left untouched and the op is reported as
      `{:release, key}` (sysctl has no "unset"; we simply stop managing it);
    * with `revert_on_release: true` — we write the captured `:original` back,
      reported as `{:revert, key, original}`. Off by default because reverting
      is a surprising side effect and the captured original is only meaningful
      while the node that captured it is alive.

  ## Strategy

  Sysctl writes are independent per key, so a pass is **best-effort**: every op
  is attempted; failures collect in `report.failed` and never starve the
  others. The next pass re-converges anything still wrong (level-triggered:
  events are hints, resync is truth).

  ## Example

      desired = %{"net.ipv4.ip_forward" => 1, "net.ipv4.conf.all.rp_filter" => 1}

      {:ok, r} = Linx.Sysctl.Reconcile.reconcile(desired)
      r.converged?            #=> true once the kernel matches
      r.last_applied          #=> feed into the next pass

      # later tick, against the same target
      {:ok, r2} = Linx.Sysctl.Reconcile.reconcile(desired, r.last_applied)
  """

  alias Linx.Sysctl
  alias Linx.Sysctl.Reconcile.Report

  @typedoc "A reconcile op. `:set`/`:revert` write; `:release` is a no-op marker."
  @type op ::
          {:set, Sysctl.key(), Sysctl.value()}
          | {:revert, Sysctl.key(), Sysctl.value()}
          | {:release, Sysctl.key()}

  @typedoc """
  Per-key ownership record. `:applied` is the value we last wrote; `:original`
  is the value that was there before we first touched the key (or `nil` if it
  was unreadable at capture time).
  """
  @type ownership :: %{applied: Sysctl.value(), original: Sysctl.value() | nil}

  @typedoc "Reconciler-held ownership map, keyed by dot-form sysctl key."
  @type last_applied :: %{optional(Sysctl.key()) => ownership()}

  @typedoc "Desired state: dot-form key to the value to converge on."
  @type desired :: %{optional(Sysctl.key()) => Sysctl.value()}

  @typedoc """
  Options for `reconcile/3` and `diff/4`:

    * `:in` — target namespace, forwarded verbatim to `Linx.Sysctl`
      (`:self` default, `{:pid, n}`, `{:path, p}`).
    * `:revert_on_release` — restore captured originals when a key leaves the
      desired set (default `false`).
  """
  @type opts :: [in: Sysctl.in_target(), revert_on_release: boolean()]

  @doc """
  Runs one reconcile pass against the desired state.

  Reads the current value of every relevant key (those in `desired` and those
  still owned in `last_applied`), diffs, applies best-effort, and returns
  `{:ok, %Report{}}`. The report's `:last_applied` is the updated ownership
  map to thread into the next pass.

  Never returns `{:error, _}` for kernel-level failures — per-op errors are
  recorded in `report.failed`, because a partial apply is a normal transient
  state the next pass corrects, not a fatal condition. (A malformed `:in`
  option still raises via the underlying verbs.)
  """
  @spec reconcile(desired(), last_applied(), opts()) :: {:ok, Report.t()}
  def reconcile(desired, last_applied \\ %{}, opts \\ [])
      when is_map(desired) and is_map(last_applied) and is_list(opts) do
    observed = observe(relevant_keys(desired, last_applied), opts)
    ops = diff(observed, desired, last_applied, opts)
    {:ok, apply_ops(ops, observed, desired, last_applied, opts)}
  end

  @doc """
  Reads the current value of each key into a `%{key => value}` map.

  Keys that can't be read (e.g. `:enoent`, `:eacces`) are simply absent from
  the result — the diff treats an absent desired key as needing a write and
  lets the write surface the real error.
  """
  @spec observe([Sysctl.key()], opts()) :: %{optional(Sysctl.key()) => binary()}
  def observe(keys, opts \\ []) when is_list(keys) and is_list(opts) do
    read_opts = Keyword.take(opts, [:in])

    for key <- keys, {:ok, value} <- [Sysctl.read(key, read_opts)], into: %{} do
      {key, value}
    end
  end

  @doc """
  Computes the ops that would converge `observed` to `desired`, given the
  `last_applied` ownership map. Pure — no I/O.

  Produces:

    * `{:set, key, value}` — desired key whose observed value differs (or that
      is absent from `observed`);
    * `{:revert, key, original}` — released key, when `revert_on_release: true`
      and an original was captured;
    * `{:release, key}` — released key otherwise.

  Order is irrelevant for sysctl; ops are emitted sets-then-releases for a
  stable, readable result.
  """
  @spec diff(%{optional(Sysctl.key()) => binary()}, desired(), last_applied(), opts()) :: [op()]
  def diff(observed, desired, last_applied \\ %{}, opts \\ [])
      when is_map(observed) and is_map(desired) and is_map(last_applied) and is_list(opts) do
    revert? = Keyword.get(opts, :revert_on_release, false)

    sets =
      for {key, value} <- desired, not converged?(observed, key, value) do
        {:set, key, value}
      end

    releases =
      for {key, own} <- last_applied, not Map.has_key?(desired, key) do
        case {revert?, own[:original]} do
          {true, original} when not is_nil(original) -> {:revert, key, original}
          _ -> {:release, key}
        end
      end

    sets ++ releases
  end

  # --- apply ----------------------------------------------------------------

  defp apply_ops(ops, observed, desired, last_applied, opts) do
    write_opts = Keyword.take(opts, [:in])
    results = Enum.map(ops, fn op -> {op, run_op(op, write_opts)} end)

    applied = for {op, :ok} <- results, do: op
    failed = for {op, {:error, %Sysctl.Error{} = err}} <- results, do: {op, err}

    %Report{
      converged?: failed == [],
      applied: applied,
      failed: failed,
      pending: [],
      last_applied: next_last_applied(results, observed, desired, last_applied)
    }
  end

  defp run_op({:set, key, value}, write_opts), do: Sysctl.write(key, value, write_opts)
  defp run_op({:revert, key, value}, write_opts), do: Sysctl.write(key, value, write_opts)
  defp run_op({:release, _key}, _write_opts), do: :ok

  # The updated ownership map after a pass. Ownership is claimed for every
  # desired key we successfully control (including no-op keys that were already
  # converged), capturing the pre-management original once. Keys whose :set
  # failed keep any prior ownership (so the original survives a transient
  # failure) but are not newly claimed. Released keys are dropped, unless a
  # revert *failed* — then they are kept so the next pass retries the revert.
  defp next_last_applied(results, observed, desired, last_applied) do
    failed_sets = MapSet.new(for {{:set, k, _}, {:error, _}} <- results, do: k)

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

  # The original to record for a key: a previously-captured original wins
  # (capture once), else the value observed before we first touched it.
  defp original_for(key, last_applied, observed) do
    case last_applied do
      %{^key => %{original: original}} -> original
      _ -> Map.get(observed, key)
    end
  end

  # --- value comparison -----------------------------------------------------

  # True iff the kernel's current (observed) value already matches desired.
  # An absent observed value (unreadable key) never counts as converged.
  defp converged?(observed, key, desired_value) do
    case Map.fetch(observed, key) do
      {:ok, raw} -> same_value?(raw, desired_value)
      :error -> false
    end
  end

  # Integers and integer lists compare token-wise (tuple-shaped knobs read back
  # tab- or space-separated, e.g. "4\t4\t1\t7"); binaries compare exactly,
  # since a free-form string knob may legitimately contain runs of whitespace.
  defp same_value?(raw, desired) when is_integer(desired), do: raw == Integer.to_string(desired)

  defp same_value?(raw, desired) when is_list(desired) do
    tokens(raw) == Enum.map(desired, &Integer.to_string/1)
  end

  defp same_value?(raw, desired) when is_binary(desired), do: raw == desired

  defp tokens(raw), do: String.split(raw, ~r/\s+/, trim: true)

  # Keys touched by a pass: desired keys plus still-owned keys (to detect and
  # release those that have left the desired set).
  defp relevant_keys(desired, last_applied) do
    (Map.keys(desired) ++ Map.keys(last_applied)) |> Enum.uniq()
  end
end
