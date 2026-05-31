defmodule Linx.Cgroup.Reconcile do
  @moduledoc """
  Single-shot declarative reconciliation for a cgroup's **resource limits** —
  observe the interface files, diff against a desired set of knobs, apply once,
  and return what happened.

  This is the mechanism half of declarative cgroups: caller-driven, holds no
  long-lived state, owns no process. The long-lived loop is the opt-in
  `Linx.Reconcile`; the cadence and persistence are a consumer's.
  `Linx.Cgroup` stays pure primitives — this module composes
  `Linx.Cgroup.read/2` and `write/3` into the observe → diff → converge triad.

  ## Limits only — existence and membership stay in the composite

  This reconciles the **limit knobs** of one already-existing cgroup
  (`memory.max`, `pids.max`, `cpu.max`, `cpu.weight`, `memory.high`, …) — the
  drift-prone, observable, value-shaped state. It deliberately does **not**
  create or destroy the cgroup, enable controllers, or move processes: that is
  lifecycle, owned by the consumer's composite and torn down with it (see the
  reconcile design notes, §5). If the cgroup or a controller's interface file is
  absent, the corresponding write simply lands in `report.failed`; the next pass
  retries once the composite has set it up.

  This is "sysctl-with-hierarchy" — a flat `%{interface_file => value}` map
  against one cgroup path — so it mirrors `Linx.Sysctl.Reconcile` exactly,
  including the three-way `last_applied` ownership and the best-effort strategy.

  ## Desired state

  A map from interface-file name to the value you want, using the same value
  shapes the `Linx.Cgroup` setters accept:

      %{
        "memory.max" => 256 * 1024 * 1024,   # bytes, or :max to clear
        "pids.max" => 100,                    # count, or :max
        "cpu.max" => {50_000, 100_000},       # {quota_us, period_us}, or :max
        "cpu.weight" => 200                    # 1..10000
      }

  Values are integers, the atom `:max` (clear the limit), a `{quota, period}`
  tuple (for `cpu.max`), or a raw binary (escape hatch for any other knob).

  ## `last_applied` — three-way ownership

  Threaded between passes, never persisted — see `Linx.Sysctl.Reconcile` for the
  full rationale (it captures live pre-management values that die with the node).
  It is a map:

      %{file => %{applied: value_we_wrote, original: raw_value_before_we_touched_it}}

  When a file leaves the desired set it is *released*:

    * default — left at its current value, reported `{:release, file}`
      (we simply stop managing it);
    * with `revert_on_release: true` — the captured `:original` raw string is
      written back, reported `{:revert, file, original}`.

  ## Strategy

  cgroup limit writes are independent per file, so a pass is **best-effort**:
  every op is attempted, and any that fail collect in `report.failed` without
  starving the others. The next pass re-converges anything still wrong.

  ## Example

      {:ok, cg} = Linx.Cgroup.create("/sys/fs/cgroup/myorg/web-42")
      :ok = Linx.Cgroup.enable_controllers("/sys/fs/cgroup/myorg", [:memory, :pids])

      desired = %{"memory.max" => 256 * 1024 * 1024, "pids.max" => 100}

      {:ok, r} = Linx.Cgroup.Reconcile.reconcile(cg, desired)
      r.converged?
      {:ok, r2} = Linx.Cgroup.Reconcile.reconcile(cg, desired, r.last_applied)  # idempotent
  """

  alias Linx.Cgroup
  alias Linx.Cgroup.Reconcile.Report

  @typedoc "A cgroup interface-file name, e.g. `\"memory.max\"`."
  @type file :: String.t()

  @typedoc "A desired knob value, in any shape `Linx.Cgroup`'s setters accept."
  @type value :: non_neg_integer() | :max | {pos_integer(), pos_integer()} | binary()

  @typedoc "A reconcile op. `:set`/`:revert` write; `:release` is a no-op marker."
  @type op ::
          {:set, file(), value()}
          | {:revert, file(), binary()}
          | {:release, file()}

  @typedoc """
  Per-file ownership record. `:applied` is the value we last wrote; `:original`
  is the raw interface-file string present before we first touched the file (or
  `nil` if it was unreadable at capture time).
  """
  @type ownership :: %{applied: value(), original: binary() | nil}

  @typedoc "Reconciler-held ownership map, keyed by interface-file name."
  @type last_applied :: %{optional(file()) => ownership()}

  @typedoc "Desired state: interface-file name to the value to converge on."
  @type desired :: %{optional(file()) => value()}

  @typedoc """
  Options for `reconcile/4` and `diff/4`:

    * `:revert_on_release` — restore captured originals when a file leaves the
      desired set (default `false`).
  """
  @type opts :: [revert_on_release: boolean()]

  @doc """
  Runs one reconcile pass against `desired` for the cgroup at `cg`.

  Reads the current value of every relevant file (those in `desired` and those
  still owned in `last_applied`), diffs, applies best-effort, and returns
  `{:ok, %Report{}}`. The report's `:last_applied` is the updated ownership map
  to thread into the next pass.

  Never returns `{:error, _}`: a per-file write failure (a missing controller,
  no permission) is recorded in `report.failed`, since a partial apply is a
  normal transient state the next pass corrects.
  """
  @spec reconcile(Cgroup.cgroup(), desired(), last_applied(), opts()) :: {:ok, Report.t()}
  def reconcile(cg, desired, last_applied \\ %{}, opts \\ [])
      when is_binary(cg) and is_map(desired) and is_map(last_applied) and is_list(opts) do
    observed = observe(cg, relevant_keys(desired, last_applied))
    ops = diff(observed, desired, last_applied, opts)
    {:ok, apply_ops(cg, ops, observed, desired, last_applied)}
  end

  @doc """
  Reads the current raw value of each interface file into a `%{file => string}`
  map. Files that can't be read (missing controller, absent cgroup) are simply
  absent — the diff treats an absent desired file as needing a write and lets
  the write surface the real error.
  """
  @spec observe(Cgroup.cgroup(), [file()]) :: %{optional(file()) => binary()}
  def observe(cg, files) when is_binary(cg) and is_list(files) do
    for file <- files, {:ok, value} <- [Cgroup.read(cg, file)], into: %{}, do: {file, value}
  end

  @doc """
  Computes the ops that would converge `observed` to `desired`, given
  `last_applied`. Pure — no I/O.

  Produces `{:set, file, value}` for a desired file whose observed value differs
  (or is absent), and either `{:revert, file, original}` or `{:release, file}`
  for a file that has left the desired set. Order is irrelevant for cgroup
  limits; ops are emitted sets-then-releases for a stable, readable result.
  """
  @spec diff(%{optional(file()) => binary()}, desired(), last_applied(), opts()) :: [op()]
  def diff(observed, desired, last_applied \\ %{}, opts \\ [])
      when is_map(observed) and is_map(desired) and is_map(last_applied) and is_list(opts) do
    revert? = Keyword.get(opts, :revert_on_release, false)

    sets =
      for {file, value} <- desired, not converged?(observed, file, value) do
        {:set, file, value}
      end

    releases =
      for {file, own} <- last_applied, not Map.has_key?(desired, file) do
        case {revert?, own[:original]} do
          {true, original} when not is_nil(original) -> {:revert, file, original}
          _ -> {:release, file}
        end
      end

    sets ++ releases
  end

  # --- apply ----------------------------------------------------------------

  defp apply_ops(cg, ops, observed, desired, last_applied) do
    results = Enum.map(ops, fn op -> {op, run_op(cg, op)} end)

    applied = for {op, :ok} <- results, do: op
    failed = for {op, {:error, %Cgroup.Error{} = err}} <- results, do: {op, err}

    %Report{
      converged?: failed == [],
      applied: applied,
      failed: failed,
      pending: [],
      last_applied: next_last_applied(results, observed, desired, last_applied)
    }
  end

  defp run_op(cg, {:set, file, value}), do: Cgroup.write(cg, file, render(value))
  defp run_op(cg, {:revert, file, original}), do: Cgroup.write(cg, file, original)
  defp run_op(_cg, {:release, _file}), do: :ok

  # The updated ownership map after a pass. Ownership is claimed for every
  # desired file we successfully control (including no-op files that were
  # already converged), capturing the pre-management original once. Files whose
  # :set failed keep any prior ownership (so the original survives a transient
  # failure) but are not newly claimed. Released files are dropped, unless a
  # revert *failed* — then they are kept so the next pass retries the revert.
  defp next_last_applied(results, observed, desired, last_applied) do
    failed_sets = MapSet.new(for {{:set, f, _}, {:error, _}} <- results, do: f)

    owned =
      for {file, value} <- desired, not MapSet.member?(failed_sets, file), into: %{} do
        {file, %{applied: value, original: original_for(file, last_applied, observed)}}
      end

    preserved =
      for {file, _value} <- desired,
          MapSet.member?(failed_sets, file),
          Map.has_key?(last_applied, file),
          into: %{},
          do: {file, last_applied[file]}

    kept_reverts =
      for {{:revert, file, _}, {:error, _}} <- results,
          Map.has_key?(last_applied, file),
          into: %{},
          do: {file, last_applied[file]}

    owned |> Map.merge(preserved) |> Map.merge(kept_reverts)
  end

  # The original to record for a file: a previously-captured original wins
  # (capture once), else the raw value observed before we first touched it.
  defp original_for(file, last_applied, observed) do
    case last_applied do
      %{^file => %{original: original}} -> original
      _ -> Map.get(observed, file)
    end
  end

  # --- value comparison -----------------------------------------------------

  # True iff the kernel's current (observed) raw value already matches desired.
  # An absent observed value never counts as converged.
  defp converged?(observed, file, desired_value) do
    case Map.fetch(observed, file) do
      {:ok, raw} -> same_value?(raw, desired_value)
      :error -> false
    end
  end

  # `:max` clears a limit. Single-value knobs (memory.max, pids.max) read back
  # the literal "max"; cpu.max reads back "max <period>" — two tokens — so a
  # leading "max" token means converged either way.
  defp same_value?(raw, :max), do: match?(["max" | _], tokens(raw))

  defp same_value?(raw, value) when is_integer(value),
    do: tokens(raw) == [Integer.to_string(value)]

  # cpu.max's {quota, period} reads back as "quota period".
  defp same_value?(raw, {quota, period}),
    do: tokens(raw) == [Integer.to_string(quota), Integer.to_string(period)]

  defp same_value?(raw, value) when is_binary(value), do: raw == value

  # Render a desired value to the text the kernel's interface file expects.
  defp render(:max), do: "max"
  defp render(value) when is_integer(value), do: Integer.to_string(value)
  defp render({quota, period}), do: "#{quota} #{period}"
  defp render(value) when is_binary(value), do: value

  defp tokens(raw), do: String.split(raw, ~r/\s+/, trim: true)

  # Files touched by a pass: desired files plus still-owned files (to detect and
  # release those that have left the desired set).
  defp relevant_keys(desired, last_applied) do
    (Map.keys(desired) ++ Map.keys(last_applied)) |> Enum.uniq()
  end
end
