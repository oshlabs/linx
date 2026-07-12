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
  alias Linx.Reconcile.FlatKV

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
    observed = observe(FlatKV.relevant_keys(desired, last_applied), opts)
    ops = diff(observed, desired, last_applied, opts)
    write_opts = Keyword.take(opts, [:in])

    report =
      FlatKV.apply(
        ops,
        observed,
        desired,
        last_applied,
        &run_op(&1, write_opts),
        Report,
        Sysctl.Error
      )

    {:ok, report}
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
    FlatKV.diff(
      observed,
      desired,
      last_applied,
      Keyword.get(opts, :revert_on_release, false),
      &same_value?/2
    )
  end

  defp run_op({:set, key, value}, write_opts), do: Sysctl.write(key, value, write_opts)
  defp run_op({:revert, key, value}, write_opts), do: Sysctl.write(key, value, write_opts)
  defp run_op({:release, _key}, _write_opts), do: :ok

  # Integers and integer lists compare token-wise (tuple-shaped knobs read back
  # tab- or space-separated, e.g. "4\t4\t1\t7"); binaries compare exactly,
  # since a free-form string knob may legitimately contain runs of whitespace.
  defp same_value?(raw, desired) when is_integer(desired), do: raw == Integer.to_string(desired)

  defp same_value?(raw, desired) when is_list(desired) do
    tokens(raw) == Enum.map(desired, &Integer.to_string/1)
  end

  # `raw` comes back trimmed from read/2, so trim the desired side too —
  # otherwise a desired binary with a trailing newline can never converge
  # and is rewritten (and reported applied) every pass, forever.
  defp same_value?(raw, desired) when is_binary(desired),
    do: raw == String.trim_trailing(desired)

  defp tokens(raw), do: String.split(raw, ~r/\s+/, trim: true)
end
