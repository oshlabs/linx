defmodule Linx.Reconcile do
  @moduledoc """
  An opt-in, level-triggered reconcile loop over a single subsystem.

  This is the long-lived control loop that turns Linx's single-shot
  `reconcile` mechanism into continuous convergence: it re-observes and
  re-diffs on a timer (the *correctness* mechanism — manual drift, crashes, and
  reboots are corrected on the next pass), and reacts within milliseconds to a
  subsystem Monitor when one is available (a *latency* layer over the timer).
  Events are hints; resync is truth.

  It is deliberately **thin and genuinely opt-in** — a primitives library that
  refuses to become a runtime offers this as a separable convenience, never a
  default:

    * **Zero footprint if absent.** Nothing here runs unless you start it. There
      is no `Application` boot side effect and no auto-supervised process; the
      `reconcile` and `Monitor` primitives work fully standalone.
    * **Your tree, not ours.** You add `{Linx.Reconcile, opts}` to *your* own
      supervision tree. Linx ships no supervisor that bundles it in.
    * **No hidden global state.** It holds only the desired state and
      `last_applied` you give it; there is no singleton or registry.
    * **Single-subsystem by construction.** It drives one
      `Linx.Reconcile.Source` in one namespace. The cross-subsystem composite
      ("this container, with this network, in this cgroup") is the consumer's —
      it is not, and cannot be, expressed here.
    * **Separable.** It is implemented entirely on the public `Source` contract
      (single-shot `reconcile` + an optional Monitor `subscribe`). Deleting it
      would cost a consumer only a ~15-line timer loop, nothing load-bearing.

  It is especially handy for the simplest consumer — a plain host-network or
  sysctl config app with no supervision tree of its own to roll a loop from —
  for which it may be the *recommended* easy path, while still never automatic.

  ## Usage

  Add it to your own supervision tree, naming the `Linx.Reconcile.Source`
  adapter for the subsystem, the `scope` (the namespace, in that subsystem's
  shape), and the desired state:

      children = [
        {Linx.Reconcile,
         source: Linx.Sysctl.Reconcile.Source,
         scope: :self,
         desired: %{"net.ipv4.ip_forward" => 1},
         name: :host_sysctls}
      ]
      Supervisor.start_link(children, strategy: :one_for_one)

  or for rtnl, monitoring a network namespace by pid:

      {Linx.Reconcile,
       source: Linx.Netlink.Rtnl.Reconcile.Source,
       scope: {:pid, container_pid},
       desired: %{addresses: [{"eth0", "10.0.0.2", 24}], routes: [{:default, "10.0.0.1"}]},
       interval: :timer.seconds(30)}

  ## Options

    * `:source` (required) — a module implementing `Linx.Reconcile.Source`.
    * `:scope` (required) — the namespace handle, in the source's shape.
    * `:desired` (required) — the desired state, in the source's shape.
    * `:reconcile_opts` — keyword forwarded verbatim to the source's
      `reconcile/4` (e.g. rtnl's `:protocol`, sysctl's `:revert_on_release`).
    * `:last_applied` — initial ownership state (default `%{}`).
    * `:interval` — timer-resync period in ms, or `:infinity` to disable the
      timer and rely solely on the Monitor. Default `#{5_000}`.
    * `:monitor` — whether to subscribe to the source's Monitor for low-latency
      wakeups (default `true`; a source that returns `:unsupported` falls back
      to timer-only transparently).
    * `:debounce` — ms to coalesce a burst of Monitor hints (or a `put_desired`)
      into one pass. Default `#{100}`.
    * `:owner` — a pid to notify after each pass with
      `{:linx_reconcile, :report, report}` / `{:linx_reconcile, :error, reason}`
      (default: no notifications).
    * `:name` — a `GenServer` name to register under.

  ## Failure model

  When `monitor: true`, the loop **links** to the Monitor it starts: if the
  Monitor dies the loop dies, and a supervisor restart resubscribes and does a
  full resync from scratch (which is correct — resync is truth). A reconcile
  pass that returns `{:error, _}` does not crash the loop; it keeps the previous
  `last_applied` and retries on the next tick.
  """

  use GenServer
  require Logger

  alias Linx.Reconcile.Source

  @default_interval 5_000
  @default_debounce 100

  @type option ::
          {:source, module()}
          | {:scope, Source.scope()}
          | {:desired, Source.desired()}
          | {:reconcile_opts, keyword()}
          | {:last_applied, Source.last_applied()}
          | {:interval, pos_integer() | :infinity}
          | {:monitor, boolean()}
          | {:debounce, non_neg_integer()}
          | {:owner, pid()}
          | {:name, GenServer.name()}

  # === Public API ===========================================================

  @doc "Starts the loop. See the moduledoc for options."
  @spec start_link([option()]) :: GenServer.on_start()
  def start_link(opts) when is_list(opts) do
    {name, opts} = Keyword.pop(opts, :name)
    GenServer.start_link(__MODULE__, opts, if(name, do: [name: name], else: []))
  end

  @doc false
  def child_spec(opts) do
    id = Keyword.get(opts, :id, Keyword.get(opts, :name, __MODULE__))
    %{id: id, start: {__MODULE__, :start_link, [Keyword.delete(opts, :id)]}}
  end

  @doc """
  Forces one reconcile pass now, synchronously, and returns its result
  (`{:ok, report}` or `{:error, reason}`). Useful in tests and for a consumer
  that wants to converge on demand without waiting for the next tick.
  """
  @spec reconcile(GenServer.server(), timeout()) :: {:ok, Source.report()} | {:error, term()}
  def reconcile(server, timeout \\ 5_000), do: GenServer.call(server, :reconcile, timeout)

  @doc """
  Replaces the desired state and schedules a (debounced) reconcile to converge
  on it. Returns `:ok` immediately.
  """
  @spec put_desired(GenServer.server(), Source.desired()) :: :ok
  def put_desired(server, desired), do: GenServer.cast(server, {:put_desired, desired})

  @doc "Returns the most recent reconcile report, or `nil` if no pass has completed yet."
  @spec last_report(GenServer.server()) :: Source.report() | nil
  def last_report(server), do: GenServer.call(server, :last_report)

  @doc "Stops the loop (and, via the link, its Monitor)."
  @spec stop(GenServer.server()) :: :ok
  def stop(server), do: GenServer.stop(server)

  # === GenServer ============================================================

  @impl true
  def init(opts) do
    state = %{
      source: Keyword.fetch!(opts, :source),
      scope: Keyword.fetch!(opts, :scope),
      desired: Keyword.fetch!(opts, :desired),
      reconcile_opts: Keyword.get(opts, :reconcile_opts, []),
      last_applied: Keyword.get(opts, :last_applied, %{}),
      interval: Keyword.get(opts, :interval, @default_interval),
      debounce: Keyword.get(opts, :debounce, @default_debounce),
      monitor?: Keyword.get(opts, :monitor, true),
      owner: Keyword.get(opts, :owner),
      monitor: nil,
      report: nil,
      wakeup_timer: nil
    }

    {:ok, state, {:continue, :start}}
  end

  @impl true
  def handle_continue(:start, state) do
    state = maybe_subscribe(state)
    # An immediate first pass, then the periodic timer takes over.
    send(self(), {:linx_reconcile, :tick})
    {:noreply, state}
  end

  @impl true
  def handle_call(:reconcile, _from, state) do
    {result, state} = run_pass(state)
    {:reply, result, state}
  end

  def handle_call(:last_report, _from, state), do: {:reply, state.report, state}

  @impl true
  def handle_cast({:put_desired, desired}, state) do
    {:noreply, schedule_wakeup(%{state | desired: desired})}
  end

  @impl true
  def handle_info({:linx_reconcile, :tick}, state) do
    {_result, state} = run_pass(state)
    {:noreply, schedule_tick(state)}
  end

  def handle_info({:linx_reconcile, :wakeup}, state) do
    {_result, state} = run_pass(%{state | wakeup_timer: nil})
    {:noreply, state}
  end

  # A monitor hint (any shape — an event or a :resync_needed): level-triggered,
  # so it just means "look now". We never act on the payload; we re-reconcile
  # full state, debounced so a burst collapses into one pass.
  def handle_info(_msg, %{monitor: monitor} = state) when is_pid(monitor) do
    {:noreply, schedule_wakeup(state)}
  end

  # No monitor: ignore stray messages.
  def handle_info(_msg, state), do: {:noreply, state}

  # === Internals ============================================================

  defp maybe_subscribe(%{monitor?: false} = state), do: state

  defp maybe_subscribe(%{source: source, scope: scope} = state) do
    case source.subscribe(scope, self()) do
      {:ok, monitor} when is_pid(monitor) ->
        %{state | monitor: monitor}

      :unsupported ->
        state

      {:error, reason} ->
        Logger.debug("Linx.Reconcile: monitor unavailable (#{inspect(reason)}); timer-only")
        state
    end
  end

  defp run_pass(state) do
    case state.source.reconcile(
           state.scope,
           state.desired,
           state.last_applied,
           state.reconcile_opts
         ) do
      {:ok, report} = ok ->
        notify(state, {:linx_reconcile, :report, report})
        {ok, %{state | report: report, last_applied: report.last_applied}}

      {:error, reason} = error ->
        notify(state, {:linx_reconcile, :error, reason})
        Logger.warning("Linx.Reconcile pass failed: #{inspect(reason)}")
        # Keep the prior last_applied; the next tick/wakeup retries.
        {error, state}
    end
  end

  defp schedule_tick(%{interval: :infinity} = state), do: state

  defp schedule_tick(%{interval: ms} = state) do
    Process.send_after(self(), {:linx_reconcile, :tick}, ms)
    state
  end

  # Coalesce a burst into one pass: only the first hint in a debounce window
  # arms the timer.
  defp schedule_wakeup(%{wakeup_timer: nil, debounce: ms} = state) do
    ref = Process.send_after(self(), {:linx_reconcile, :wakeup}, ms)
    %{state | wakeup_timer: ref}
  end

  defp schedule_wakeup(state), do: state

  defp notify(%{owner: nil}, _msg), do: :ok
  defp notify(%{owner: owner}, msg), do: send(owner, msg)
end
