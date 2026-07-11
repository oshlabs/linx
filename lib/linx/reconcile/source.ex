defmodule Linx.Reconcile.Source do
  @moduledoc """
  The plug-in contract that lets the generic `Linx.Reconcile` loop drive any
  reconcilable subsystem — deliberately minimal.

  Each reconcilable subsystem keeps its own rich, type-bearing surface
  (`Linx.Sysctl.Reconcile`, `Linx.Netlink.Rtnl.Reconcile`, …) for consumers
  that want direct control. This behaviour is the *narrow* seam the loop drives,
  implemented by a small adapter that delegates to that surface — so the loop
  stays subsystem-agnostic and the per-subsystem APIs stay free of a
  lowest-common-denominator façade.

  Two layers, then:

    * the per-subsystem `reconcile/3,4` a consumer calls directly when it wants
      control, and
    * this uniform contract the `Linx.Reconcile` loop drives.

  ## The `scope`

  A `scope` names the namespace the source acts in, in whatever shape that
  subsystem already accepts. It is an opaque value to the loop, threaded
  verbatim into every callback:

    * sysctl — the `:in` target (`:self`, `{:pid, n}`, `{:path, p}`);
    * cgroup — the cgroup directory path (the handle every `Linx.Cgroup`
      verb takes);
    * rtnl — a `t:Linx.Netlink.Socket.netns/0` (`:host`, `{:pid, n}`,
      `{:path, p}`), the source opening a short-lived socket per pass.

  ## The report contract

  `reconcile/4` returns `{:ok, report}` on a completed pass (even a partial one
  — per-op failures live *inside* the report). The loop relies on two fields
  being present on that report, by convention shared across every subsystem's
  report struct:

    * `:converged?` — `boolean()`, whether the pass left nothing undone;
    * `:last_applied` — the updated ownership state to thread into the next
      pass.

  `Linx.Sysctl.Reconcile.Report`, `Linx.Cgroup.Reconcile.Report`, and
  `Linx.Netlink.Rtnl.Reconcile.Report` all carry these (alongside
  `:applied`/`:failed`/`:pending`). `{:error, reason}` is reserved for a pass
  that could not run at all (could not observe the kernel, an invalid desired
  state) — the loop keeps the previous `last_applied` and retries on the next
  tick.

  ## Why no netfilter adapter (yet)

  `Linx.Netfilter` has both halves — `push(mode: :reconcile)` with
  generation-CAS and a Monitor for `subscribe` — but its ownership story
  differs from the flat-KV sources: convergence is judged against a pulled
  ruleset snapshot under a generation id, not against a `last_applied` map,
  and a CAS loss means "re-pull and recompute", not "retry the same ops".
  Squeezing that into this report contract would bend both; drive
  `Linx.Netfilter.push/3` + `Linx.Netfilter.subscribe/1` directly (a
  ~15-line loop) until a netfilter-shaped adapter design earns its place.

  ## Litmus test

  This contract is also the go/no-go test for whether the opt-in loop is worth
  shipping: if subsystems implement these callbacks by clean delegation, the
  loop is trivially worth it; if atomicity or ownership force contortions, we
  stop at the single-shot `reconcile` + Monitor primitives and let consumers
  wrap them directly. An out-of-tree PoC and the sysctl/rtnl adapters cleared it.
  """

  @typedoc "Opaque namespace handle, in the shape the subsystem already accepts."
  @type scope :: term()

  @typedoc "The desired state, in the subsystem's own desired-state shape."
  @type desired :: term()

  @typedoc "Reconciler-held ownership, threaded between passes. `%{}` is empty."
  @type last_applied :: term()

  @typedoc "Observed kernel state, in the subsystem's own observed shape."
  @type observed :: term()

  @typedoc """
  A reconcile report. Must expose at least `:converged?` (boolean) and
  `:last_applied` (the next ownership state) — see the moduledoc.
  """
  @type report :: %{
          required(:converged?) => boolean(),
          required(:last_applied) => last_applied(),
          optional(atom()) => term()
        }

  @typedoc "Subsystem-specific options, forwarded verbatim to the per-pass verb."
  @type opts :: keyword()

  @doc """
  Runs one reconcile pass in `scope` against `desired`, given the prior
  `last_applied`. Returns `{:ok, report}` on a completed (possibly partial)
  pass, or `{:error, reason}` if the pass could not run at all.
  """
  @callback reconcile(scope(), desired(), last_applied(), opts()) ::
              {:ok, report()} | {:error, term()}

  @doc """
  Starts a Monitor delivering change hints to `owner`, for the loop's low-latency
  wakeups. Returns `{:ok, monitor_pid}`, `:unsupported` (the loop runs
  timer-only), or `{:error, reason}`.

  The loop treats every message it then receives as a level-triggered "look now"
  hint — it never acts on an event payload — so the monitor's exact message
  shape is its own concern.
  """
  @callback subscribe(scope(), owner :: pid()) ::
              {:ok, pid()} | {:error, term()} | :unsupported

  @doc """
  Observes current kernel state in `scope`. Optional — the loop does not call
  it (it drives `reconcile/4`, which observes internally); it rounds out the
  contract for consumers and diagnostics.
  """
  @callback observe(scope(), opts()) :: {:ok, observed()} | {:error, term()}

  @optional_callbacks observe: 2
end
