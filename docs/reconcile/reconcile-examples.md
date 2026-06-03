# Declarative reconciliation examples

A tour of Linx's declarative-configuration surface: you describe the kernel
state you *want*, and a reconciler diffs it against what the kernel actually has
and converges the two — idempotent and self-healing, so manual drift, crashes,
and reboots are corrected on the next pass.

This is the **overview**. Each subsystem keeps its own hands-on examples in its
`EXAMPLES.md`; the per-subsystem detail is not repeated here. This page covers
the shared model, the generic opt-in loop (`Linx.Reconcile`), the plug-in
contract (`Linx.Reconcile.Source`), and how the pieces fit together. The design
and rationale live in `docs/reconcile/PLAN.md`.

## The shared model

Reconciliation is **mechanism in Linx, policy in the consumer**. Linx gives you
the verbs; the desired-state source of truth, the cadence, and the supervision
are yours.

Every reconcilable subsystem rhymes on the same four verbs (the template is
`Linx.Netfilter`, which had them first — see `docs/netfilter/netfilter-examples.md`):

  * **observe** — read current kernel state into plain values;
  * **diff** — compute the minimal set of create/update/delete ops;
  * **reconcile** (`push`) — apply that diff in one caller-driven pass;
  * **subscribe** — a Monitor that says "look now" when something changes.

Two principles run through all of it:

  * **Events are hints; resync is truth.** A Monitor is a *latency* layer: any
    event (or an `ENOBUFS` `:resync_needed`) means "re-read and re-diff full
    state", never "apply this delta". Correctness rests on the periodic resync,
    not on catching every event.
  * **Delete only what you own.** Where the kernel tags ownership (routes carry
    `rtm_protocol`), the diff is **two-way** — observed-filtered-to-our-tag vs
    desired. Where it does not (addresses, sysctls, cgroup knobs), the diff is
    **three-way**: a reconciler-held `last_applied` set records what *we*
    installed, so foreign state that merely appeared is left untouched. You
    thread `last_applied` from each pass into the next.

### The reconcilable subsystems at a glance

| Subsystem | Single-shot module | `scope` | Ownership | Monitor |
|---|---|---|---|---|
| netfilter | `Linx.Netfilter` (`push(mode: :reconcile)`) | a table | socket-owned + genID CAS | yes |
| rtnl | `Linx.Netlink.Rtnl.Reconcile` | an open socket / netns | routes two-way, rest three-way | yes |
| sysctl | `Linx.Sysctl.Reconcile` | the `:in` target | three-way | no |
| cgroup limits | `Linx.Cgroup.Reconcile` | a cgroup path | three-way | no |

Anything not in this table (capabilities, seccomp, uid maps, mount, tty) is not
reconciled state — it is spec applied once at spawn, or a runtime channel. See
`docs/reconcile/PLAN.md` §5 for why.

## Single-shot reconcile, by hand

The smallest real loop needs nothing but the single-shot verb and a variable to
thread `last_applied` through. Here it is for sysctl:

```elixir
alias Linx.Sysctl.Reconcile

desired = %{"net.ipv4.ip_forward" => 1, "net.ipv4.conf.all.rp_filter" => 1}

# First pass: writes whatever the kernel doesn't already match.
{:ok, r} = Reconcile.reconcile(desired)
r.converged?       #=> true once the kernel matches
r.applied          #=> the ops that ran this pass
r.last_applied     #=> thread this into the next pass

# A second pass against the same desired state is a no-op.
{:ok, r2} = Reconcile.reconcile(desired, r.last_applied)
r2.applied         #=> []
```

Every pass returns a uniform **report** — `converged?`, `applied`, `failed`,
`pending`, `last_applied` — whichever subsystem produced it. The *strategy*
differs by subsystem and is visible in the report:

  * **independent ops (sysctl, cgroup) are best-effort** — every op is
    attempted, failures collect in `failed`, `pending` stays empty;
  * **ordered ops (rtnl) are fail-fast** — the pass stops at the first failure
    (`failed` holds it), and the ops it had not reached become `pending`.

Either way a partial apply is a normal transient state the next pass corrects;
there is no rollback.

The same shape, per subsystem (full examples on each page):

```elixir
# rtnl — authored by interface name; routes owned by rtm_protocol.
{:ok, sock} = Linx.Netlink.Rtnl.open()
{:ok, r} =
  Linx.Netlink.Rtnl.Reconcile.reconcile(sock, %{
    addresses: [{"eth0", "10.0.0.2", 24}],
    routes: [{:default, "10.0.0.1"}]
  })

# cgroup limits — a flat map of interface file => value.
{:ok, r} =
  Linx.Cgroup.Reconcile.reconcile("/sys/fs/cgroup/myorg/web-42", %{
    "memory.max" => 256 * 1024 * 1024,
    "pids.max" => 100,
    "cpu.max" => {50_000, 100_000}
  })
```

See `docs/sysctl/sysctl-examples.md`, `docs/netlink/netlink-examples.md`, and
`docs/cgroup/cgroup-examples.md` for the subsystem-specific detail (value shapes,
`revert_on_release`, route options, namespaces).

## Diffing without applying

The diff is pure and exposed on its own, for inspection or a custom apply
strategy. For rtnl:

```elixir
alias Linx.Netlink.Rtnl.Diff

# Two-way for routes (ownership is the rtm_protocol tag):
Diff.routes(desired_routes, observed_routes, _protocol = 76)
#=> [{:create, %Route{...}}, {:update, %Route{...}}, {:delete, %Route{...}}]

# Three-way for addresses (ownership is the last-applied key set):
Diff.addresses(desired_addrs, observed_addrs, owned_keys)
```

A `{:create, item}`/`{:update, item}` carries the *desired* struct; a
`{:delete, item}` carries the *observed* one (it holds the kernel's handle).

## Watching for change: the Monitor

`Linx.Netlink.Rtnl.Monitor` is the `ip monitor` equivalent — it forwards each
rtnetlink change to an owner as a wake-up hint:

```elixir
{:ok, mon} = Linx.Netlink.Rtnl.Monitor.subscribe()

# the owner receives, for any change in the namespace:
#   {:linx_rtnl, :event, %Linx.Netlink.Rtnl.Monitor.Event{...}}
#   {:linx_rtnl, :resync_needed}        (on ENOBUFS — the stream is lossy)

Linx.Netlink.Rtnl.Monitor.unsubscribe(mon)
```

You rarely wire this up by hand — the loop below does it for you. See
`docs/netlink/netlink-examples.md` for the standalone Monitor.

## `Linx.Reconcile` — the opt-in loop

Threading `last_applied` on a timer and re-syncing on a Monitor hint is a ~15-line
pattern you could write yourself. `Linx.Reconcile` is that loop, packaged — a
GenServer you add to **your own** supervision tree. It is deliberately thin and
genuinely opt-in: nothing runs unless you start it, there is no `Application`
boot side effect and no singleton, and it drives exactly **one** subsystem in
one namespace (the cross-subsystem composite stays in the consumer — see below).

It is especially useful for the simplest consumer — a plain host-config app with
no supervision tree of its own to roll a loop from.

```elixir
children = [
  {Linx.Reconcile,
   source: Linx.Sysctl.Reconcile.Source,
   scope: :self,
   desired: %{"net.ipv4.ip_forward" => 1},
   name: :host_sysctls}
]
Supervisor.start_link(children, strategy: :one_for_one)
```

Or for rtnl, continuously converging a container's namespace by pid, woken by
the Monitor and re-syncing every 30 s as the safety net:

```elixir
{Linx.Reconcile,
 source: Linx.Netlink.Rtnl.Reconcile.Source,
 scope: {:pid, container_pid},
 desired: %{
   addresses: [{"eth0", "10.0.0.2", 24}],
   routes: [{:default, "10.0.0.1"}]
 },
 interval: :timer.seconds(30)}
```

### Options

  * `:source` (required) — a module implementing `Linx.Reconcile.Source`.
  * `:scope` (required) — the namespace handle, in that source's shape
    (sysctl: the `:in` target; rtnl: a netns; cgroup: a cgroup path).
  * `:desired` (required) — the desired state, in that source's shape.
  * `:reconcile_opts` — keyword forwarded verbatim to the source (e.g. rtnl's
    `:protocol`, sysctl's `:revert_on_release`).
  * `:last_applied` — initial ownership state (default `%{}`).
  * `:interval` — timer-resync period in ms, or `:infinity` to rely solely on
    the Monitor (default `5_000`).
  * `:monitor` — subscribe to the source's Monitor for low-latency wakeups
    (default `true`; a source that returns `:unsupported` falls back to
    timer-only transparently).
  * `:debounce` — ms to coalesce a burst of hints (or a `put_desired`) into one
    pass (default `100`).
  * `:owner` — a pid to notify after each pass.
  * `:name` — a `GenServer` name to register under.

### Driving it at runtime

```elixir
{:ok, pid} =
  Linx.Reconcile.start_link(
    source: Linx.Cgroup.Reconcile.Source,
    scope: "/sys/fs/cgroup/myorg/web-42",
    desired: %{"pids.max" => 100}
  )

# Force a pass now and inspect its report (handy in tests).
{:ok, report} = Linx.Reconcile.reconcile(pid)

# Swap the desired state; a debounced pass converges on it.
:ok = Linx.Reconcile.put_desired(pid, %{"pids.max" => 200})

# The most recent report (nil before the first pass completes).
Linx.Reconcile.last_report(pid)

Linx.Reconcile.stop(pid)
```

With an `:owner` set, each pass notifies it:

```elixir
{Linx.Reconcile,
 source: Linx.Sysctl.Reconcile.Source, scope: :self,
 desired: %{"net.ipv4.ip_forward" => 1}, owner: self()}

# the owner receives, after every pass:
#   {:linx_reconcile, :report, %{converged?: true, ...}}
#   {:linx_reconcile, :error, reason}     (a pass that could not run at all)
```

### Failure model

A reconcile pass that returns `{:error, _}` does **not** crash the loop — it
keeps the previous `last_applied` and retries on the next tick. When
`monitor: true`, the loop *links* to the Monitor it starts: if the Monitor dies,
the loop dies, and a supervisor restart resubscribes and does a full resync from
scratch (which is correct — resync is truth). So put it under a supervisor.

## `Linx.Reconcile.Source` — the plug-in contract

The loop is subsystem-agnostic because it drives a deliberately minimal
behaviour, and each subsystem ships a thin adapter that delegates to its own
rich single-shot surface:

| Adapter | `scope` | `subscribe/2` |
|---|---|---|
| `Linx.Sysctl.Reconcile.Source` | the `:in` target | `:unsupported` (timer-only) |
| `Linx.Netlink.Rtnl.Reconcile.Source` | a netns | starts an rtnl `Monitor` |
| `Linx.Cgroup.Reconcile.Source` | a cgroup path | `:unsupported` (timer-only) |

The contract is three callbacks (`observe/2` is optional — the loop does not
call it):

```elixir
@callback reconcile(scope, desired, last_applied, opts) ::
            {:ok, report} | {:error, term}
@callback subscribe(scope, owner :: pid) ::
            {:ok, pid} | {:error, term} | :unsupported
@callback observe(scope, opts) :: {:ok, observed} | {:error, term}
```

The loop relies only on the report exposing `:converged?` and `:last_applied`
(every subsystem's report does). To drive a custom subsystem, implement the
behaviour by delegating to your own `reconcile`:

```elixir
defmodule MyApp.Hosts.Source do
  @behaviour Linx.Reconcile.Source

  @impl true
  def reconcile(scope, desired, last_applied, opts) do
    # delegate to your own single-shot reconcile, returning a report map
    # with at least :converged? and :last_applied
    MyApp.Hosts.reconcile(scope, desired, last_applied, opts)
  end

  @impl true
  def subscribe(_scope, _owner), do: :unsupported   # timer-only is fine
end
```

Then `{Linx.Reconcile, source: MyApp.Hosts.Source, scope: ..., desired: ...}`.

## The cross-subsystem composite stays in the consumer

`Linx.Reconcile` drives one subsystem. An object that spans subsystems — "this
container should exist, in its own namespace, with this address and these
limits, and be restarted if it crashes" — cannot live in a primitives library
without Linx becoming the runtime it refuses to be. That composite is the
consumer's, built by composing `Linx.Process`, the single-shot reconciles, and
OTP supervision directly.

`tank/` is a worked example of exactly that: a nested app that consumes only
Linx's public API to build a supervised container whose network is reconciled
from the host at the spawn checkpoint. See `tank/README.md` and
`tank/lib/tank/container.ex`.

## See also

  * `docs/reconcile/PLAN.md` — the design, the mechanism/policy seam, ownership
    and lifetime, the subsystem classification, and the decisions behind all of
    the above.
  * `docs/sysctl/sysctl-examples.md` — "Declarative reconciliation" and "A long-lived
    loop (opt-in)".
  * `docs/netlink/netlink-examples.md` — "Reconciliation", "Single-shot reconcile", "the
    Monitor", and "A long-lived loop (opt-in)".
  * `docs/cgroup/cgroup-examples.md` — "Reconciling limits declaratively".
  * `docs/process/process-examples.md` — "Supervising a workload" (how a crashed
    workload is restarted via OTP, not a reconcile loop).
  * `docs/netfilter/netfilter-examples.md` — the reference
    triad every other subsystem rhymes with.
