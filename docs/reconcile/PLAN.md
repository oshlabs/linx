# Declarative configuration via reconciliation — design & plan

This is the design and plan for making Linx **declarative**: you describe the
desired Linux configuration state, and a reconciler continuously diffs it
against what the kernel actually has and converges the two — the closed-loop
control model Kubernetes uses for cluster state and VintageNet uses for network
state. Idempotent and self-healing: manual drift, crashes, and reboots are
corrected on the next pass.

It captures decisions already made and questions still open. It is forward
pointed: nothing here is implemented yet beyond the `Linx.Netfilter` reference
(see §2). Companion docs: the "Declarative reconcile" section of
`docs/ROADMAP.md` and `docs/netfilter/DESIGN.md`.

## 1. Consumers — who this is for

Linx is primitives, not a runtime, and the reconcile design serves a spectrum of
consumers, not one application:

- **A container orchestrator** (the first real consumer, working name *Tank* —
  a Nerves application intended to replace VintageNet). It holds a per-container
  *spec* spanning process, namespaces, cgroup, addresses, routes, and rules, and
  binds their lifetimes together. This is the most demanding consumer; it
  exercises the cross-subsystem *composite* (§4) that only a consumer can hold.
- **A plain host-network-configuration app.** The simplest consumer: one
  namespace (the host), a handful of links, addresses, routes, and sysctls,
  reconciled on a timer or by the opt-in loop. No containers, no composite, no
  process lifecycle. This case is why the opt-in `Linx.Reconcile` loop (§7) earns
  its place — such an app has no supervision tree of its own to roll a loop from.
- **Other non-container apps** that want any subset of declarative kernel state.

The design target is that the *simplest* consumer is trivial and the *most
demanding* one is possible, on the same primitives.

The single biggest design move, learned from VintageNet: VintageNet shells out
to `ip`/`udhcpc`/`wpa_supplicant` and **explicitly refuses to diff** — it tears
an interface fully down and rebuilds it, accepting a connectivity hiccup, to
avoid state-machine complexity. Because Linx speaks netlink directly, it can do
what VintageNet declined: a real level-triggered observe→diff→act reconcile that
avoids the hiccup. That refusal is the gap this work closes.

## 2. The reference implementation: `Linx.Netfilter`

The netfilter subsystem already exposes the full reconciler triad, and it is the
template every other subsystem rhymes with:

- **`pull`** — observe current kernel state into a plain `%Ruleset{}` value.
- **`diff`** — compute the minimal `%Patch{}` between two values.
- **`push(mode: :reconcile)`** — apply that patch as one atomic batch, threaded
  with `NFTA_BATCH_GENID` for optimistic-concurrency CAS, so Linx coexists with
  `nft`/firewalld/any other writer in the same namespace; on a generation
  mismatch the kernel rejects the batch (`:erestart`) and Linx re-pulls,
  re-diffs, and retries with backoff.
- **`subscribe`** — a Monitor GenServer with snapshot-then-tail (a `get_gen`
  handshake drops events captured during the dump) and `ENOBUFS →
  :resync_needed`. Events are wake-up hints; resync is truth.

Plus the two things naive implementations get wrong:

- **Stable per-rule `:tag` identity** so reordering produces an update, not a
  spurious delete+create. Reconcile mode rejects untagged multi-rule chains up
  front.
- **Socket-lifetime ownership** (`NFT_TABLE_F_OWNER`): the kernel destroys the
  table when the owning BEAM socket closes. Crash *is* cleanup; leaked rules
  become unrepresentable. rtnl cannot replicate this (there is no socket-owned
  route), which is exactly why rtnl needs ownership *tagging* instead (§4, §5).

## 3. The seam: mechanism in Linx, policy in the consumer

The clean cut, and the line the whole project is built on ("primitives, not a
runtime"):

| Mechanism → **Linx** | Policy → **the consumer** |
|---|---|
| `pull` / `diff` / `push(mode: :reconcile)` | the desired-state source of truth |
| per-resource diff, `RTPROT` ownership tagging | persistence of desired state and last-applied |
| the Monitor (`ENOBUFS → :resync_needed`) | the long-lived loop's cadence, debounce, backoff |
| single-shot reconcile *within one subsystem* | whether to reap foreign (non-owned) entries |
| `NLM_F_REPLACE`, idempotent ops | orchestration of `udhcpc`/`wpa_supplicant` daemons |

The test that keeps this honest: *does it hold long-lived state or own a process
lifecycle?* If yes, it is a runtime, and it belongs in the consumer — or, at
most, in a clearly opt-in and separable `Linx.Reconcile` layer (§7), never the
default.

Cross-subsystem reconciliation ("this container should exist, with this address,
in this cgroup, behind these rules") spans Process + Cgroup + Rtnl + Netfilter
and cannot live in a primitives library without Linx becoming the runtime it
refuses to be — only the consumer holds the composite object that spans
subsystems. Every item in the Linx column is unambiguously mechanism and belongs
in Linx regardless of how the loop-home question resolves, so that work is not
blocked on it.

Lesson from systemd-networkd: its `ManageForeignRoutes=yes` default reaps routes
it does not own and routinely deletes VPN/CNI routes, so operators disable it.
Reaping foreign entries is therefore a **consumer policy switch**, off by
default — never a library default.

## 4. Ownership & lifetime

This is load-bearing for the whole design: **lifetime = ownership.** It
generalizes the netfilter socket-ownership property to the supervision level and
makes a whole class of "the loop fights the lifecycle" bugs *unrepresentable*
rather than something to detect and handle.

**Scope every reconciler to one network namespace.** `Rtnl.open/1` is per
namespace, so one reconciler owns one namespace's state and the ordered pass over
it (§8 sketch). The namespace boundary is the kernel's own scoping boundary;
disjoint reconcilers physically cannot fight over a resource.

**A resource's owner is whatever should share its lifetime:**

- **Host-owned, long-lived infrastructure** — physical NICs, bridges, the host's
  own addresses/routes, a macvlan/ipvlan *parent*. Declared by a host-scoped
  reconciler whose lifetime is the node/application lifetime. Stable across
  container churn.
- **Container-owned, ephemeral plumbing** — a container's ipvlan slave, its veth
  pair, the addresses/routes inside its namespace. Declared by a per-container
  composite whose reconciler lives in the container's supervision subtree, so it
  *stops when the container stops*. Its desired state dies with the container;
  there is no orphaned loop left trying to recreate an interface into a namespace
  that no longer exists.

The kernel does most teardown for free: when a namespace is destroyed (its last
pinning reference goes away), its virtual devices are deleted and veth peers
cascade-delete. So the rule that falls out: **the host reconciler's desired state
must never contain any resource whose existence is conditional on a container**
(no veth host-ends, no container ipvlans) — those belong to the container
composite, which has the right lifetime. Cross-scope dependencies read in one
direction only: the container composite *reads* a host-owned `eth0`'s index to
build an ipvlan; the host never reaches into the container.

**The one real knob: what pins the namespace.**

- *Inner process pins it* (simplest): network dies and is reborn on each restart;
  brief reconnect blip, no leaks.
- *A longer-lived holder pins it* (a bind-mount, or a small "sandbox"/pause
  holder — the Kubernetes pod-sandbox pattern): addresses/routes survive
  individual container restarts; the restarted process re-enters the same
  namespace with config intact. The reconciler binds to the holder's lifetime.

Both fit "lifetime = ownership"; they differ only in which owner pins the
namespace, and that choice is what decides whether network survives a restart.
This is a per-workload decision for the consumer.

## 5. Subsystem classification

Only the subsystems that are genuinely drift-prone, observable, scoped state get
a reconcile loop. The rest are declarative *spec the lifecycle applies* — which
keeps the reconcile machinery small and keeps Linx primitives. Four buckets:

| Subsystem | Kind | Reconcile? |
|---|---|---|
| **rtnl** (links/addrs/routes/rules/neigh) | declarative kernel state | yes — the main work |
| **Netfilter** | declarative kernel state | done (the template) |
| **sysctl** | declarative kernel state | yes — trivially |
| **cgroup** | *split*: limits = state; existence/membership = lifecycle | limits yes; rest is lifecycle |
| **capabilities** | process spawn attribute | no — spec field |
| **seccomp** | process spawn attribute | no — spec field |
| **user** (uid/gid maps) | process spawn attribute | no — spec field |
| **mount** | namespace lifecycle setup | no — lifecycle (defer any live reconcile) |
| **tty/PTY** | runtime I/O channel | no — not state |

**Bucket A — declarative kernel state (the triad applies).** rtnl, sysctl, and
cgroup *limits*. sysctl is the simplest possible reconciler — a flat `%{key =>
value}` with no ordering or identity subtlety, and `net.*` keys are per-namespace
so they share rtnl's scope. It is the cheapest place to build and prove the
generic reconcile discipline (observe → diff → idempotent-apply → last-applied
for ownership) before the harder rtnl resources. cgroup *limits* (`memory.max`,
`cpu.max`, weights) reconcile like sysctl-with-hierarchy.

**Bucket B — process spawn spec (set once at creation, re-applied verbatim on
restart, owned by the process lifecycle).** capabilities, seccomp, uid/gid maps.
There is nothing to observe-and-converge: seccomp filters can only be *added* and
never removed; uid/gid maps are *write-once*; cap sets are pinned at exec. They
are fields of the spec that the supervisor's `child_spec` carries and re-applies
on restart — the "reconciliation" for them is simply *the supervisor restarting
the process with the same spec*.

**Bucket C — namespace lifecycle setup (owned by the container, kernel
auto-torn-down).** mount setup (rootfs, binds, tmpfs), and the
namespace/cgroup-dir existence. This is §4 generalized to all namespaces: set up
at creation, destroyed with the owner, mostly cleaned up by the kernel. mount
*could* be live-reconciled (it is observable via `/proc/self/mountinfo`) but it
is high-risk (unmount-in-use → `EBUSY`, remount disrupts running processes) and
low-value — defer; treat as create-time setup in the composite.

**Bucket D — runtime I/O (not declarative).** tty/PTY is an I/O channel attached
for the process's life; winsize/signals are runtime controls, not desired state.
Outside the model entirely.

**The unifying insight.** A container *spec* is one declarative document with
three kinds of content: reconciled state (rtnl, sysctl, cgroup limits) converged
by per-scope loops; creation-time attributes (caps, seccomp, uid maps, mounts)
applied once at spawn and re-applied on restart; and runtime channels (tty)
attached for the process's life. All three are bound by the same ownership
principle (§4). We do not bolt a loop onto every subsystem.

## 6. The data model — one vocabulary, used three ways

**The kernel's model is not a tree.** It is a flat set of keyed records per
resource type, scoped by namespace, with reference-by-key between them (an
address carries an index → link; a route carries `oif`/`gateway`; routes live in
tables global to the namespace, not "under" an interface).

So:

- **Author as a tree** (for humans) — interfaces keyed by name; routes and rules
  at the top level because that is where the kernel keeps them (they only
  *reference* an interface by name). Nesting routes under an interface would lie
  about the kernel's structure and bite the moment a route has no interface or a
  gateway reachable via two links.
- **Reconcile as flat keyed sets** — the diff currency is the **netlink structs
  themselves** (`%Rtnl.Address{}`, `%Rtnl.Route{}`, …). Desired and observed are
  the *same type*, so diffing is plain set arithmetic — no translation layer.
  This is the netfilter `%Ruleset{}` pattern generalized.

**Persisted config ≠ verbatim structs.** Some struct fields are kernel-assigned
output, not authorable input: `index`/`ifindex`/`oif` (ephemeral across
reboots), live `flags`, kernel-inferred `scope`, SLAAC lifetimes. Test: *could
you write this field down before the kernel has ever seen the interface?* If no,
it is observed-only and must not be persisted.

Therefore:

- **Persist** the human, name-keyed tree (names, CIDR strings, table numbers, the
  owning proto). Stable across reboots. (Persistence itself is the consumer's
  concern — Linx keeps it optional, like VintageNet's pluggable persistence.)
- **Normalize** to the index-bearing structs at the edge of each reconcile pass
  (resolving names → indices from a fresh `Link.list`). Structs remain the diff
  vocabulary; they just are not what hits disk.
- **Never persist observed state** — it lives in the reconciler's process state
  and dies with the node.

### Diff keys and ownership

- **Link** — key by `name` (index is ephemeral; name is the stable handle).
- **Address** — key by `{interface, family, address, prefixlen}`. No protocol
  field exists on `ifaddrmsg`, so: filter observed to `RT_SCOPE_UNIVERSE` to drop
  `fe80::/64` link-locals; and use a **three-way merge** (last-applied vs
  current-desired vs observed) so you only delete addresses *you* previously
  installed. This is `kubectl apply`'s last-applied-configuration trick, for the
  same reason — to know what you own.
- **Route** — key by `{table, family, dst, dst_len, metric}`. Gateway is *not*
  part of the key (it is the mutable value), so a gateway change is an update via
  `NLM_F_REPLACE`, not delete+create. Ownership is by `RTPROT` (a dedicated
  protocol number; **two-way** diff: desired vs observed-filtered-by-our-proto).
  Connected routes are `proto kernel` and never enter our managed set.
- **Neighbour** — key by `{interface, dst}`.
- **Rule** — key by `{priority, family, selectors}`.

Asymmetry to embrace, not paper over: **routes get two-way** (proto is the
ownership marker), **addresses get three-way** (last-applied is the marker), and
sysctls likewise get three-way (no kernel ownership tag). That mirrors what the
kernel does and does not give you, and it stays visible in each subsystem's API
rather than being hidden behind a uniform façade (§7).

## 7. API surface & consistency

Across every reconcilable subsystem the surface should be **similar by
convention, not identical by force.** Tank — and every other consumer — programs
against one mental model; the genuine differences stay visible rather than hidden
behind a false-uniform type.

**The same across all (the discipline):**

- the four verbs — `pull(scope)` → a plain value, `diff(from, to)` → a patch,
  `push(scope, desired, mode: :reconcile)`, `subscribe(scope, owner)`;
- the option vocabulary — `mode: :reconcile`, `retries:`, `last_applied:`,
  `owner:`;
- the error contract — `{:error, %X.Error{}}` with transient-vs-permanent
  classification (`EAGAIN`/`ENOBUFS` → retry; `EPERM`/`EINVAL` → stop);
- the monitor discipline — `{:linx_<subsys>, :resync_needed}` on `ENOBUFS`;
  events are wake-up hints, resync is truth;
- a `last_applied` parameter wherever the kernel offers no ownership tag.

The existing `Linx.Netfilter` surface is the template; rtnl and sysctl model
their vocabulary on it so a consumer that has learned one has learned them all.

**The genuine divergences (kept visible, never papered over):**

1. **Value type** — `%Ruleset{}` vs a sysctl `%{key => value}` vs rtnl's
   per-namespace bundle of structs. These cannot be one type, and a consumer
   *wants* `Netfilter.pull` to return a `%Ruleset{}`, not a `term()`.
2. **Ownership model** — socket-owned + genID CAS (netfilter), `RTPROT` two-way
   (routes), last-applied three-way (addresses, sysctls).
3. **Atomicity** — netfilter's `push` is an atomic batch (all-or-nothing,
   rollback on genID mismatch); rtnl has **no transaction**, so a reconcile pass
   is an ordered sequence that can *partially apply* and therefore returns a
   richer *report* (what converged, what failed), not a bare `:ok`; sysctl writes
   are independent per key. Consumers must understand this — it is expressed in
   each subsystem's per-pass report/error type, not hidden.

**Convention now; a narrow behaviour only for the loop.** A fat shared
`@behaviour` would drag every `pull` down to `{:ok, term()}` and erase the type
information that makes each surface pleasant, while still leaking on atomicity.
So the rich per-subsystem surfaces stay convention-based. The one place a real
contract earns its keep is the opt-in loop's plug-in seam:

```elixir
# the generic loop's plug-in contract — deliberately minimal
defmodule Linx.Reconcile.Source do
  @callback observe(scope, opts) :: {:ok, observed} | {:error, term}
  @callback reconcile(scope, desired, last_applied, opts) ::
              {:ok, report} | {:error, term}
  @callback subscribe(scope, owner) :: {:ok, monitor} | {:error, term} | :unsupported
end
```

Each reconcilable subsystem implements this by delegating to its own
`pull`/`diff`/`push`. That gives two layers: the rich per-subsystem surface a
consumer uses directly when it wants control, and the narrow uniform contract the
generic loop drives. This contract is also the **litmus test** for whether the
opt-in loop is worth shipping (§8, Phase 7): if subsystems implement the three
callbacks cleanly, the loop is trivially worth it; if atomicity/ownership force
contortions, we stop at single-shot reconcile + Monitor primitives and let
consumers wrap them directly.

## 8. Phases

Dependency order — the reconciler's correctness depends on the things hardened
first. The error taxonomy and property-tested codecs this builds on already
landed (a reconcile loop's correctness *is* its error handling, and a codec bug
corrupts state on every pass). The sequencing below reflects the decisions in §9:
**sysctl leads** as the proving ground, while the independent rtnl actuation work
proceeds in parallel.

1. **rtnl actuation parity.** Settable `protocol`/`table`/`metric` (`RTA_PRIORITY`
   is not in the Route codec today), `NLM_F_REPLACE` for in-place updates (defined
   but never used), idempotent ops (every `add` is `CREATE|EXCL` today, so it
   errors if the object exists). Pure actuation — no reconcile logic — so it is
   independent groundwork that can run in parallel with everything below and is
   not blocked on any decision.
2. **sysctl reconcile — the proving ground.** The first full reconcile loop, built
   on the trivial flat `%{key => value}` case: `pull`/`diff`/`push(mode:
   :reconcile)`, three-way `last_applied` ownership, the **fail-fast** report
   (§9), and the `Reconcile.Source` contract (§7). This is where the generic
   discipline is nailed down and property-tested before the harder rtnl resources.
3. **rtnl per-resource `diff` + `RTPROT` ownership tagging.** Carry the validated
   discipline to the decoded structs (§6 keys), with the two-way/three-way
   asymmetry.
4. **rtnl single-shot `reconcile`.** The per-namespace ordered pass across resource
   types, reusing the Phase 2 pattern; the rtnl analogue of
   `Netfilter.push(mode: :reconcile)`, caller-driven, no long-lived state. Ordered
   before the Monitor deliberately: timer-based resync already converges (see the
   observe-loop note below), so reconcile does not depend on the Monitor.
5. **the rtnl `Monitor`.** `RTNLGRP_*` group subscription (constants do not exist
   yet; `Socket.add_membership/2` does), `ENOBUFS → :resync_needed`. The same
   codec decodes `RTM_NEW*`/`RTM_DEL*` into the same structs, so an event is just
   a wake-up — a latency layer over the timer-driven reconcile, not a prerequisite.
6. **`Linx.Process` supervision ergonomics.** `child_spec/1` carrying the spawn
   opts, restart-friendly exit semantics, and reliable OS-process reaping in
   `terminate` so a restart never leaks the old child. This is how "auto-restart
   a crashed container with the same arguments" is achieved — via OTP, not a
   reconcile loop (Bucket B/C).
7. **opt-in `Linx.Reconcile` loop** — shipped as `Linx.Reconcile` (the loop) +
   `Linx.Reconcile.Source` (the narrow plug-in contract of §7), with
   `Linx.Sysctl.Reconcile.Source` and `Linx.Netlink.Rtnl.Reconcile.Source`
   adapters. Thin, single-subsystem, level-triggered, `ENOBUFS`-resyncing,
   configurable cadence — and **really opt-in**, which is a hard test, not a
   vibe:
   - zero footprint if absent — no `Application` boot side effect, no
     auto-supervised process; the primitives work fully standalone;
   - an explicit `child_spec` the consumer adds to *their own* tree; Linx ships no
     supervisor that bundles it in;
   - no hidden global state or singleton — it holds the desired state it is given;
   - single-subsystem by construction — it never reaches for the composite;
   - the separability test — implementable entirely on the public single-shot
     `reconcile` + Monitor API, such that deleting it would cost a consumer only a
     ~15-line timer loop, nothing load-bearing.

   Being genuinely separable is also what keeps it from drifting into the runtime
   Linx refuses to be. Especially valuable to the simple host-config consumer that
   has no supervision tree of its own — for which it may be the *recommended* easy
   path, while still never automatic.
8. **cgroup limits reconcile** — shipped as `Linx.Cgroup.Reconcile` (+ `Report`
   and a `Source` adapter): reconcile the limit knobs (`memory.max`, `pids.max`,
   `cpu.max`, weights) as "sysctl-with-hierarchy" — flat `%{file => value}`,
   best-effort, three-way `last_applied`. cgroup existence/membership stays in
   the composite (this never creates/destroys the cgroup or moves processes).
9. **the proof-of-concept consumer.** A nested mix app at `tank/` with `mix.exs`
   declaring `{:linx, path: ".."}`, consuming **only the public `Linx.*` API** so
   it structurally cannot reach internals — which makes it the acceptance test
   for whether the primitives are sufficient, and a trivial lift-out later
   (`git mv` + flip the dep to a hex version). It exercises the cross-subsystem
   composite (container + namespace + address + rules + restart) that can only
   live in a consumer, and gates Phase 7.
10. **hardening.** Diff-correctness properties, CAS race behaviour, Monitor event
    ordering, the partial-apply report paths.

A note on the observe loop: you do **not** need the Monitor to start. For static
config, run the reconcile on a timer — re-`list`, diff, apply — and you already
get real convergence (delete an address by hand and the next tick restores it).
That is level-triggered resync, a *correctness* mechanism. The Monitor is a
*latency* improvement layered on top, feeding the same structs into the same
diff. Events are hints; resync is truth.

## 9. Decisions & open questions

### Decided

- **Q3 — sysctl leads.** The first full reconcile loop is built on sysctl as the
  proving ground for the generic discipline (Phase 2); the rtnl *actuation* fixes
  (Phase 1) are independent and run in parallel.
- **Q2 — partial-apply report, strategy per subsystem.** A reconcile pass returns
  a uniform report — `converged?` / `applied` / `failed` / `pending` (realized as
  `Linx.Sysctl.Reconcile.Report`) — but the *strategy* follows whether the
  subsystem's ops are ordered. **Ordered (rtnl)** is fail-fast: a later op depends
  on an earlier one (a route via a not-yet-added address fails anyway), so the
  pass stops at the first failure — `failed` holds ≤1 op, `pending` holds the
  rest. **Independent (sysctl)** is best-effort: every op is attempted so one
  permanent `EACCES` never starves the others — `failed` collects them all,
  `pending` is empty. Rollback is rejected either way: the level-triggered next
  tick is the safety net, which makes it wasted work.
- **Q1 — offer the opt-in loop (predisposition).** Linx will build toward shipping
  a thin opt-in `Linx.Reconcile` loop (Phase 7), subject to the five "really
  opt-in" constraints listed there and the `Reconcile.Source` litmus test (§7).
  The *final* go/no-go is confirmed by the PoC; the predisposition is yes.
- **Q4 — defer the `Connection` GenServer, demand-driven.** Concurrent in-flight
  rtnl requests are *not* a reconcile prerequisite: one reconciler per namespace
  owns its socket and does an ordered pass, and the Monitor uses a separate
  (multicast) socket, so nothing contends. The `Connection` GenServer waits for a
  concrete need — PoC-observed contention, or a deliberate shared-socket pool —
  rather than being sequenced ahead of reconcile work.

- **Phase-7 gate — resolved by the PoC.** The `tank/` PoC (Phase 9) built the
  container+network composite on the *public* API and converged end to end, with
  **no gaps** — and it did so by consuming the single-shot `Rtnl.Reconcile` +
  `Linx.Process` directly under OTP supervision. It did **not** need a
  per-subsystem `Linx.Reconcile` loop; the composite's lifecycle is supervision +
  checkpoint-time single-shot reconcile. Verdict: ship `Linx.Reconcile` (Phase 7)
  **thin and justified by the simple host-config consumer** (timer + Monitor
  wakeup + resync over one subsystem's single-shot reconcile) — not as a composite
  engine. The composite stays in the consumer, as designed.

### Still open

- Nothing blocking. Phases 7 (the thin opt-in loop) and 8 (cgroup limits
  reconcile) are implemented; Phase 9's `tank/` is a living PoC to grow as
  needed; Phase 10 (hardening) is the remaining work.

## Appendix — minimal reconcile skeleton (illustrative)

```elixir
def reconcile(socket, %Spec{} = spec, last_applied) do
  {:ok, links} = Link.list(socket)
  by_name = Map.new(links, &{&1.name, &1.index})

  observed = observe(socket, by_name)   # decoded structs, filtered to "ours"
  desired  = normalize(spec, by_name)   # same struct types

  socket
  |> apply_phase(:links,  diff(desired.links,  observed.links))
  |> apply_phase(:addrs,  diff(desired.addrs,  observed.addrs, last_applied.addrs))
  |> apply_phase(:routes, diff(desired.routes, observed.routes))
  |> apply_phase(:rules,  diff(desired.rules,  observed.rules))
end
```

Apply order follows the kernel's L2→L3 layering and is the only place the "tree"
is real — as a dependency DAG, not containment: create links → set attributes →
bring up → add addresses (connected routes appear here, for free) → add routes →
add rules → add neighbours. Teardown reverses. Addresses must precede routes (a
route via an unreachable gateway gets `ENETUNREACH`). Because ordering crosses
resource types, prefer **one reconciler per namespace** owning the socket and the
ordered pass, rather than a process per resource type with barriers between
phases. The namespace boundary is the kernel's own scoping boundary, so
`Rtnl.open/1` per namespace maps onto one reconciler per namespace exactly.
