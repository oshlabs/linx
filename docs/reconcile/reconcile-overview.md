# Overview

`Linx.Reconcile` is a thin, opt-in control loop that keeps one kernel subsystem
converged on a desired state — re-observing and re-diffing on a timer, and
reacting within milliseconds to a change event when the subsystem offers one.


A single `reconcile` call — observe current state, diff against desired, apply
the minimal patch — is correct exactly once. Real systems drift: a manual `ip`
command, a crash, a reboot. `Linx.Reconcile` turns the single-shot mechanism into
*continuous* convergence: a level-triggered loop that resyncs periodically (the
correctness layer — drift is healed on the next pass) and, where a subsystem
Monitor exists, wakes immediately on a change hint (a latency layer over the
timer). **Events are hints; resync is truth.** It is deliberately minimal: no
boot side effects, no global state, no singleton — it holds only the desired
state and the ownership you hand it, and drives exactly one
`Linx.Reconcile.Source` in one namespace.

## Where it fits

This is the optional capstone over Linx's reconcilable subsystems. Each one —
`Linx.Netfilter` (the original template), `Linx.Netlink.Rtnl`, `Linx.Sysctl` —
exposes the same four verbs (observe, diff, reconcile, subscribe) behind a
`Linx.Reconcile.Source` adapter; `Linx.Reconcile` is built entirely on that
public contract, so deleting it would cost a consumer only a ~15-line timer loop.
It is single-subsystem by construction: the cross-subsystem composite ("this
container, with this network, in this cgroup, bound to this process") belongs to
the consumer — an orchestrator — never here. You add
`{Linx.Reconcile, opts}` to *your own* supervision tree; Linx ships nothing that
starts it for you.

### Ownership = lifetime

A reconciler's natural unit is the network namespace (`Linx.Netlink.Rtnl.open/1`
is per-namespace), and a resource's owner is whatever should share its lifetime.
That splits cleanly into long-lived host infrastructure — physical NICs,
bridges, the host's own addresses and routes, a macvlan/ipvlan *parent* — owned
by a host-scoped loop whose lifetime is the node's, and ephemeral per-container
plumbing — a container's ipvlan slave, its veth pair, the addresses inside its
namespace — owned by a loop in the container's own supervision subtree, so it
*stops when the container stops* and leaves no orphan loop recreating an
interface into a namespace that no longer exists. Two rules fall out: the host
loop's desired state must never name a resource whose existence is conditional on
a container (those belong to the container's subtree, which has the right
lifetime), and cross-scope dependencies read one direction only — a container
reads a host-owned link's index to build its ipvlan; the host never reaches into
a container. What *pins* a namespace decides what survives a restart: if the
inner process pins it, the network dies and is reborn on each restart (a brief
blip, no leaks); if a longer-lived holder pins it (a bind-mount, or a
pause/sandbox holder, as Kubernetes pods do), addresses and routes outlive
individual restarts and the restarted process re-enters the same namespace with
its config intact. That is a per-workload choice for the consumer.

## Flow

The classic closed-loop control model: desired and observed states feed a diff,
the resulting patch is applied, and the loop is re-armed — by a periodic timer
for correctness, or sooner by a Monitor hint for latency.

```mermaid
flowchart LR
    desired["desired state<br/>(you provide)"] --> diff
    observe["observe<br/>(read kernel)"] --> diff["diff"]
    diff -->|"create / update / delete ops"| act["reconcile<br/>(apply patch)"]
    act --> kernel["kernel subsystem"]
    kernel --> observe
    timer["timer (resync = truth)"] -.->|"re-arm"| observe
    monitor["Monitor (hint = latency)"] -.->|"look now"| observe
```

## Learn more

- **API** — `Linx.Reconcile` (the opt-in loop) and `Linx.Reconcile.Source` (the
  per-subsystem plug-in contract)
- **Examples** — [reconcile-examples.md](reconcile-examples.md): the shared reconcile model, the
  opt-in loop, the Source contract, and how the pieces fit
