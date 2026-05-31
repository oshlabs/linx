# Declarative configuration via reconciliation — plan

> **Status: skeleton.** Captured quickly from memory to seed the
> `declarative-reconcile` branch. **Refine this plan after the next context
> compaction** — settle the open design question, flesh out the phases, and
> add task breakdowns before writing code.

## Goal

Make Linx **declarative**: describe the desired Linux networking/config
state, then a reconciler continuously diffs it against the kernel's actual
state and converges the two — the Kubernetes / VintageNet closed loop.
Idempotent and self-healing: manual drift, crashes, and reboots are all
corrected on the next reconcile pass.

## What already exists (the reference triad)

`Linx.Netfilter` is the prototype: `pull` (observe kernel state) + `diff`
(compute the minimal change) + `push(mode: :reconcile)` (apply atomically),
with genID-based compare-and-swap, stable per-rule `:tag` identity, and
resync-on-`ENOBUFS` subscription. That is a reconciler's substrate.

## The gap: rtnl

`Linx.Netlink.Rtnl` (links / addresses / routes / rules / neighbours) has
the actuation verbs but not the closed loop. To match Netfilter it needs:

- per-resource `diff`,
- ownership tagging (`RTPROT_*`) so the reconciler manages only what it owns,
- `NLM_F_REPLACE` for safe in-place updates,
- a multicast `Monitor` (the `ip monitor` equivalent) to close the observe
  loop.

## The key open design question (decide before any code)

Does the reconciler / control loop live **inside Linx** or in a **consumer
app**? Opening position, to be debated: Linx owns the *mechanism* (diff,
ownership tagging, Monitor, CAS); the long-lived control loop + desired-state
holder + retry/backoff cadence live in a consumer — or at most a clearly
opt-in `Linx.Reconcile` layer — to preserve the "primitives, not a runtime"
framing.

## Dependencies / why this is next

Builds on the polish work already on `main`: the normalized error structs (a
reconcile loop must distinguish transient `EAGAIN`-retry from fatal `EPERM`),
the uniform `{:error, %X.Error{}}` shapes, and the property-tested codecs (a
buggy codec corrupts desired state on every pass).

## Phases (placeholder — refine after compaction)

1. Design discussion + decision on the in-Linx-vs-consumer fork.
2. rtnl observe side: the multicast `Monitor`.
3. rtnl `diff` + ownership tagging + `NLM_F_REPLACE`.
4. A reconcile API (shape determined by phase 1).
5. Hardening: diff-correctness properties, CAS race behaviour, Monitor
   event ordering.

## Notes

- No version numbers in this plan or the branch, by request.
- Related: the "Declarative reconcile" section of `docs/ROADMAP.md` and
  `docs/netfilter/DESIGN.md`.
