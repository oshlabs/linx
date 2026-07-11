# TODO: extract the shared flat-KV reconcile engine (cgroup + sysctl)

Status: **not started** — deliberately deferred out of the 2026-07-11
`review-fixes` pass (refactor, not a correction).

## Problem

`Linx.Cgroup.Reconcile` and `Linx.Sysctl.Reconcile` are ~85% line-identical
twins. Both reconcile a flat key→value store against desired state with
three-way `last_applied` ownership, and the shared machinery came out the
same in both files:

- `diff/4` (desired ∪ owned keys → ops, revert-and-release for keys that
  left the desired set)
- `apply_ops/…` (best-effort apply, per-op failure collection)
- `next_last_applied/…` (ownership threading: failed sets keep old
  ownership, failed reverts are retried, capture-once `:original`)
- `converged?/…`, `tokens/1`, `relevant_keys/…`
- the `%Report{}` structs (identical fields, identical `Inspect` impls)
- the `Linx.Reconcile.Source` adapters

The moduledocs acknowledge the mirroring ("mirrors `Linx.Sysctl.Reconcile`
exactly"), and the 2026-07 review found the risk it invites is real: the
trailing-whitespace convergence bug had to be fixed **twice** (once per
twin), and any future change to `next_last_applied` semantics can silently
diverge between the copies. AGENTS.md's "no abstraction until a second
caller" defended the first copy; the second caller exists, so the third
flat-KV subsystem must not become a third copy.

## Shape of the fix

One shared engine — working name `Linx.Reconcile.FlatKV` (or
`Linx.KV.Reconcile`) — owning the pass structure and ownership semantics,
parameterized by a small adapter (behaviour or function map) for what
actually differs:

| Callback | cgroup | sysctl |
|---|---|---|
| `read(scope, key)` | `Cgroup.read/2` (path, file) | `Sysctl.read/2` (`:in` opts) |
| `write(scope, key, rendered)` | `Cgroup.write/3` | `Sysctl.write/3` |
| `render(value)` | `:max`, `{quota, period}`, int, binary | int, int list, binary |
| `same_value?(raw, desired)` | token-wise + `:max` prefix rule | token-wise ints, trimmed binaries |
| scope shape | cgroup dir path (positional arg) | `:in` target (in opts) |

Everything else — diff, apply, `next_last_applied`, report assembly,
convergence — moves into the engine **once**. The public per-subsystem
modules (`Linx.Cgroup.Reconcile`, `Linx.Sysctl.Reconcile`) keep their
exact current APIs, docs, and Report struct names, becoming thin fronts
over the engine; the `Reconcile.Source` adapters are untouched.

Known asymmetry to preserve, not paper over: cgroup takes the scope
positionally (`reconcile(cg, desired, last_applied, opts)`) while sysctl
carries it in opts (`reconcile(desired, last_applied, opts)`) — the public
signatures stay as they are; only the internals unify.

## Acceptance criteria

- `test/linx/cgroup/reconcile_test.exs`,
  `test/linx/cgroup/reconcile_property_test.exs`,
  `test/linx/sysctl/reconcile_test.exs`, and
  `test/linx/reconcile_integration_test.exs` pass **unchanged** — the
  existing suites define the semantics; if a test needs editing, the
  refactor changed behavior and is wrong.
- Full `./sudotest.sh` green; dialyzer clean.
- Net line count goes down (~120+ lines of duplication deleted).
- The ownership rules (capture-once `:original`, failed-set ownership
  retention, failed-revert retry) live in exactly one documented place.

## Trigger / priority

Low urgency — do it before (or as part of) adding any third flat-KV
reconcile surface, or the next time a semantic change has to touch
`next_last_applied` in both files. Folds naturally into the 0.3.0 cycle.
