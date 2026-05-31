# Linx roadmap

Forward-looking direction — the **cross-cutting** plan. Per-subsystem
feature backlogs live in each module's "Forward compatibility" moduledoc
section; this file is for work that spans subsystems or sequences phases.

## Sequencing (and why)

1. **Cleanup / polish** — normalize interfaces, consolidate docs, baseline
   hardening. ✅ Done; the branch that introduced this file.
2. **Declarative reconcile** — ✅ Done. The closed loop now spans Netfilter,
   rtnl, sysctl, and cgroup limits, with an opt-in `Linx.Reconcile` loop on top
   (below). See `docs/reconcile/EXAMPLES.md` and `docs/reconcile/PLAN.md`.
3. **Hardening round 2** — runs *after* reconcile, deliberately: property-testing
   a surface that's about to change is wasted effort, so it waited for the shape
   to settle. The reconcile-specific hardening landed with the feature; the
   cross-cutting items below remain.
4. **Release to hex.pm** — when the maintainer is satisfied. Deferred on
   purpose; the mechanics (package metadata, CHANGELOG, CI) are already in
   place.

## Declarative reconcile ✅ (shipped)

Linx is now **declarative**: describe desired networking/config state and a
reconciler diffs it against the kernel and converges them — the Kubernetes /
VintageNet closed loop, idempotent and self-healing across drift, crashes, and
reboots. All of it on the `pull`/`diff`/`push(mode: :reconcile)`/`subscribe`
template that `Linx.Netfilter` set.

- **rtnl** — per-resource `diff` with two-way (`RTPROT` tag) / three-way
  (`last_applied`) ownership, `NLM_F_REPLACE` in-place updates, a single-shot
  `Linx.Netlink.Rtnl.Reconcile`, and a multicast `Monitor`.
- **sysctl** and **cgroup limits** — single-shot `Reconcile` (three-way
  ownership, best-effort apply).
- **`Linx.Reconcile`** — the opt-in, single-subsystem control loop over the
  `Linx.Reconcile.Source` contract (timer resync + Monitor wakeups).

**The open design question is resolved:** Linx owns the mechanism *and* ships a
thin, genuinely opt-in `Linx.Reconcile` loop (no boot side effect, no singleton,
separable) — while the cross-subsystem composite stays in the consumer, proven
by the `tank/` PoC. "Primitives, not a runtime" holds. Full design in
`docs/reconcile/PLAN.md`; usage in `docs/reconcile/EXAMPLES.md`.

## Hardening round 2 (after reconcile)

Baseline hardening is already in place: StreamData property tests
(value types, netlink codec seams, a generative `~NFT` round-trip, sysctl
keys) and error-path coverage (the `%X.Error{}` model + not-found
pipelines). Remaining:

- **C ASan/UBSan** on the five NIFs — build with
  `-fsanitize=address,undefined` and run the integration suite under them.
  Gated on the CI privileged job below (needs the privileged suite running).
- **CI privileged integration job** — the ~168 `:integration` tests need
  root / namespaces / nf_tables / cgroups. Triage what the GitHub
  `ubuntu-24.04` runner kernel actually supports; promote what passes to a
  (initially non-required) job. See `.github/workflows/ci.yml`.
- **More property tests** — the `Linx.Netlink.Codec` per-message
  round-trips, seccomp `from_rules` / `to_rules`, the `/proc/<pid>/mountinfo`
  parser.
- **Reconcile-specific** — ✅ Done with the feature: `diff` convergence
  properties (rtnl + cgroup), `Monitor` event ordering and decode totality, and
  the partial-apply report paths (rtnl fail-fast, sysctl/cgroup best-effort).
  Netfilter genID CAS races remain exercised in its own suite.

## Docs polish (optional)

- Forward-compatibility notes for the `Linx.Netlink.Codec` and the
  version-locked `Linx.Process` / `Linx.Tty` agent protocol (the one
  per-subsystem moduledoc spot the polish pass left as low-priority).

## Release to hex.pm (deferred)

Already done: `package:` metadata, `CHANGELOG.md`, the CI matrix + README
badge, the `~> 1.15` / OTP 26 floor.

Still needed when the maintainer chooses to publish:

- Confirm the **`:linx` package name** is available on hex.pm.
- Decide **publisher identity** — personal hex account vs a `oshlabs` hex
  organization (the repo is org-owned).
- `mix hex.user auth` (or org auth), then a reviewed `mix hex.publish`.
- Quiet the handful of benign `mix docs` auto-link warnings for a clean
  release docs build.
- Flip the GitHub repo **public** (the CI badge then renders for everyone).
