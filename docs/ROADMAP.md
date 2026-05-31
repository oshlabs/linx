# Linx roadmap

Forward-looking direction — the **cross-cutting** plan. Per-subsystem
feature backlogs live in each module's "Forward compatibility" moduledoc
section; this file is for work that spans subsystems or sequences phases.

## Sequencing (and why)

1. **Cleanup / polish** — normalize interfaces, consolidate docs, baseline
   hardening. ✅ Done; the branch that introduced this file.
2. **Declarative reconcile** — the next major capability (below).
3. **Hardening round 2** — runs *after* reconcile, deliberately. Reconcile
   adds substantial new code (rtnl `diff` / ownership / `Monitor`), and
   property-testing + sanitizing a surface that's about to change is wasted
   effort. Harden once the shape is settled.
4. **Release to hex.pm** — when the maintainer is satisfied. Deferred on
   purpose; the mechanics (package metadata, CHANGELOG, CI) are already in
   place.

## Declarative reconcile (next major work)

Make Linx **declarative**: describe desired Linux networking/config state,
then a reconciler continuously diffs it against the kernel's actual state
and converges them — the Kubernetes / VintageNet closed loop. Idempotent and
self-healing across drift, crashes, and reboots.

- **The triad already exists in `Linx.Netfilter`:** `pull` (observe) +
  `diff` (minimal change) + `push(mode: :reconcile)` (apply), with
  genID-based compare-and-swap, stable per-rule `:tag` identity, and
  resync-on-`ENOBUFS` subscription. That is a reconciler's substrate.
- **The gap is rtnl** (links / addresses / routes / rules / neighbours): it
  has the actuation verbs but not the closed loop. To match Netfilter it
  needs per-resource `diff`, ownership tagging (`RTPROT_*`), `NLM_F_REPLACE`
  for safe in-place updates, and a multicast `Monitor` (the `ip monitor`
  equivalent — also on the netlink forward-compat list).
- **Open design question (needs a dedicated discussion):** does the
  reconciler / control loop live *inside* Linx or in a consumer app? Opening
  position: Linx owns the **mechanism** (diff, ownership tagging, Monitor,
  CAS); the long-lived control loop + desired-state holder + retry cadence
  belong in a consumer, or at most a clearly opt-in `Linx.Reconcile` layer —
  to preserve the "primitives, not a runtime" framing.

## Hardening round 2 (after reconcile)

Baseline hardening is already in place: StreamData property tests
(value types, netlink codec seams, a generative `~NFT` round-trip, sysctl
keys) and error-path coverage (the `%X.Error{}` model + not-found
pipelines). Remaining:

- **C ASan/UBSan** on the five NIFs — build with
  `-fsanitize=address,undefined` and run the integration suite under them.
  Gated on the CI privileged job below (needs the privileged suite running).
- **CI privileged integration job** — the 147 `:integration` tests need
  root / namespaces / nf_tables / cgroups. Triage what the GitHub
  `ubuntu-24.04` runner kernel actually supports; promote what passes to a
  (initially non-required) job. See `.github/workflows/ci.yml`.
- **More property tests** — the `Linx.Netlink.Codec` per-message
  round-trips, seccomp `from_rules` / `to_rules`, the `/proc/<pid>/mountinfo`
  parser.
- **Reconcile-specific** (once it exists) — `diff` correctness properties,
  ownership / genID CAS race behaviour, `Monitor` event ordering.

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
