# 12 — Hex release mechanics

**Status:** planned · **Gates 0.1.0:** this *is* the release · **Topic:** publishing Linx 0.1.0 to hex.pm

The capstone: the actual, irreversible publish of **Linx 0.1.0**, and the ordering for Tank
to follow. (Publishing claims the hex name permanently — there is no un-publish after 1h,
only retire, and a retired name is not freed.)

## The 0.1.0 gate (must be true before publish)
- **Blocker topics done:** `00` (root module), `01` (README), `02a`+`02b` (error contract),
  `03` (docs/package hygiene), `04a`+`04b` (EXAMPLES + REFERENCES), `05` (per-dir READMEs),
  `06` (build preflight), `07` (C zero-length), `08` (`supported?` convention).
- **Kernel layer verified manually:** `./sudotest.sh` green on the **exact release commit**
  — this is the gate, since `09`'s CI job is fast-follow.
- **Docs build clean:** `mix docs` zero warnings; minimal render sanity (full QA `11` is
  post-publish).
- **Fast-follow, NOT gating:** `09` (CI integration), `09b` (ASan/UBSan), `10` (property
  tests), `11` (rendered-docs QA).

## Publish sequence
1. **Maintainer auth (interactive — maintainer runs it):** `mix hex.user auth` (or
   `mix hex.user register` if oshlabs has no hex account). Confirm the publishing
   account/org. The agent cannot do this step.
2. **Package-metadata audit.** `mix.exs` is largely complete: MIT, GitHub links,
   `files: ~w(lib c_src mix.exs README.md LICENSE)`, maintainers, the long `description`,
   `version 0.1.0`. Confirm the description still reads true after all changes. Inspect the
   tarball with `mix hex.build`; ideally compile it from a clean checkout to prove the C
   builds for a consumer (ties to `06`'s preflight).
3. **Make `oshlabs/linx` public** — so `source_url` / hexdocs "View Source" resolve. (This
   is the "open them up" half of the original goal.)
4. **Publish** — `mix hex.publish` (package + docs together), or `mix hex.publish package`
   then `mix hex.publish docs`.
5. **Tag + release** — `git tag v0.1.0` + push; optional GitHub release.

## Tank — follow-on (documented here, executed separately)
Linx-first is forced: Tank can't carry a path dep on hex. Once Linx 0.1.0 is live:
- Flip Tank's `{:linx, path: "../linx"}` → `{:linx, "~> 0.1"}` (on a Tank branch; run its
  `mix test` + `./sudotest.sh` green).
- Tank then releases on its **own readiness** — it's mid-stream at M7 — likely an honest
  early `0.1.0` purely to **claim the `tank` hex name** (still free as of this planning).
  That publish is a separate effort in the `oshlabs/tank` repo; captured here only as the
  ordering + the dep flip.

## Acceptance check
- `mix hex.build` produces a tarball that compiles the C from a clean checkout on a
  supported Linux.
- `oshlabs/linx` is public; `source_url` resolves.
- `linx 0.1.0` is live on hex.pm; docs at hexdocs.pm/linx; `v0.1.0` tagged.
- Tank's dep-flip path is recorded for the follow-on.

## Risk / scope notes
- **Irreversible** — the first publish permanently claims the name. Do it only after the
  gate above, especially the manual `./sudotest.sh` (the kernel layer is otherwise
  CI-unverified until `09`).
- The hex auth step is the one thing the agent cannot perform; it blocks publish until the
  maintainer runs it.
