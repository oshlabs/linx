# 04a — EXAMPLES.md uniformity

**Status:** planned · **Gates 0.1.0:** fast-follow-eligible, but cheap → do for 0.1.0 · **Topic:** per-subsystem EXAMPLES.md

Split from `04`. Companion: `04b` (REFERENCES.md links). EXAMPLES.md are runnable
recipe pages, surfaced on hexdocs via `mix.exs` extras.

## Problem
The 11 EXAMPLES.md have uniform titles (`# Linx.X examples`) but inconsistent
organization: h2 counts run 4 (mount) → 31 (netfilter); some open with
`## Detecting support`, others `## Quick start`; `## Error paths` exists in `process`
only; reconcile sections appear ad hoc; no consistent intro block. Code-block
conventions also drift against two standing rules: **no `iex>`/`...>` prefixes** (so
recipes paste cleanly) and **`/bin/sh`, not `/bin/bash`**. Content quality is already
good — this is alignment + polish, not a rewrite.

Confirmed: EXAMPLES.md contain **no links** today, and by rule they stay link-free —
extensive examples only; all citations live in REFERENCES.md (`04b`).

## Decision / approach
Apply a **common spine** to every file; subsystem-specific recipes vary in the middle.

```
# Linx.X examples
<1–2 sentence intro: what X is + "Runnable recipes. See `Linx.X` for the API and
 REFERENCES.md for sources.">

## Detecting support          # only where supported?/0 exists; identical wording
## Quick start                # the simplest end-to-end recipe
## <domain sections…>         # the bulk — subsystem-specific, by design
## Composing with `Linx.Y`    # uniform heading where the subsystem composes
## Declarative reconciliation # only reconcile-capable: sysctl, cgroup, rtnl, netfilter
## Error paths                # uniform heading + placement (near the end)
```

Uniform **conventions**, applied to all 11:
- **No `iex>` / `...>` prefixes** anywhere — bare expressions in code blocks, results
  shown as `# => ...` comments. (The flagship `Linx.Process` example already does this.)
- **`/bin/sh`, not `/bin/bash`**, in any `argv`/command.
- Consistent comment voice (intent, not mechanics); every block copy-paste-runnable.
- No external links (citations → REFERENCES.md).

"Like they do now, but better": where a file is thin (mount h2:4, user h2:5), add the
missing spine sections (Quick start / Error paths / Composing) if the content warrants;
don't pad.

## Coupling
- `05` (per-`docs/*/` README) is the index that points at EXAMPLES/REFERENCES; the
  intro line here must match what `05` settles — read together.
- `11` (rendered-docs QA) verifies each page renders cleanly on hexdocs.

## Concrete changes
- Each `docs/<sub>/EXAMPLES.md` — align to the spine, add the uniform intro, rename
  recurring sections to the canonical headings, strip any `iex>`/`...>`, swap
  `/bin/bash` → `/bin/sh`.

## Acceptance check
- `grep -rn 'iex>\|\.\.\.>' docs/*/EXAMPLES.md` → empty.
- `grep -rn '/bin/bash' docs/*/EXAMPLES.md` → empty.
- `grep -rnoE '\]\([^)]+\)|https?://' docs/*/EXAMPLES.md` → empty (still link-free).
- Every file: `# Linx.X examples` + intro block; lead sections (Detecting support where
  applicable → Quick start) and trailing `## Error paths` present and consistently named.
- `mix docs` renders every EXAMPLES page without warnings.

## Risk / scope notes
- Docs-only, low risk. The judgment is "improve thin files vs leave them" — bias to the
  spine, but don't invent recipes that don't earn their place.
