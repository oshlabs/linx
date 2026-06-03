# 11 — Generated-docs quality review

**Status:** planned · **Gates 0.1.0:** no (fast-follow) · **Topic:** final holistic QA on the rendered hexdocs

A holistic pass over the built `mix docs` site. Depends on everything `00`–`10` having
landed — it's the backstop that catches whatever those left rough.

## Problem
Nobody has read the *rendered* hexdocs end-to-end. After the root module, README, per-dir
READMEs + Mermaid, uniform EXAMPLES, linked REFERENCES, and the error-spec changes, the
built HTML needs a human walkthrough to confirm it reads as genuinely top-notch. Broken
autolinks, unrendered diagrams, awkward phrasing, and mis-grouped navigation are the things
that only show up when someone actually reads the site.

## Decision / approach
**Primarily a manual, interactive read** — the maintainer and the agent walk the built docs
together, page by page, making modifications as issues surface. This is iterative
(back-and-forth), not a one-shot checklist; expect edits to moduledocs, EXAMPLES, READMEs,
and `mix.exs` doc config as we go.

A few **lightweight scripted checks** run first, only to clear the mechanical noise so the
manual read is about *quality*, not dead links:
- `mix docs` builds with **zero warnings** (ex_doc flags broken refs / missing extras).
- A quick dead-link sweep (`curl -sI`) over the REFERENCES/extras URLs from `04b`.
- Greps: no stray `iex>`/`...>` in examples; no AGENTS/ROADMAP/CHANGELOG pages; no
  `@moduledoc false` internals in the sidebar.

**The manual read** (the substance) covers, with edits made live:
- Landing page (README) reads as a proper front page; the root `Linx` page is the subsystem
  map (`00`), not boilerplate.
- Per group: the README is a good landing page and **Mermaid diagrams render** (`05`);
  EXAMPLES read well and are copy-pasteable (`04a`); REFERENCES are fully linked (`04b`).
- Module pages: real moduledocs, `@doc` + `@spec` on public functions, and specs showing
  the **real error types** (`%Linx.X.Error{}` unions from `02a`/`02b`).
- Navigation/grouping is sensible; tone and density are consistent across subsystems.

## Relationship to 0.1.0
Fast-follow — the thorough read is post-publish. A **minimal pre-publish sanity** (docs
build clean; README + a couple of pages render) is already implied by `00`/`01`/`04`/`05`
acceptance and by `12` (which won't publish docs that fail to build). `11` is the exhaustive
human pass on top.

## Coupling
- Depends on all of `00`–`10`.
- `12` publishes docs via `mix hex.publish docs`; a clean `11` is what makes that
  trustworthy.

## Concrete changes
- Whatever the read surfaces — moduledoc/EXAMPLES/README edits, `mix.exs` doc-config
  tweaks, grouping fixes. Open-ended by nature; tracked as the review proceeds.

## Acceptance check
- `mix docs` builds warning-clean; no dead links in REFERENCES/extras.
- The maintainer has read the rendered site top-to-bottom and signed off; outstanding nits
  are either fixed or consciously deferred.

## Risk / scope notes
- Open-ended and iterative; the value is human judgment, not automation. Time-box if needed
  and defer non-blocking polish to 0.1.x.
- Findings here may loop back into any `00`–`10` topic.
