# 05 — Per-directory README.md for docs/*/

**Status:** planned · **Gates 0.1.0:** yes (public-facing) · **Topic:** subsystem overview / doc-group landing pages

The largest docs topic: a `README.md` in every `docs/<subsystem>/` that serves as the
**high-level overview** and landing page for that subsystem's doc group on hexdocs.

## Problem
There is no per-subsystem overview page. The moduledoc is the API reference, EXAMPLES.md
is recipes, REFERENCES.md is citations — but nothing answers, at a glance, *"what is this
subsystem, what problem does it solve, and where does it sit in Linx?"* On hexdocs each
group (Netlink, Process, …) currently opens straight into EXAMPLES with no orientation.

## Decision / approach
Add `docs/<sub>/README.md` as a **high-level, conceptual overview** — explicitly **not** a
moduledoc duplicate (the moduledoc stays the API + usage reference) and **not** a status
tracker. It answers: what the subsystem does, its place in the grand view (relation to the
`Linx.Process` checkpoint and sibling subsystems, who consumes it), and the flow — with a
diagram where one clarifies.

**Grounding (research inputs, not content to copy):**
- The retired `docs/<sub>/{PLAN,COVERAGE}.md` at `git show 6a12443^:docs/<sub>/PLAN.md`
  — for the "Goal"/use-case prose **only**. **Do not** resurrect milestone codes
  (`U0–U2`), status legends (`✅🟡⬜⏳`), or coverage matrices — `6a12443` removed those
  deliberately, and they're tracker noise.
- The current `Linx.X` moduledoc and `docs/<sub>/REFERENCES.md` sources.
- Targeted online reading (man pages, kernel docs) where it sharpens the overview.

**Uniform structure across all 11:**
```
# Linx.X
<lead: 1–2 sentences — what this subsystem does, at a high level>

## Overview          # the kernel surface it wraps + the problem it solves, conceptually
## Where it fits     # its place in Linx — the checkpoint, sibling subsystems, consumers
## Flow              # a diagram where it helps (lifecycle / data flow); omit if it doesn't
## Learn more        # links: `Linx.X` moduledoc (API) · EXAMPLES.md (recipes)
                     #        · REFERENCES.md (sources) · DESIGN.md (where it exists)
```

**Diagrams:** prefer **Mermaid** (renders on hexdocs) — but it requires wiring once into
ex_doc (`before_closing_body_tag` injecting the mermaid init script) in `mix.exs` docs
config. That wiring is a sub-task of this topic. Fall back to a fenced ASCII diagram where
the flow is simple enough not to warrant it. Diagrams are *where they help*, not mandatory.

**Wiring:** add each `docs/<sub>/README.md` as the **first** entry in its
`groups_for_extras` group in `mix.exs` so it's the group's landing page. This is the
extras restructure topic `03` deferred to here.

## Coupling
- `03` removed AGENTS from extras; this adds the READMEs — same `mix.exs` block.
- `04a`/`04b` — the README's "Learn more" links to EXAMPLES/REFERENCES; intro lines should
  match what those settle.
- `11` (rendered-docs QA) — verifies the READMEs render, links resolve, and Mermaid
  diagrams display in the built hexdocs.

## Concrete changes
- New `docs/{netlink,process,tty,cgroup,mount,user,capabilities,seccomp,sysctl,netfilter,reconcile}/README.md`.
- `mix.exs` — add the 11 READMEs to `extras` and as the lead of each `groups_for_extras`
  group; wire Mermaid into the docs config if diagrams use it.

## Acceptance check
- Every `docs/<sub>/` has a `README.md` following the uniform structure; none duplicates
  its moduledoc and none contains status/milestone trackers.
- `mix docs` renders each as its group's landing page; Mermaid diagrams display; all
  cross-links resolve.
- A reader landing on a group understands the subsystem's purpose and place before any
  recipe or API detail.

## Risk / scope notes
- Biggest docs effort (11 grounded overviews + diagrams + research), but per-subsystem and
  parallelizable.
- Main pitfall: drifting into moduledoc duplication or tracker content. Keep it
  orientational ("what / why / where it fits / the flow"), defer all API detail to the
  moduledoc and all status to nowhere.
- Mermaid wiring is a one-time ex_doc config change that also benefits any future diagrams.
