# 04b — REFERENCES.md links & uniformity

**Status:** planned · **Gates 0.1.0:** yes (public-facing, cheap–medium) · **Topic:** per-subsystem REFERENCES.md

Split from `04`. Companion: `04a` (EXAMPLES.md). REFERENCES.md are the per-subsystem
citation pages (man pages, kernel docs, UAPI headers, in-repo cross-refs), surfaced on
hexdocs via `mix.exs` extras.

## Problem
The citations already exist and are good; in most files they just aren't **hyperlinked**.
Link coverage today:

| Well-linked (model/near-model) | links | Thin / unlinked (need links added) | links |
|---|---|---|---|
| netfilter | 45 | capabilities | 0 |
| netlink | 35 | cgroup | 0 |
| process | 21 | mount | 0 |
| tty | 18 | sysctl | 0 |
| | | user | 0 |
| | | seccomp | 3 |

`docs/netfilter/REFERENCES.md` is the model: each citation is `**[title](url)**` — short
description, grouped under standard sections. The unlinked files cite real sources
(`user_namespaces(7)`, `clone(2)`, kernel-doc paths, UAPI headers) in **plain text** —
they just need the URLs added in the same format.

## Decision / approach
1. **Link-ify existing citations** in the six thin files (capabilities, cgroup, mount,
   sysctl, user, seccomp), matching netfilter's `**[name](url)**` — description format.
   Don't rewrite the prose; add the hyperlink to each named source. URL conventions
   (from the netfilter model):
   - **Man pages** → `https://manpages.debian.org/...` or `https://man.archlinux.org/...`
   - **Kernel docs** → `https://docs.kernel.org/...`
   - **UAPI headers / kernel source** →
     `https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/<path>`
   - **RFCs** → `https://www.rfc-editor.org/rfc/rfcNNNN`
2. **Uniform structure** across all 11, modeled on netfilter/user: a consistent section
   set, in consistent order, including only the sections that apply —
   `## Kernel UAPI headers` · `## Kernel documentation` · `## Man pages` ·
   `## In-repo cross-references` · `## Adjacent userspace tooling`.
   Add a uniform 1–2 line intro (netfilter/user already share one).
3. **Relevance check** — drop or mark "out of scope" any citation that isn't actually
   encoded/learned-from (netfilter already does this for deferred milestones).

## Coupling
- `04a` (EXAMPLES) — the paired page; `05` (per-dir README) links to REFERENCES.
- `11` (rendered-docs QA) re-checks links resolve in the built hexdocs.

## Concrete changes
- `docs/{capabilities,cgroup,mount,sysctl,user,seccomp}/REFERENCES.md` — add URLs to
  every named man page / kernel doc / UAPI header; align sections to the standard set.
- `docs/{netfilter,netlink,process,tty}/REFERENCES.md` — light pass to confirm they
  already match the standard sections; fix any drift.

## Acceptance check
- Every REFERENCES.md citation that names a man page, kernel doc, or UAPI header is a
  hyperlink (`grep -L 'http' docs/*/REFERENCES.md` → no file that *should* have links is
  link-less; the six thin files now have links).
- All files share the standard section set + intro.
- **Links resolve**: a HEAD/`curl -sI` sweep of every added URL returns 2xx/3xx (run at
  execution; the `11` rendered-docs pass is the backstop).
- `mix docs` renders every REFERENCES page without warnings.

## Risk / scope notes
- Docs-only. The real effort is research: finding the canonical *stable* URL per source
  (kernel.org git tree for UAPI, docs.kernel.org for docs, a stable man-page host). The
  netfilter file already establishes every host/pattern to reuse.
- Pick **one** man-page host and use it consistently (netfilter mixes Debian + Arch —
  worth normalizing to one during this pass).
