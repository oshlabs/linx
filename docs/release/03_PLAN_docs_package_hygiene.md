# 03 — Docs / package hygiene

**Status:** planned · **Gates 0.1.0:** yes (cheap, public-facing) · **Topic:** what ships and what renders on hexdocs

## Problem
- **AGENTS.md leaks into public hexdocs** — listed in `mix.exs` `extras` (`:68`) and as
  `"Repo-wide": ["AGENTS.md"]` in `groups_for_extras` (`:113`). It is LLM/dev
  instructions, not user documentation.
- **AGENTS.md mixes documentation into instructions** — most of it is directives, but
  the error-handling subsection (`AGENTS.md:34-49`) *documents the error contract* in
  prose + a sample struct (now covered by the README and each `Linx.X.Error`
  moduledoc), and the generic Elixir bullets (`:51-77`) are language-101 knowledge, not
  linx-specific instruction.
- **`docs/ROADMAP.md`** carries stale release framing (deferred / CHANGELOG / "confirm
  name available") and is superseded by `docs/release/`. Only one referrer:
  `docs/reconcile/PLAN.md`.
- **`erl_crash.dump` (5 MB)** at the repo root — gitignored (won't ship) but cruft.
- **`files:`** (`lib c_src mix.exs README.md LICENSE`) — audit-only; docs reach hexdocs
  via `mix hex.publish docs` (working tree), not the tarball, so omitting `docs/` is
  correct.

## Decision / approach
1. **Simplify AGENTS.md to instructions-only.** Principle: it directs how the LLM
   writes code; it does not *document the library for a reader* (that's moduledocs +
   README). Concretely:
   - Condense the error-handling subsection (`:34-49`) to a short directive + pointer:
     "Follow the three-lane error contract — kernel failure → `%Linx.X.Error{}`;
     context-free → bare atom; input validation → `{:error, {:bad_*, _}}`. See the
     README *Errors* section and the `Linx.X.Error` moduledocs." Drop the duplicated
     prose and the sample struct.
   - Trim the generic Elixir-101 bullets (`:51-77`) that aren't linx-specific; keep the
     ones that are real guardrails for *this* codebase if any, at execution judgment.
   - Keep the linx-specific guidance: code style, the NIF-vs-port decision and C rules,
     mix-format-before-commit, and the test patterns.
   - Target: noticeably shorter, purely directive.
2. **Remove AGENTS.md from hexdocs** — delete the `extras` entry (`:68`) and the
   `"Repo-wide"` group (`:113`). The file stays in the repo as the agent guide.
3. **Delete `docs/ROADMAP.md`** and remove its reference in `docs/reconcile/PLAN.md`
   (repoint to the relevant moduledoc / `docs/release/`, or drop the sentence).
4. **Delete `erl_crash.dump`.**
5. **Confirm `files:`** — `lib` carries the `lib/mix/tasks/compile.*` custom compilers,
   `c_src` the C sources, plus `mix.exs`/`README.md`/`LICENSE`; no `docs/` needed in the
   tarball. Record the rationale; expect no change.

## Coupling note
The `extras` / `groups_for_extras` block is **restructured by topic `05`** (per-`docs/*/`
README files wired in). `03` only does removals here (AGENTS); `05` does the additions.

## Concrete changes
- `AGENTS.md` — simplify per (1).
- `mix.exs` — drop AGENTS from `extras` and `groups_for_extras`.
- delete `docs/ROADMAP.md`; edit `docs/reconcile/PLAN.md` to drop the ROADMAP reference.
- delete `erl_crash.dump`.

## Acceptance check
- `grep -n "AGENTS" mix.exs` → empty; `mix docs` builds with no AGENTS page / "Repo-wide"
  group.
- `git ls-files docs/ROADMAP.md` → empty; `grep -rln "ROADMAP" lib docs --include='*.md'`
  (excluding `docs/release/`) → empty.
- `erl_crash.dump` gone.
- AGENTS.md is shorter and contains no library *documentation* (no duplicated contract
  prose / sample structs) — only directives.

## Risk / scope notes
- Low risk; no code paths touched. AGENTS.md and ROADMAP.md are dev-only.
- Deleting ROADMAP loses the cross-cutting forward plan; acceptable since per-subsystem
  forward notes live in moduledocs and release work now lives in `docs/release/`.
