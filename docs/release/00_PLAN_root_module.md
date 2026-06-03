# 00 — Root `Linx` module

**Status:** done (commit d35cd3c) · **Gates 0.1.0:** yes (publish blocker) · **Topic:** root module / hexdocs front matter

## Problem

`lib/linx.ex` is untouched `mix new` boilerplate:

```elixir
defmodule Linx do
  @moduledoc """
  Documentation for `Linx`.
  """

  @doc """
  Hello world.

  ## Examples

      iex> Linx.hello()
      :world
  """
  def hello, do: :world
end
```

This ships a junk public function (`Linx.hello/0`) in the released package and is
the canonical module entry a visitor sees on hexdocs.pm/linx. Its boilerplate
test lives in `test/linx_test.exs`:

```elixir
defmodule LinxTest do
  use ExUnit.Case
  doctest Linx

  test "greets the world" do
    assert Linx.hello() == :world
  end
end
```

Verified: nothing outside these two files references `Linx.hello` (the other
`grep "hello"` hits are unrelated test fixtures).

## Decision

Turn `lib/linx.ex` into a **pure documentation hub** — no functions — that serves
as the canonical *module index* for the library.

It must **not re-narrate the README.** `mix.exs` sets `main: "readme"`, so the
README is the landing page (narrative + install + the "primitives, not a runtime"
pitch; polished in topic `01`). The `Linx` moduledoc has a different job: a compact
**navigational map** of the API surface for someone browsing the module list. This
keeps prose in one place and avoids two docs drifting apart.

Resolved sub-decisions (from the proposal):

- **Moduledoc role:** concise index/map, not a fuller overview.
- **`test/linx_test.exs`:** delete the file. A pure-doc module has nothing to
  assert, and a bare `doctest Linx` with no examples is noise.
- **`Linx.version/0`:** not added. Keep the module function-less; trivial to add
  later if a real need appears.

## Moduledoc structure

Mirror the existing `groups_for_modules` grouping in `mix.exs` (lines ~116+) so the
page and the sidebar agree. Sections:

1. **Lede** — one sentence ("Linux kernel-interface primitives for Elixir") + one
   line restating "primitives, not a runtime" with a pointer to the README for the
   pitch and quick start.
2. **Subsystems** — the map, grouped, each entry a `` `Linx.X` `` autolink + a
   one-line description:
   - Process & namespaces — `Linx.Process`
   - Networking — `Linx.Netlink` / `Linx.Netlink.Rtnl`, `Linx.Netfilter`
   - Resource control — `Linx.Cgroup`
   - Filesystem — `Linx.Mount`
   - Identity & security — `Linx.User`, `Linx.Capabilities`, `Linx.Seccomp`
   - Tuning — `Linx.Sysctl`
   - Value types — `Linx.IP`, `Linx.MAC`
   - Declarative — `Linx.Reconcile`
3. **The composition** — 2–3 lines on the `Linx.Process` checkpoint as the seam
   the other subsystems hook into, linking to `Linx.Process`.
4. **Errors** — 1–2 lines on the `%Linx.X.Error{}` model; align wording with the
   contract finalized in topic `02` (so this section may be touched again there).
5. **Declarative reconcile** — 1–2 lines on the pull/diff/push triad, pointing to
   `docs/reconcile/EXAMPLES.md`.
6. **Getting started** — pointers to the README and the per-subsystem
   `EXAMPLES.md` (which become uniform in topic `04`).

Keep it tight — a map, not an essay. No `iex>` doctests (the module has no
functions).

## Concrete changes

1. `lib/linx.ex` — replace the moduledoc with the structure above; **delete
   `hello/0`**.
2. `test/linx_test.exs` — **delete the file.**

## Acceptance check

- `mix compile --warnings-as-errors` — clean.
- `mix test` — green, with one fewer test and no `Linx.hello` reference remaining
  (`grep -rn "Linx.hello" lib test` returns nothing).
- `mix docs` builds; the `Linx` module page renders the subsystem map with every
  `` `Linx.X` `` cross-link resolving (no broken autolinks in the ex_doc output).

## Risk / scope notes

- Low risk: deletes boilerplate, adds documentation only. No public API a real
  consumer could depend on is removed (`hello/0` is not real API).
- **Cross-topic touch:** the *Errors* section (4) restates the error contract that
  topic `02` finalizes, and the *Getting started* pointers (6) reference the
  EXAMPLES files reworked in topic `04` and the per-dir READMEs added in `05`. Do a
  light re-read of this moduledoc after `02`/`04`/`05` land; the final hexdocs pass
  in topic `11` is the backstop.
