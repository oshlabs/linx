# 01 — README (top-level)

**Status:** done (commit 70f127f) · **Gates 0.1.0:** yes (publish blocker) · **Topic:** README / hexdocs landing page

## Problem

The README is the hexdocs landing page (`mix.exs` sets `main: "readme"`), and three
spots are written for a *pre-publish* repo:

- **`README.md:15` — Installation** says "Not on Hex yet. Depend on it from Git"
  with `{:linx, github: "oshlabs/linx"}`. The published package would tell visitors
  it isn't published. *(publish blocker H2)*
- **`README.md:142` — Docs** says generated docs "**will be** hosted at
  hexdocs.pm/linx" — future tense, on the page that *is* hexdocs.
- **`README.md:25` — Requirements** never mentions that a **C toolchain is needed
  at build time**, although `mix deps.compile` runs the five custom C compilers
  (`lib/mix/tasks/compile.*.ex`) on the consumer's machine. A missing `cc` yields a
  cryptic failure.

## Decision

Make the README read as a published-package landing page. Scope is deliberately
**install + docs + build prerequisites + a light read-through**. The two other
README touch-points are owned by other topics and edited there so each change stays
atomic:

- The **Errors section** (`README.md:138`, the false "never raw `{:error, :enoent}`"
  promise) → **topic `02`**, alongside the `Mount.list` code fix, so prose and
  contract change together.
- The **exact kernel-floor number** (`README.md:25` says 6.6 LTS; the C syscall
  floor is 5.8) → **topic `06`**, which sets the authoritative supported floor via
  the portability preflight.

Resolved sub-decisions: keep a **tempered** "early days" note; add the C-toolchain
prerequisites **with per-distro install commands**; pin as `{:linx, "~> 0.1"}`.

## Concrete changes

1. **Installation (`:13-23`)** → hex; drop the "Not on Hex yet" line:

   ```elixir
   def deps do
     [
       {:linx, "~> 0.1"}
     ]
   end
   ```

2. **Build prerequisites** — new short block in Requirements (`:25`). The C sources
   need a compiler, the Erlang/OTP headers (`erl_nif.h`, `ei.h` — shipped with your
   Erlang install), and the libc + Linux UAPI headers (pulled in by the meta
   packages below). Proposed copy:

   > **Build prerequisites.** The kernel-interface NIFs and the process Port are
   > compiled from C (`c_src/`) at install time, so a C compiler and headers must be
   > present:
   >
   > - **Debian / Ubuntu:** `sudo apt install build-essential` *(add `erlang-dev`
   >   if you installed Erlang from apt rather than asdf/precompiled)*
   > - **Arch:** `sudo pacman -S base-devel` *(the `erlang` / `erlang-nox` package
   >   already ships the Erlang headers)*
   >
   > `build-essential` / `base-devel` also provide the libc and Linux UAPI headers
   > the sources include.

3. **Temper "early days" (`:11`)** → soften to set 0.x expectations without
   sounding unreleasable, e.g.:

   > ⚠️ **0.x.** The API is still settling; minor releases may include breaking
   > changes until 1.0.

4. **Docs (`:140-142`)** → present tense: docs **are** hosted at
   [hexdocs.pm/linx](https://hexdocs.pm/linx); keep the `mix docs` → `_build/docs/`
   note for local dev.

5. **Light read-through** for landing-page quality; verify the relative
   `docs/<sub>/EXAMPLES.md` links (`:100-120`) resolve as ex_doc extras (they may be
   revisited in `04`/`05`).

## Acceptance check

- `grep -nE "Not on Hex|github: \"oshlabs|will be hosted" README.md` → empty.
- README shows the hex dep, the per-distro build prerequisites, and present-tense
  hexdocs hosting.
- `mix docs` builds; README renders as the landing page with subsystem links
  resolving (no broken extras links in the ex_doc output).

## Risk / scope notes

- Low risk: prose/dep-snippet edits only, no code.
- **Distro package accuracy:** `build-essential` (Debian/Ubuntu) and `base-devel`
  (Arch) reliably provide `cc` + `make` + libc/UAPI headers; the genuine variability
  is the **Erlang headers**, which come from the Erlang install (asdf/kerl/precompiled
  include them; distro-packaged Erlang needs `erlang-dev` on Debian/Ubuntu). The copy
  above calls this out rather than over-promising an exact package set.
- **Cross-topic touch:** the Errors section is finalized in `02`, the kernel-floor
  number in `06`, and the subsystem doc links may shift in `04`/`05`. The final
  hexdocs pass in `11` is the backstop for the rendered result.
