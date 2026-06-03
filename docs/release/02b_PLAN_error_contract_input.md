# 02b — Error contract: input mistakes, raises, specs, README

**Status:** planned · **Gates 0.1.0:** yes · **Topic:** error contract (buckets 2/3, raises, spec sweep, README)

Split from `02`. The cleanup half, on top of `02a` (kernel failures → structs).
Driven by the full error-return audit. Principle (settled with the maintainer):
pre-1.0, with nothing published, **make the code match the contract** rather than
soften the contract.

## Problem

### B — input mistake returned as a bare atom (should be a tagged tuple)
- **B1 — `Route.add/replace/delete/add_default/delete_default/build`** →
  `{:error, :family_mismatch}` (`route.ex:305`). The README *cites*
  `{:error, {:family_mismatch, …}}` as the model tagged form — this is the anti-example.
- **B2 — `Rule.add/2`, `delete/2`** → `{:error, :family_mismatch}` (`rule.ex:193`).
- **B3 (soft) — `Process.spawn`** → `{:error, :argv_required}` (`process.ex:690`) sits
  beside seven `{:bad_*, _}` tuples in the same validation pipeline.

### C — raises on bad input where peer functions return tuples
- **C1 — `Link.create_macvlan/4`, `create_ipvlan/4`** → `FunctionClauseError` on a bad
  `mode` (`link.ex:338-342`).
- **C2 — `Tty.attach/3`** → `FunctionClauseError` on a bad `target` (`tty.ex:355/421`).
- **C3 — `Process.pty_set_winsize/2`** → `FunctionClauseError` on a bad winsize
  (`process.ex:562/569`).
- **C4 — `Netfilter.log_listen/2`** → `ArgumentError` in `init` on a bad `:group`.
- **C5 — `Expr.payload/2`, `dnat_to/3`, `snat_to/3`** → `ArgumentError`
  (`expr.ex:166,480,485`). **Left as-is** — `Expr` is a raise-on-bad-input typed
  builder with no `{:ok, _}` contract; documented as such.

### D — fourth shapes, loose specs, doc nits
- `Tty.attach(:group_leader)` → `{:gl_reader, why}` / `{:gl_reader_exit, reason}`
  wrapping raw OTP reasons (`tty.ex:650,653`) — a shape outside the three buckets.
- `:no_reply` on `Link/Route/Stats.get` — empty reply to a single-object GET.
- Loose `@spec`s: `IP.parse` (`ip.ex:48`), `Subnet.parse` (`subnet.ex:35`), `MAC.parse`
  (`mac.ex:37`) say `{:error, term}` but return tagged tuples.
- `User.setup_maps/2` doc says `{:bad_map,_}` for a missing key; code returns
  `{:bad_setup, {:missing, _}}`.
- **M1 — 87 loose `{:error, term()}` specs** across the marketed subsystems that, after
  `02a`, actually return `%X.Error{}` ∪ specific atoms.

## Decision / approach

**B — convert to tagged tuples:**
- B1/B2: `:family_mismatch` → `{:error, {:family_mismatch, {got, expected}}}` in
  `Route.check_families/2` (`route.ex:305`) and `Rule.pick_family/2` (`rule.ex:193`).
  Verify `Reconcile`'s existing wrap (`reconcile.ex` `{:normalize, {:route, …}}`) still
  composes.
- B3: `:argv_required` → `{:error, {:bad_argv, :required}}` (`process.ex:690`).

**C — convert C1–C4 to tagged tuples; keep C5 as a documented raise-builder:**
- C1: `macvlan_mode/1`/`ipvlan_mode/1` return `{:ok, val} | {:error, {:bad_mode, m}}`;
  `create_macvlan/ipvlan` thread it.
- C2: add an `attach/3` clause returning `{:error, {:bad_target, target}}`.
- C3: `pty_set_winsize/2` returns `{:error, {:bad_winsize, arg}}` for the non-tuple,
  non-`%{rows,cols,xpixel,ypixel}` case.
- C4: validate `:group` before `init`, returning `{:error, {:bad_group, g}}`.
- Keep compile-time sigil raises (`~IP`, `~MAC`) and positional-arg guards (idiomatic).

**D:**
- Tighten the three parser specs to the real tagged shape
  (`{:error, {:bad_address, binary}}`, etc.).
- Fix the `User.setup_maps/2` doc nit.
- **Document** (don't change) `:no_reply` and the `{:gl_reader,_}` shapes — genuinely
  debatable, not worth churn; the `attach/2` spec already covers them under a union.
- **Spec sweep (M1):** replace `{:error, term()}` on the public functions of the
  marketed subsystems (netlink/rtnl, tty, mount, netfilter, cgroup, user, capabilities,
  sysctl) with precise unions reflecting reality, now including the `02a` structs —
  e.g. `{:error, Linx.Netlink.Error.t() | {:family_mismatch, term} | :no_reply}`.
  Leave genuinely-open `term` in internal modules and broad `Reconcile.Source` callbacks.

**README — reconcile the Errors section** (`README.md:138`, deferred from `01`):
after `02a`+B+C, all three buckets are *true* — kernel failures are structs, input
mistakes are tagged tuples, lifecycle conditions are bare atoms. Keep the strong
wording; correct any specific example that no longer matches.

## Concrete changes
- `lib/linx/netlink/rtnl/route.ex`, `rule.ex` — B1/B2.
- `lib/linx/process.ex` — B3, C3.
- `lib/linx/netlink/rtnl/link.ex` — C1.
- `lib/linx/tty.ex` — C2 (+ document the `{:gl_reader,_}` shape).
- `lib/linx/netfilter.ex` / `lib/linx/netfilter/log.ex` — C4.
- `lib/linx/ip.ex`, `ip/subnet.ex`, `mac.ex` — parser specs.
- `lib/linx/user.ex` — doc nit.
- The marketed subsystems — `{:error, term()}` → precise unions (spec-only; non-breaking).
- `README.md` — Errors section.

## Tests
- Assert the new tagged tuples: `Route`/`Rule` family mismatch, `create_macvlan` bad
  mode, `attach` bad target, `pty_set_winsize` bad winsize, `log_listen` bad group,
  `spawn` missing argv.
- `mix compile --warnings-as-errors` clean (no undefined-type warnings from new specs).

## Downstream: Tank compatibility
Same `linx-error-contract` branch as `02a`. Coupling is **low**: Tank calls
`create_macvlan(_, _, _, :bridge)` and `attach(:controlling|:group_leader, _)` with
**valid** mode/target, so the C1/C2 conversions never fire on its paths; it matches
only `:no_local_tty` (lifecycle, unchanged) and uses `{:error, _}` wildcards elsewhere.
**Action:** run Tank's `mix test` + `./sudotest.sh` against updated Linx; fix any test
asserting an old shape; commit + push. Gate is a green Tank suite.

## Acceptance check
- `grep -rn "{:error, :family_mismatch}" lib` → gone.
- No `FunctionClauseError`/`ArgumentError` on the C1–C4 documented bad-input paths
  (tests assert tagged tuples); C5 still raises by design.
- No `{:error, term()}` specs remain on the marketed subsystems' public functions.
- README Errors section matches actual returns; `mix docs` renders cleanly.
- Tank suite green on `linx-error-contract`.

## Risk / scope notes
- Lower risk than `02a`: mostly localized tuples + spec tightening (non-breaking).
- The C conversions change a crash into a tuple — purely additive for well-behaved
  callers; only code that *relied on the crash* (none found, incl. Tank) is affected.
- Final hexdocs read of the rendered specs/errors happens in topic `11`.
