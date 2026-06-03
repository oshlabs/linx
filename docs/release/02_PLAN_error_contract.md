# 02 — Error contract

**Status:** done · **Gates 0.1.0:** yes (README correctness) · **Topic:** error shapes

> **History.** This started as a large "make every kernel failure a `%Linx.X.Error{}`
> struct" effort (originally split `02a`/`02b`, including a full netlink wire-layer
> rewrite — `Socket`/`Request`/`Nfnl`/`Monitor`/`Log` plus a Tank compatibility branch).
> We **scrapped that.** AGENTS.md's own rule is *context-rich* failure → struct; a
> transport hiccup like `{:error, {:send, :eperm}}` is **not** context-rich (it's already
> pattern-matchable and names the failing stage), and wrapping every syscall return in a
> `case` to re-box it violates rule #1 (KISS). The struct-everywhere promise wasn't worth
> the interface churn, so we dropped the promise instead.

## What we changed

### 1. README — deleted the Errors section
The README claimed kernel failures are "never raw `{:error, :enoent}` tuples," which was
false (the wire layer returns staged tuples, and that's *fine*). Error-shape contracts
aren't landing-page material, so the whole `## Errors` section was removed rather than
rewritten.

### 2. Stop raising on bad input → tagged tuples (AGENTS.md rule 3)
These crashed where their peers return tuples; rule 3 says caller-input mistakes stay in
the `{:ok, _} | {:error, _}` world, not `raise`:
- **`Link.create_macvlan/4`, `create_ipvlan/4`** — bad `mode` → `{:error, {:bad_mode, m}}`
  (the `*_mode/1` helpers now return `{:ok, _} | {:error, _}`, threaded with `with`).
- **`Tty.attach/3`** — bad `target` → `{:error, {:bad_target, target}}` (new catch-all
  clause; a non-pid `session` with a valid target stays a guard crash — a type error).
- **`Process.pty_set_winsize/2`** — malformed size → `{:error, {:bad_winsize, bad}}`
  (catch-all clause).
- **`Netfilter.log_listen/2`** — out-of-range `:group` → `{:error, {:bad_group, group}}`
  (validated in `log_listen/2` before `start_link`; the `raise` in `Log.init` removed).

### 3. Bare atom → tagged tuple for input mismatch
- **`Route` / `Rule` family mismatch** — `{:error, :family_mismatch}` →
  `{:error, {:family_mismatch, {got, expected}}}`. Composes through the rtnl reconcile
  wrap unchanged (`build_route` passes the reason opaquely).

## What we deliberately did NOT do
- **No wire-layer struct wrapping.** `{:send,_}`/`{:recv,_}`/`{:socket,_}`/bare-errno from
  `Socket`/`Request`/`Nfnl`/`Monitor`/`Log` stay as informative staged tuples.
- **No `from_posix_atom` builder**, no spec sweep to enforce structs, **no Tank branch**
  (the wire layer's shape didn't change, so Tank is unaffected).
- **`Mount.list`** still returns `{:error, posix}` — it mirrors `File.read`'s own idiomatic
  shape; changing it for within-module symmetry wasn't worth it (KISS).

## Tests
- Updated two assertions for the richer `family_mismatch` tuple (`route_test`,
  `reconcile_test`).
- Added unit tests (all hit validation before any kernel call, so they run in the normal
  suite): `create_macvlan`/`create_ipvlan` bad mode, `attach` bad target,
  `pty_set_winsize` bad size, `log_listen` bad group.

## Verification
- `mix test --exclude integration`: 1013 tests, 0 failures; `mix format --check-formatted`
  clean; `mix compile --warnings-as-errors` clean.
- `./sudotest.sh test/linx/netlink/rtnl/integration_test.exs`: 30 tests, 0 failures (the
  macvlan happy path + family handling against the real kernel are unaffected).
