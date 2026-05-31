# Linx 0.1.0 — release-preparation plan

> A project-wide, one-off plan — **not** a per-subsystem `PLAN.md` like
> the ten under `docs/<subsystem>/` that this work will retire. It
> covers the path from "all subsystems shipped on main" to "0.1.0
> published on Hex." This file deletes itself in the final phase
> (Phase 4); the per-subsystem `PLAN.md`/`COVERAGE.md` files are
> retired earlier, in Phase 2.

## Why this branch exists

The feature set is done. What's missing for a first Hex release isn't
more features — it's making the library read as **one** library, not
ten overlapping ones that happen to share a repo. That consistency
pass, plus hardening and release mechanics, is the whole job of this
branch.

### Ten subsystems, not eight

The original version of this plan counted **eight** subsystems. Two
more have landed on main since and are first-class throughout:

  - **`Linx.Sysctl`** — `/proc/sys` kernel tunables (NIF; S0–S3 shipped).
  - **`Linx.Netfilter`** — nf_tables firewalling *and* the `~NFT`
    sigil DSL. The **largest** subsystem (~26 `Linx.Netfilter.*`
    modules + 8 `Linx.NFT.*` modules) and the one most likely to harbour
    interface-normalisation issues. First-class in the Phase-1 audit
    and the Phase-3 property-testing work.

The canonical list (use this everywhere — audit, docs sweep, CHANGELOG):

| # | Subsystem | Entry module | Native | Error struct | Notes |
|---|---|---|---|---|---|
| 1 | Netlink | `Linx.Netlink` (+ `Rtnl`, `Nfnl`) | NIF (`netlink_socket.c`) | `Linx.Netlink.Error` | core + rtnetlink + nfnetlink |
| 2 | Process | `Linx.Process` | **Port** (`linx_process.c`) | `Linx.Process.Error` *(to add)* | clone/exec checkpoint |
| 3 | Tty | `Linx.Tty` | NIF (`linx_tty.c`) | `Linx.Tty.Error` *(to add)* | PTY / termios / attach |
| 4 | Cgroup | `Linx.Cgroup` | none (cgroupfs) | `Linx.Cgroup.Error` | v2 unified hierarchy |
| 5 | Mount | `Linx.Mount` | NIF (`linx_mount.c`) | `Linx.Mount.Error` | mount/umount/pivot_root + mountinfo |
| 6 | User | `Linx.User` | none (procfs) | `Linx.User.Error` | uid/gid maps |
| 7 | Capabilities | `Linx.Capabilities` | none (procfs + Process) | `Linx.Capabilities.Error` | 5 cap sets |
| 8 | Seccomp | `Linx.Seccomp` | none (BPF via Process) | `Linx.Seccomp.Error` | cBPF syscall filters |
| 9 | Sysctl | `Linx.Sysctl` | NIF (`linx_sysctl.c`) | `Linx.Sysctl.Error` | `/proc/sys` tunables |
| 10 | Netfilter | `Linx.Netfilter` / `Linx.NFT` | NIF (shared netlink) | `Linx.Netfilter.Error` + `Linx.NFT.ParseError` | nf_tables + `~NFT` sigil |

Plus shared public value types: `Linx.IP`, `Linx.IP.Subnet`,
`Linx.MAC`.

## Branch status

This branch (`polish-v0.1.0`) **is already rebased onto current main**
(`be77478`). The old resume-note claim that it "branches from
`e30ef41`" is stale and superseded by this paragraph. Treat current
`main` as the base.

---

## Decisions locked during planning

These were settled in discussion before Phase 1; the audit *applies*
them, it does not re-litigate them. Recorded here so they survive
context compaction.

### D1 — Post-terminal condition unifies on `:no_process`

Process + Tty return **four** atoms today for "the workload is gone,
you can't do that": `:already_terminated` (`proceed/1`, `abort/1`, cap
commands), `:ended` (`signal/2`), `:session_terminated` (Tty
`attach/2`), and `:session_ended` (`wait/1`, `info/1`, and Tty when the
GenServer is gone).

**Collapse all four into one atom: `{:error, :no_process}`.** Drop the
"workload terminated vs session-GenServer gone" distinction entirely —
callers don't care. `:no_process` is precise: at the parked checkpoint
a process genuinely exists (cloned, parked, pre-`execve`), so the error
only ever fires once the OS process is truly gone. Apply across **both**
Process and Tty in one commit; it's the headline breaking change for
0.1.0 (and breaking is free — no users yet). Note it in the CHANGELOG.

### D2 — Error model: context-richness decides the shape

The axis is **how much context the error carries**, not caller-vs-kernel.
Three lanes, applied uniformly across all ten subsystems:

  1. **Context-rich kernel/syscall failure → `%Linx.X.Error{}`.**
     Every error struct **implements the `Exception` behaviour** so
     `Exception.message/1` is the one uniform way to render any Linx
     error as a human string (the strongly-endorsed Elixir-y form —
     see Redix/Postgrex/Mint/Ecto/NimbleOptions and the Elixir
     anti-patterns doc). Uniform **core fields: `operation` + `errno` +
     `code`**, always present. Optional **honest extras** only where
     genuinely non-nil: `path` (filesystem/procfs subsystems),
     `message` (kernel extended-ack string), and subsystem-specifics
     (e.g. Netfilter's `subsys`/`batch_seq`/`attr_offset`). No padding
     a struct with fields that are forever `nil`.
  2. **Context-free condition → bare atom.** Carries nothing to attach,
     so a struct would be empty ceremony. `:no_process` is the
     canonical example (cf. stdlib `File`'s `{:error, :enoent}`,
     `:gen_tcp`'s `{:error, :closed}`, Redix's reason atoms).
  3. **Caller validation → tagged tuple `{:error, {:bad_*, reason}}`.**
     Do **not** raise `ArgumentError` here even though the official doc
     permits it for pure programmer errors — Linx's "bad" inputs are
     usually *dynamic runtime data* (a uid-map list, an `~NFT` string,
     a parsed flag set), so staying in the `{:ok,_}/{:error,_}` world
     keeps them composable in `with`.

Consequences for the audit:
  - **Add `Linx.Process.Error` and `Linx.Tty.Error`** (Family-B shape:
    `operation`/`errno`/`code`, no `path`). Process's async mailbox
    errors become `{:linx_process, :error, %Linx.Process.Error{}}`
    (keep the `stage` field name — it carries real clone→exec meaning;
    it *is* the `operation`). Tty's NIF `{:error, {:stage, errno}}`
    becomes `%Linx.Tty.Error{}`.
  - **Add `:operation` to `Linx.Netlink.Error`** (it lacks one today; a
    netlink error always comes from a specific request type). Align its
    `from_errno/2` constructor with the `from_posix` family naming.
  - This is the de-facto convention to codify in `AGENTS.md`.

### D3 — Inspect: minimal for 0.1.0; the clever bits get their own plan

  - **0.1.0:** add plain **summary** `Inspect` to the container structs
    that fall through to default today — Netfilter `Table`, `Chain`,
    `Set`, `Map`, `Ruleset`, `Flowtable`, `Object` (e.g.
    `#Linx.Netfilter.Ruleset<2 tables, 8 chains, 240 rules>`) — and to
    `Seccomp.Builder`. Leaf structs (`Rule`/`Verdict`/`Expr`) keep
    their existing content-showing impls. House rule: **summarise
    containers, show leaves.**
  - **Deferred to a separate plan:** rendering `inspect(ruleset)` as its
    round-trippable `~NFT"""..."""` source (elegant — `~NFT` is valid
    Elixir — but needs a fallback for rulesets using features the
    formatter emits as `# <unsupported>` comments), `~NFT.Chain` /
    `~NFT.Rule` sub-sigils, and whether `Linx.NFT` folds into
    `Linx.Netfilter`. Capture these in **`docs/netfilter/DESIGN.md`** —
    a *new* forward-looking doc, explicitly **not** swept up by the
    Phase-2 consolidation. Post-0.1.0 scope.

### D4 — Docs: slim README, migrate depth into code, three doctest lanes

  - **Root `README.md` shrinks to the standard Elixir shape:** what it
    is, install, a brief per-subsystem blurb each linking to its module
    docs, the headline composition, status + license. The ~62 KB of
    depth currently inlined migrates *into* the moduledocs, where ExDoc
    renders it as first-class API documentation.
  - **Doctest policy — three lanes** (this is how the root/non-root
    split is handled under `mix test`):
      1. **Pure, verifiable examples → real doctests, *with* `iex>`
         prefixes** (the documented exception to the no-`iex>`-prefix
         house style). Run under plain `mix test`, CI-verified.
         Candidates: `Linx.NFT.parse`/`format`, `Netlink.Codec`
         round-trips, `Linx.IP`/`Subnet`/`MAC`, the `Constants`
         round-trips, `Mount.parse_mountinfo(sample)`,
         `Capabilities.parse_status(sample)`.
      2. **Root-requiring / side-effecting examples → plain code blocks,
         *no* `iex>` prefix.** A block without the prompt is not
         collected as a doctest, so `mix test` never runs it; ExDoc
         still renders it (and it stays paste-friendly). This makes the
         root/non-root problem vanish — you can't fail a test you never
         generated.
      3. **Verified root *behaviour* → the integration suite**
         (`@describetag :integration`, run via `./sudotest.sh`), not
         doctests.
  - **External markdown per subsystem after consolidation:** keep
    **`EXAMPLES.md`** (big multi-subsystem recipes) **and**
    **`REFERENCES.md`** (man-page / kernel-header bibliography). Delete
    `PLAN.md` and `COVERAGE.md` (and `netfilter/TODO.md`).

### Open — deferred decisions

  - **Elixir / Erlang version floor.** `mix.exs` currently pins
    `elixir: "~> 1.19"` (bleeding edge). Whether to lower it for reach
    is deferred — decide during Phase 4.

---

## Phases — in order, because each makes the next obvious

  1. **Combined review** — consistency audit across all ten subsystems
     (applies D1–D2).
  2. **Docs consolidation** — retire `PLAN.md` + `COVERAGE.md`
     everywhere; promote rationale into `@moduledoc` (applies D4).
  3. **Hardening** — property-based tests, C memory audit, error-path
     coverage.
  4. **0.1.0 release** — CI, CHANGELOG, mix.exs polish, Hex publish
     (resolves the version-floor open question).

Phase ordering is **not** flexible. Don't skip ahead.

---

## Phase 1 — Combined review

**Goal:** apply D1–D2 and surface/fix any remaining inconsistencies
between subsystems before they get baked into the first Hex release.
Atoms, error shapes, and verb names ship to external callers — fixing
them is a one-shot breaking change, so it happens *before* publish.

**Deliverable:** `docs/v0.1.0/AUDIT.md` (sibling to this file): every
inconsistency found, what it should be, and which subsystem(s) need
editing. Make small fixup commits per dimension — not one mega-commit.

**Execution note:** this phase runs as a **deep multi-agent sweep**
(parallel readers per subsystem × dimension → synthesis into
`AUDIT.md` → per-dimension fixup commits). That's a token-heavy
workflow and an explicit opt-in — confirm before launching.

### Audit dimensions

| Dimension | What to check |
|---|---|
| **Error struct shapes** | Apply **D2**: uniform core `operation`/`errno`/`code` + `Exception` impl on every `%Linx.X.Error{}`; `path`/`message`/extras only where non-nil. Add `operation` to `Netlink.Error`. |
| **New error structs** | Apply **D2**: add `Linx.Process.Error` + `Linx.Tty.Error`; migrate Process's async mailbox tuple and Tty's `{:stage, errno}` onto them. |
| **Error constructor naming** | Unify on `from_posix`; reconcile Netlink's `from_errno/2` (wire int) with the atom-based `from_posix/N` family. Keep arity differences only where the extra context (e.g. Sysctl's `:key`) is real. |
| **`defexception` + `message/1`** | Present + parallel wording on every error struct: `"<subsys> <op> failed on <path>: <errno> (errno N)"`. |
| **Post-terminal atoms** | Apply **D1**: collapse to `{:error, :no_process}` across Process + Tty. |
| **Inspect impls** | Apply **D3**: summary Inspect on Netfilter containers + `Seccomp.Builder`; leaves unchanged. |
| **Verb naming** | `open` (sockets), `create`/`create_*` (cgroup, links), `spawn` (process), `add`/`delete` (addresses/routes/neighbours/rules), `build`/`push`/`pull`/`diff` (netfilter). Same word for the same op? `supported?/0` idiom — confirm naming parity across the seven that have it. |
| **Validation-vs-kernel split** | Apply **D2 lane 3**: caller mistakes → `{:error, {:bad_*, reason}}`; verify tuple shapes are predictable and documented as intentional. |
| **Forward-compat / unknown handling** | Four strategies today (silent-drop, keep-raw-bytes, `:unknown` sentinel, log-once). Decide the right one *per situation* and document the rule. |
| **Test conventions** | `@describetag :integration` for mixed files (per memory `exunit-describetag-not-moduletag`); `@moduletag` only in dedicated all-integration files. Fix Cgroup's `cgroup_test.exs` (`async: true` + `@moduletag`). Process/Tty have no integration tag — add where a test touches the kernel. |
| **`@spec` + `@type` coverage** | Every public function spec'd; internals `@moduledoc false`. |
| **Moduledoc shape** | Same outline everywhere: what / why / motivating example / status. Netlink is the laggard (sparse top-level + entry modules, no inline examples). |
| **Common idioms** | MapSet-of-atoms at the API + raw bits on the wire; the `:in {:pid,_}`/`{:path,_}`/`:self` cross-namespace option (Mount + Sysctl share it — confirm parity elsewhere). |

### Per-subsystem Phase-1 checklists

> Tick these off in `AUDIT.md`. ✎ = concrete fix identified during
> planning; ⚲ = verify-only (likely already fine).

**1. Netlink** — the moduledoc laggard + error-shape outlier.
  - ✎ Add `:operation` to `Netlink.Error`; reconcile `from_errno/2`
    with the `from_posix` family naming (D2).
  - ✎ Bring `Linx.Netlink`, `Rtnl`, `Nfnl` moduledocs to the house
    shape; add inline examples to resource modules (Link/Address/…).
  - ⚲ Verify unknown-attr / unknown-`LinkInfo`-kind handling matches
    the documented forward-compat rule.
  - ⚲ `rtnl/integration_test.exs` `@moduletag` — fine if all-integration.
  - ⚲ Verb-naming review across Link/Address/Route/Neighbour/Rule.

**2. Process** — D1 + D2 headliner.
  - ✎ Collapse terminated atoms to `:no_process` (D1).
  - ✎ Add `Linx.Process.Error`; move async mailbox errors to
    `{:linx_process, :error, %Linx.Process.Error{}}` (keep `stage`).
  - ⚲ `@spec` coverage on all public verbs.
  - ⚲ `Process.Info` Inspect already present — confirm fields.

**3. Tty** — D1 + D2 partner.
  - ✎ Apply `:no_process` to `attach/2` (D1).
  - ✎ Add `Linx.Tty.Error`; migrate `{:error, {:stage, errno}}` onto it.
  - ⚲ Confirm `Tty.Saved` / `Tty.WindowSize` Inspect + specs.

**4. Cgroup**
  - ✎ `cgroup_test.exs`: `@moduletag :integration` on an `async: true`
    mixed file → convert to `@describetag`.
  - ⚲ `enable_controllers/2` → `{:partial, failures}` is an intentional
    outlier; document, don't "fix."
  - ⚲ Error shape (the `path` family reference) + `from_posix/3` +
    `message/1` parity.

**5. Mount**
  - ⚲ Error shape — reference for the `path` family.
  - ⚲ `:bad_flag`/`:bad_in` — canonical validation-split example (D2).
  - ⚲ `mount/4` returning three error shapes — confirm documented.

**6. User**
  - ⚲ Error shape + `User.Map` range Inspect — already good.
  - ⚲ Validation tuples (`:bad_map`/`:bad_setup`/`:bad_setgroups`).

**7. Capabilities**
  - ⚲ Log-once-on-unknown-bits — document as the chosen forward-compat
    strategy for bitmask growth.
  - ⚲ `Constants.to_bits/from_bits` faithful within known bits (lossy
    above `last_cap` — note for Phase 3).
  - ⚲ `State` count-only Inspect + Error shape.

**8. Seccomp**
  - ⚲ Error shape (no `path`) — confirm justified under D2.
  - ✎ Add summary `Inspect` to `Seccomp.Builder` (mirror `Filter`'s) (D3).
  - ⚲ `Syscalls.from_number/2` → `:unknown`; round-trip invariants for
    Phase 3.

**9. Sysctl** — newly first-class.
  - ⚲ Error shape (`path` family + `:key`) + `from_posix/4`.
  - ⚲ `:in` cross-namespace option matches Mount exactly.
  - ⚲ Key-validation regex blocks traversal — flag for Phase 3 fuzzing.
  - ✎ Ensure Sysctl appears in the README subsystem list + CHANGELOG.

**10. Netfilter + `~NFT`** — the big one.
  - ✎ Add summary `Inspect` to `Table`/`Chain`/`Set`/`Map`/`Ruleset`/
    `Flowtable`/`Object` (D3); leaves unchanged.
  - ⚲ `Netfilter.Error` rich shape — confirm the extra fields are
    justified honest-extras under D2.
  - ⚲ `NFT.ParseError` caret rendering — confirm parity with Elixir-style
    errors.
  - ⚲ Validation tuples (`:bad_table`/`:bad_chain`) parity.
  - ✎ Fold `docs/netfilter/TODO.md` Tier-1 blockers into Deferred (below);
    open `docs/netfilter/DESIGN.md` for the deferred Inspect/sigil/
    namespace work (D3).
  - ⚲ Flag parse→compile→format round-trip + "never crash" for Phase 3.

---

## Phase 2 — Docs consolidation

**Goal:** apply **D4**. Retire the per-subsystem `PLAN.md`/`COVERAGE.md`;
slim the README; migrate depth into moduledocs as doctests where pure.

### Per `docs/<x>/` directory (all ten)

  1. **`PLAN.md`** — extract design *rationale* a consumer benefits from
     into the relevant `@moduledoc`; "what's next" is git history's job;
     delete the file. (Netlink's 442 lines, Netfilter's 1702, Tty's 1087
     carry the most salvageable rationale.)
  2. **`COVERAGE.md`** — delete. Every row is shipped; README sections +
     module docs cover the surface better.
  3. **`EXAMPLES.md`** — keep (multi-subsystem recipes).
  4. **`REFERENCES.md`** — keep (citations).

### Netfilter's extra files

  - `docs/netfilter/TODO.md` (183 lines) — its Tier-1 blockers are 0.2+
    scope; move them into the Deferred section here, then delete it.
  - `docs/netfilter/DESIGN.md` — **new**, created in Phase 1 for the
    deferred `~NFT`-Inspect / sub-sigil / namespace work (D3). **Not**
    deleted — it's the post-0.1.0 design doc.

### Docs-into-code (D4)

  - Migrate the README's per-subsystem depth into moduledocs.
  - Convert pure examples to `iex>` doctests; leave root/side-effecting
    examples as prefix-less code blocks; keep verified root behaviour in
    `@describetag :integration` tests. (See D4's three lanes.)
  - Slim root `README.md` to the standard shape.

### Then

  - Update `mix.exs` `docs.extras` + `groups_for_extras` to drop every
    deleted file (all ten subsystems' `PLAN.md`/`COVERAGE.md` +
    `netfilter/TODO.md`); add `netfilter/DESIGN.md`. With `PLAN`/
    `COVERAGE` gone, the per-subsystem "— design" groups collapse to
    just `REFERENCES.md` — re-think the `groups_for_extras` IA (e.g.
    per-subsystem "Guides" = EXAMPLES, a single "References" group).
  - Update `AGENTS.md`: docs convention is now `EXAMPLES.md` +
    `REFERENCES.md` per subsystem.
  - Update memory note `maintain-living-docs` (drop PLAN/COVERAGE).

Pick granularity by review burden. Don't delete a subsystem's `PLAN.md`
until its rationale has been audited into moduledocs first.

---

## Phase 3 — Hardening

**Goal:** raise confidence the library survives malformed input, kernel
oddities, and stress. Three layers, cheapest first.

### 3a. Property-based testing (StreamData)

Add `{:stream_data, "~> 1.0", only: :test}` to `mix.exs`. Targets:

  - **Netlink `Codec`** — every message type encode → decode → equal.
  - **Netfilter `~NFT`** (highest-value) — parse → compile → format →
    re-parse yields a structurally equivalent ruleset; tokenizer/parser/
    compiler **never crash** on arbitrary input (always `ParseError`).
  - **Capabilities `Constants`** — `to_bits(from_bits(n))` faithful for
    arbitrary u64 masks *modulo bits above `last_cap`* (deliberately
    lossy there).
  - **Seccomp `Constants`** — action u32 round-trips per `{action,errno}`.
    **`Seccomp.Syscalls`** — per arch: no dup numbers; every atom
    round-trips `to_number`/`from_number`; `all/1` == forward-map keys.
  - **Parsers on arbitrary bytes** (never crash; reject cleanly):
    `Capabilities.parse_status/2`, `Mount.parse_mountinfo/1`,
    `User.parse_map/1`, `Sysctl` key validation.

### 3b. C memory audit

Five C units (the original plan listed four — `linx_sysctl.c` was missing):

  - `c_src/linx_process.c` (Port) — fork/exec fd leaks, CLOEXEC, the
    `free_request`/`free_str_array` pairs, the BPF seccomp-blob
    malloc/free, `report_error` pre-exec paths.
  - `c_src/netlink_socket.c` (NIF) — ei frame decode over-reads,
    malloc/free pairing.
  - `c_src/linx_tty.c` (NIF) — minimal alloc; errno→atom switch coverage.
  - `c_src/linx_mount.c` (NIF) — setns-on-throwaway-pthread teardown,
    error-path frees.
  - `c_src/linx_sysctl.c` (NIF) — same setns-pthread pattern; audit alike.

Add `scripts/asan.sh`: compile with `-fsanitize=address
-fsanitize=undefined -g -O0`, run the integration suite under sudo.
Watch `goto cleanup` error paths, fork/exec double-frees, unchecked
`errno`. Document deliberate one-shot allocations not freed before
`_exit`.

### 3c. Error-path coverage

For every errno surfacing in a `%Linx.X.Error{}` or
`{:linx_process, :error, %Linx.Process.Error{}}`:

  - `EACCES` via `chmod 000`; `ENOENT` via bogus pids / nonexistent
    sysctl keys; `EMFILE` via `setrlimit(RLIMIT_NOFILE)`.
  - `EBUSY` (cgroup destroy with members), `EPERM` (cap drops without
    `CAP_SETPCAP`), `EINVAL` (malformed BPF) — already tested.

Document what's hard to test (`ENOMEM` mid-syscall) and accept the gap.

---

## Phase 4 — 0.1.0 Hex release

**Goal:** publish.

### Pre-flight

  - [ ] Resolve the **Elixir/Erlang version floor** open question; set
        `elixir:` accordingly in `mix.exs`.
  - [ ] `mix.exs` package metadata (**currently absent**): `package:
        [licenses: ["MIT"], links: %{"GitHub" => @source_url},
        maintainers: [...]]` + `homepage`/`source_url`.
  - [ ] `CHANGELOG.md` at repo root — 0.1.0 entry summarising all ten
        subsystems + the `:no_process` breaking change (D1).
  - [ ] `LICENSE` present (MIT). ✓
  - [ ] README polished for Hex; Sysctl + Netfilter represented.
  - [ ] `mix format --check-formatted` clean.
  - [ ] `mix compile --warnings-as-errors` clean.
  - [ ] `mix dialyzer` clean (or documented known-acceptable warnings).
  - [ ] `mix credo --strict` reviewed.
  - [ ] `mix hex.audit` passes.

### CI (GitHub Actions) — `.github/workflows/ci.yml`

  - `mix format --check-formatted`
  - `mix compile --warnings-as-errors`
  - `mix test` (plain — regular runner; runs pure doctests + unit tests)
  - `mix test --include integration` in a privileged container (clone(2)
    namespace flags, setns, capset, seccomp install, nft batches)
  - Optional: matrix Elixir 1.18/1.19, OTP 27/28 (per the floor decision).

### Publish

  - `mix hex.publish`
  - `mix docs && mix hex.docs publish`

### Tag + merge

  - Final cleanup: **delete `docs/v0.1.0/`** (this file + `AUDIT.md`).
    Keep `docs/netfilter/DESIGN.md`.
  - Commit: "Linx 0.1.0".
  - Merge `polish-v0.1.0` → `main`. Tag `v0.1.0`, push tag.

---

## Deferred — captured so we don't lose them (0.2+)

  - **`Linx.Netfilter` / `~NFT`** — round-trippable `~NFT`-rendering
    Inspect, `~NFT.Chain`/`~NFT.Rule` sub-sigils, `NFT`↔`Netfilter`
    namespace integration (all → `docs/netfilter/DESIGN.md`). Plus the
    old `TODO.md` Tier-1 blockers: `limit rate`, `meta FIELD set` /
    `ct … set`, named objects, flowtables, concatenated set/map keys,
    NPTv6, `include` substitution, the `nftables.conf` codec + `mix
    format` plugin.
  - **`Linx.Seccomp`** — per-arg matching (`allow_if/3`), multi-arch
    routing, `SECCOMP_USER_NOTIF`.
  - **`Linx.Capabilities`** — file capabilities (`security.capability`
    xattrs; `setcap`/`getcap`); securebits (`SECBIT_*`).
  - **`Linx.Cgroup`** — typed setters for less-common controllers
    (`io.max`, `cpuset.cpus`, `memory.swap.max`); event monitoring
    (`memory.events`, OOM); `cgroup.kill`.
  - **`Linx.Mount`** — new mount API (`fsopen`/`fsmount`/`open_tree`/
    `move_mount`/`mount_setattr`); typed `mount_options`/`super_options`.
  - **`Linx.User`** — `newuidmap(1)`/`newgidmap(1)` for unprivileged
    multi-range maps via `/etc/subuid`/`/etc/subgid`.
  - **`Linx.Netlink`** — Connection GenServer for concurrent in-flight
    requests; Monitor for multicast events; `NETLINK_GENERIC`; more link
    kinds (`bond`, `vxlan`, `tun`/`tap`).
  - **`Linx.Process`** — Phoenix LiveView terminal demo (memory note
    `linx-demo-web-phoenix-liveview`).
  - **Cross-distro testing** — Debian, Ubuntu, Fedora, Alpine.

---

## Progress tracker (live — update as work lands)

**Phase 1 — Combined review: ✅ COMPLETE.** `AUDIT.md` written (114
findings) and annotated with outcomes. All fixups shipped on
`polish-v0.1.0`:
  - D1 `:no_process` collapse (Process + Tty, incl. tests + docs).
  - D2 error model: added `Linx.Process.Error` + `Linx.Tty.Error`;
    `@impl Exception` on `Netlink.Error`; uniform `{:bad_*, _}`
    validation tuples in Process; `Netlink.Error` keeps no `:operation`
    (option c, documented). D3 summary `Inspect` on Netfilter containers
    + `Seccomp.Builder`. Seccomp `:bad_rules_arg` → `:bad_rules`.
  - Bonus fix: `Linx.MAC.decode/1` no longer crashes on a non-6-byte
    link-layer address.
  - Decided NOT to do: `supported?/0` parity (noise on always-present
    subsystems); Netfilter verb renames (→ `DESIGN.md`). The audit's
    `@spec` dimension over-reported — 5 of 6 were already covered.

**Phase 2 — Docs consolidation: 🟡 IN PROGRESS.**
  Done:
  - Retired all ten `PLAN.md` + `COVERAGE.md` + `netfilter/TODO.md`;
    promoted the two genuinely-absent rationales (Mount classic-API,
    Sysctl "not a config applier"). All dangling refs fixed; `mix.exs`
    docs IA reworked; `maintain-living-docs` memory updated;
    `docs/netfilter/DESIGN.md` created.
  - Netlink entry moduledocs (`Netlink`/`Rtnl`/`Nfnl`) brought to the
    what/why/example/status shape (the audit's lone laggard).
  - `## Forward compatibility` sections added (Mount, Cgroup, User,
    Sysctl, Seccomp; Capabilities already had one).
  - **`mix format` the whole tree** (it had never been format-clean) —
    isolated commit + `.git-blame-ignore-revs`. The Phase-4
    `--check-formatted` gate now passes.
  - **README slim** ✅ — 62 KB → ~10.7 KB. Kept the tagline +
    "primitives, not a runtime" framing + headline composition + install
    + license; the ten per-subsystem walkthroughs collapsed to a 1–3
    sentence blurb each (deep recipes now live in the moduledocs /
    `EXAMPLES.md`); added a short "Errors" section reflecting the D2
    convention; fixed the stale `PLAN.md`/`COVERAGE.md` doc-IA mentions.
    `LICENSE` added to `mix.exs` `extras` (titled "License") — its
    `mix docs` page now generates and the README link resolves.
  - **Netlink resource-module examples** ✅ — added a `## Example` block
    (house 4-space, prefix-less illustrative shape; output comments match
    each module's verified `Inspect`) to `Link` / `Address` / `Route` /
    `Neighbour` / `Rule`. The entry modules (`Netlink`/`Rtnl`/`Nfnl`)
    already had theirs.
  Remaining:
  - Optional forward-compat notes for Netlink's codec + Process/Tty's
    version-locked agent protocol (low priority; can fold into Phase 4).

  **Phase 2 is effectively complete** — only the optional forward-compat
  notes above are left, and they're not gating.

**Phase 3 — Hardening: 🟡 IN PROGRESS.**
  Done:
  - **StreamData property tests** added (`{:stream_data, "~> 1.0",
    only: :test}`):
    - Value types (`5487d19`): `Linx.IP` / `MAC` byte + string round-trips
      and family tagging; `Subnet` parse round-trip + contains?/network/
      broadcast invariants; `Netlink.Attr` TLV round-trip + 4-byte
      alignment; `Stats.Link64` counter round-trip + trailing-byte / short-
      layout tolerance.
    - NFT + sysctl (`c56febb`): a **generative** `~NFT` round-trip
      (random rulesets → parse/format/parse identity + format idempotence;
      complements the curated `golden_test.exs`), and sysctl key
      validation (well-formed never `:bad_key`; traversal/illegal always
      `:bad_key`).
  - **First real bug found + fixed** (`c56febb`): the NFT tokenizer
    misread a digit-led first IPv6 hextet ending in `d` (e.g. `830d:…`)
    as the time literal "830 days" (`d` is the only time unit that's also
    a hex digit). Fixed + deterministic regression test + CHANGELOG entry.
  Remaining:
  - C ASan/UBSan pass on the five NIFs (coupled to the CI privileged-job
    decision — needs the integration suite running).
  - Error-path coverage (force `%X.Error{}` / tagged-tuple branches:
    ESRCH/ENOENT/EPERM, malformed kernel responses).
  - Optional further properties: the `Netlink.Codec` message round-trips,
    seccomp filter `from_rules`/`to_rules`, the mountinfo parser.

**Phase 4 — Release: ⬜ NOT STARTED.** Known open items:
  - ✅ **Version floor decided.** `mix.exs` now pins `elixir: "~> 1.15"`
    (was `~> 1.19`, which was just the dev box — a feature scan found no
    stdlib usage past ~1.15). The real binding constraint is **OTP ≥ 26**,
    forced by `Linx.Tty.attach(:group_leader)`'s `:prim_tty` internals
    (`disable_reader`/`enable_reader` + the `:sys.replace_state` output-mode
    flip); 1.15 is the oldest Elixir that supports OTP 26. mix.exs can't
    express an OTP floor, so it lives in the README "Requirements" note +
    must be CI-enforced. CI matrix (still TODO): `elixir {1.15, latest} ×
    otp {26, latest}`, and **only the latest-Elixir cell runs
    `mix format --check-formatted`** (formatter output is version-sensitive
    — running the check on the 1.15 cell would fail spuriously against code
    formatted on 1.19). ✅ `.tool-versions` added (erlang 28.5.0.1, elixir
    1.19.5-otp-28 — matched majors; suite green on this combo) pinning the
    dev/format toolchain so contributors format identically. NB: the asdf
    `-otp-28` suffix is the OTP the Elixir build was *compiled against*, not
    a hard runtime requirement — but pin a matched pairing rather than
    relying on BEAM backward-compat (1.19 on OTP 29 works but is off
    Elixir's support matrix; the OTP-29 build is 1.20-rc). Kernel floor
    (6.6 LTS, target 6.12) is also in the README Requirements note now.
  - Note: `mix format --check-formatted` is genuinely green again as of
    `2066ffc` — a quoted-atom miss in `mix.exs` (`{:"LICENSE", ...}` →
    `{:LICENSE, ...}`) had slipped in with the README slim. When checking
    formatting, read the command's exit code directly — don't pipe it
    through `tail`, which masks the failure.
  - ✅ **`package:` metadata + `CHANGELOG.md` added** (`d5fb193`).
    licenses/links/maintainers + a `files:` list that ships `lib` + `c_src`
    (the NIF compilers under `lib/mix/tasks/compile.*.ex` build the `.c`
    sources on the consumer's machine; `priv/` artifacts are per-machine and
    never shipped; `docs/` extras omitted to stay lean). Validated with
    `mix hex.build` — tarball = lib + 5×c_src + mix.exs + README + LICENSE +
    CHANGELOG, nothing else. CHANGELOG is also a `mix docs` extra.
  - ✅ **`mix compile --warnings-as-errors` is clean** (`a75fa32`). The
    three clause-grouping warnings (`netfilter/encoder.ex`,
    `nft/compiler.ex`, `nft/formatter.ex`) were fixed by relocating the
    wedged helper functions out from between clause groups (behavior-
    preserving; suite green). This gate is ready for CI.
  - `--check-formatted` already passes (done in Phase 2).
  - ✅ **CI workflow added** (`.github/workflows/ci.yml`). Triggers:
    `pull_request` + `push` to main (feature-branch pushes don't fire
    until a PR opens). Matrix: elixir/otp `1.15/26` (floor), `1.17/27`
    (mid), `1.19/28` (dev pin). Each cell runs `mix deps.get`, compile
    `--warnings-as-errors`, and `mix test --warnings-as-errors`; the
    format check runs only on the latest cell (version-sensitive output).
    README has the CI badge (renders once the repo goes public). The 147
    `:integration` tests (excluded by default in `test_helper.exs`) are a
    **planned follow-up privileged job** — runner-kernel support TBD.
  - `mix docs` emits a handful of benign auto-link warnings — ExDoc
    trying to resolve backtick code spans as references: hidden modules
    (`Linx.Seccomp.Constants`/`Syscalls`), a not-yet-existent
    `Linx.Tty.openpt/0` and `Set.new!/2`, and `:prim_tty.*` Erlang refs
    in `docs/tty/EXAMPLES.md`. Pre-existing; quiet them (escape or
    rephrase) before the release docs build if we want a clean run.

## Notes for resuming after context compaction

  - Branch `polish-v0.1.0`, already rebased onto current `main`
    (`be77478`). Ignore the old "branches from `e30ef41`" note.
  - **Ten** subsystems, not eight — Sysctl and Netfilter are first-class.
  - **D1–D4 are locked** (see "Decisions locked during planning"). The
    audit applies them; it does not re-debate them.
  - Phase ordering is **not** flexible.
  - Phase 1 produces `docs/v0.1.0/AUDIT.md` as a deep multi-agent
    sweep (token-heavy opt-in — confirm before launching). Atom/error/
    verb renames are breaking and land before publish.
  - Phase 2 deletes every per-subsystem `PLAN.md` + `COVERAGE.md` (+
    `netfilter/TODO.md`) — but only after rationale moves into
    moduledocs. `docs/netfilter/DESIGN.md` is kept; this file deletes
    itself in Phase 4.
  - The error-shape convention (D2) is mirrored into `AGENTS.md`.
