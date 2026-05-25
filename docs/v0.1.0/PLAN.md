# Linx 0.1.0 — release-preparation plan

> Not a per-subsystem `PLAN.md` like the eight in `docs/<subsystem>/`
> that this work will delete. This is a project-wide one-off plan
> covering the path from "eight subsystems shipped on main" to
> "0.1.0 published on Hex." This file deletes itself in the final
> phase.

## Why this branch exists

All eight subsystems ship on main as of `e30ef41`:

  Linx.Netlink, Linx.Process, Linx.Tty, Linx.Cgroup,
  Linx.Mount, Linx.User, Linx.Capabilities, Linx.Seccomp.

`mix test`: 452 plain + 9 doctests, 0 failures.
`./sudotest.sh`: 538 plain + 9 doctests + the kernel-acceptance
integration tests, 0 failures.

What's missing for a first Hex release isn't more features — it's
making sure the library reads as **one** library, not eight
overlapping ones that happen to share a repo. That's the job of
this branch.

## Phases — in order, because each makes the next obvious

  1. **Combined review** — consistency audit across all eight subsystems.
  2. **Docs consolidation** — delete `PLAN.md` + `COVERAGE.md` everywhere;
     promote what's load-bearing to module `@moduledoc`.
  3. **Hardening** — property-based tests, C-code memory audit, error-path
     coverage.
  4. **0.1.0 release** — CI, CHANGELOG, mix.exs polish, Hex publish.

## Phase 1 — Combined review

**Goal:** surface inconsistencies between subsystems before they get
baked into the first Hex release.

### Audit dimensions

| Dimension | What to check |
|---|---|
| **Error struct shapes** | `%Linx.X.Error{}` fields + semantics consistent across Cgroup / Mount / User / Capabilities / Seccomp / Netlink. `from_posix/_` signatures uniform. `defexception` + `message/1` impls present. |
| **Inspect impls** | Compact `#Linx.X<…>` rendering everywhere with meaningful content; no struct-default fallthrough on user-facing types. |
| **Verb naming** | `create/1` vs `open/1` vs `spawn/1` vs `read/1` — same word for the same conceptual operation across subsystems? |
| **Forward-compat** | Unknown-bit / unknown-number handling consistent? Capabilities logs once on unknown bits past `last_cap`; Seccomp returns `:unknown` from `from_number/2`; Mount? Netlink? |
| **Test conventions** | `@describetag :integration` (not `@moduletag`) used everywhere per the memory note `exunit-describetag-not-moduletag`? `sudotest.sh`-friendly? |
| **`@spec` + `@type` coverage** | Every public function spec'd? Internals marked `@moduledoc false`? |
| **Moduledoc shape** | Every subsystem's top-level moduledoc has the same outline: what it is / why / motivating example / status? |
| **Common idioms** | MapSet-of-atoms-at-the-API + raw-bits-on-the-wire used consistently? `:in {:pid, _}` / `:in {:path, _}` shape consistent where cross-namespace? |
| **Post-terminal error atoms** | `Linx.Process` returns three different atoms for "the workload already terminated": `:ended` (`signal/2`), `:already_terminated` (`proceed/1`, `abort/1`), `:session_ended` (`pty_write/2`, `pty_set_winsize/2`). `Linx.Tty.attach/2` adds a fourth — `:session_terminated` (workload exited) plus `:session_ended` (GenServer gone). Unify on one atom across subsystems for the same condition; decide whether "workload terminated, session GenServer alive" and "session GenServer gone entirely" are worth distinguishing at all (probably not — callers rarely care). Atoms ship to external callers, so the unification is a one-shot breaking change — bundle with any other 0.1.0 atom renames before publishing. |

### Deliverable

`docs/v0.1.0/AUDIT.md` (sibling to this file): every inconsistency
found, what it should be, and which subsystem(s) need editing.

Make small fixup commits per dimension. Don't try to land all the
fixes in one mega-commit.

## Phase 2 — Docs consolidation

**Goal:** the per-subsystem `PLAN.md` and `COVERAGE.md` files have
served their purpose. Time to retire them and move what's still
load-bearing into the modules.

### Steps

For each `docs/<x>/` directory (one of the eight subsystems):

  1. **`PLAN.md`** — read it. Extract any *design rationale* that
     consumers would benefit from (the "why" behind a decision)
     into the relevant module's `@moduledoc`. The "what we're going
     to build next" content is git history's job. Delete the file.

  2. **`COVERAGE.md`** — delete. Every row is ✅ now; the README's
     subsystem sections + module docs cover the same surface
     better.

  3. **`EXAMPLES.md`** — keep. Real recipes that don't fit in a
     moduledoc.

  4. **`REFERENCES.md`** — keep. Man-page / kernel-header citation
     hygiene.

Then:

  - Update `mix.exs` `docs.extras` + `groups_for_extras` to drop
    every deleted file.
  - Update `AGENTS.md` to reflect the new convention
    (`EXAMPLES.md` + `REFERENCES.md` only per subsystem).
  - Update the memory note `maintain-living-docs` (it currently
    mentions all four).

### Subsystems to walk through

`docs/netlink/`, `docs/process/`, `docs/tty/`, `docs/cgroup/`,
`docs/mount/`, `docs/user/`, `docs/capabilities/`, `docs/seccomp/`.

Eight directories. Could be one commit per subsystem or one big
"retire PLAN.md + COVERAGE.md" sweep — pick by review burden.

## Phase 3 — Hardening

**Goal:** raise confidence that the library survives malformed
input, kernel oddities, and stress.

Three layers, cheapest-first.

### 3a. Property-based testing (StreamData)

Add `{:stream_data, "~> 1.0", only: :test}` to `mix.exs`.

High-value targets:

  - **Codec round-trips.** `Linx.Netlink.Codec`: every message type
    encode → decode → assert equal. `Linx.Capabilities.Constants`:
    `to_bits(from_bits(n)) == n` for arbitrary u64 masks (modulo
    bits above last_cap). `Linx.Seccomp.Constants`: action u32
    round-trips for every {action, errno} combination.
  - **Parsers eating arbitrary bytes.** `Linx.Capabilities.parse_status/2`
    fed arbitrary `/proc/<pid>/status`-ish strings. `Linx.Mount.list`
    fed arbitrary mountinfo lines. Should never crash; should reject
    cleanly.
  - **Syscall-table invariants.** `Linx.Seccomp.Syscalls`: for each
    arch, no duplicate numbers; every atom round-trips through
    `to_number/from_number`; `all/1` equals the set of forward-map
    keys.

Property tests are cheap to add and routinely catch edge cases
unit tests miss.

### 3b. C-code memory audit

Targets: `c_src/linx_process.c`, `c_src/netlink_socket.c`,
`c_src/linx_tty.c`, `c_src/linx_mount.c`.

  - Add a `scripts/asan.sh` that compiles the C parts with
    `-fsanitize=address -fsanitize=undefined -g -O0` and runs the
    integration suite under sudo.
  - Watch for: leaks in error paths (every `goto cleanup`-style
    path), double-frees in fork/exec, unchecked `errno` use,
    over-reads in ei frame decoding, malloc/free pair mismatches.
  - Document any deliberate one-shot allocations the agent doesn't
    free at exit (since `_exit(_)` recovers everything).

### 3c. Error-path coverage

Most tests hit happy paths. For every errno that surfaces in a
`%Linx.X.Error{}` or `{:linx_process, :error, errno, stage}`:

  - `EACCES` via `chmod 000`.
  - `ENOENT` via reading bogus pids.
  - `EMFILE` via `setrlimit(RLIMIT_NOFILE)`.
  - `EBUSY` (cgroup destroy with members) — already tested.
  - `EPERM` (cap drops without CAP_SETPCAP) — already tested.
  - `EINVAL` (malformed BPF) — already tested via integration.

Document what's hard to test (`ENOMEM` mid-syscall) and accept
the gap.

## Phase 4 — 0.1.0 Hex release

**Goal:** publish.

### Pre-flight

  - [ ] `mix.exs` package metadata: `homepage`, `package: [licenses:
        ["MIT"], links: %{"GitHub" => @source_url}, maintainers:
        [...]]`.
  - [ ] `CHANGELOG.md` at the repo root, starting with the 0.1.0
        entry summarising every subsystem.
  - [ ] `LICENSE` already present (MIT).
  - [ ] README polished for Hex (it's already excellent; minor
        tweaks at most — the headline composition is the right
        opener).
  - [ ] `mix format --check-formatted` clean.
  - [ ] `mix compile --warnings-as-errors` clean.
  - [ ] `mix dialyzer` clean (or known-acceptable warnings
        documented).
  - [ ] `mix credo --strict` reviewed.
  - [ ] `mix hex.audit` passes.

### CI (GitHub Actions)

`.github/workflows/ci.yml`:

  - `mix format --check-formatted`
  - `mix compile --warnings-as-errors`
  - `mix test` (plain — runs on a regular GitHub runner)
  - `mix test --include integration` in a privileged container
    (needed for clone(2) namespace flags, setns, capset, seccomp
    install)
  - Optional: matrix Elixir 1.18 / 1.19, OTP 27 / 28.

### Publish

  - `mix hex.publish`
  - `mix docs && mix hex.docs publish`

### Tag + merge

  - Final cleanup: **delete `docs/v0.1.0/`** (this file and any
    siblings).
  - Commit: "Linx 0.1.0".
  - Merge `v0.1.0` → `main`.
  - Tag `v0.1.0`, push tag.

## Deferred — captured so we don't lose them

To 0.2 or later. Each was in scope at some point during the
foundational work but is correctly out of scope for 0.1.0.

  - **`Linx.Seccomp` per-arg matching** (`allow_if/3` — S1.5).
  - **`Linx.Seccomp` multi-arch routing**.
  - **`Linx.Seccomp` `SECCOMP_USER_NOTIF`** (userspace decision
    handlers).
  - **`Linx.Capabilities.File`** — file capabilities
    (`security.capability` xattrs; `setcap(8)` / `getcap(8)`).
  - **`Linx.Capabilities` securebits** (`SECBIT_*`).
  - **`Linx.Cgroup`** typed setters for less-common controllers
    (`io.max`, `cpuset.cpus`, `memory.swap.max`); event monitoring
    (`memory.events`, OOM); `cgroup.kill` for atomic teardown.
  - **`Linx.Mount` new mount API** (`fsopen` / `fsmount` /
    `open_tree` / `move_mount` / `mount_setattr`); typed parsing
    of `mount_options` / `super_options`.
  - **`Linx.User` `newuidmap(1)` / `newgidmap(1)` integration**
    for unprivileged multi-range maps via `/etc/subuid`
    / `/etc/subgid`.
  - **`Linx.Netlink`** Connection GenServer for concurrent
    in-flight requests; Monitor for multicast event subscription;
    `NETLINK_GENERIC` family; more link kinds (`bond`, `vxlan`,
    `tun`/`tap`).
  - **`Linx.Process` Phoenix LiveView terminal demo** (memory
    note `linx-demo-web-phoenix-liveview`).
  - **Cross-distro testing**: Debian, Ubuntu, Fedora, Alpine — let
    early 0.1.0 users surface distro-specific issues; act on the
    real reports.

## Notes for resuming after context compaction

  - This branch is `v0.1.0`.
  - It branches from `e30ef41` on main (post-seccomp-foundations
    merge + README updates).
  - Phase ordering is **not** flexible — each phase makes the next
    one obvious. Don't skip ahead.
  - The "what's next" section of the README will be re-trimmed in
    Phase 2 as part of docs consolidation.
  - Every per-subsystem `PLAN.md` will be deleted in Phase 2; the
    project-wide one — this file — is deleted in Phase 4. Don't
    delete subsystem PLAN.md until their content has been audited
    for design rationale that should move to moduledocs first.
