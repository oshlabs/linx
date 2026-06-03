# 08 — `supported?/0` consistency

**Status:** planned · **Gates 0.1.0:** yes (cheap, API-surface clarity) · **Topic:** capability-probe convention

## Problem
`supported?/0` is defined on 6 subsystems and absent on 4, with no documented convention,
so it reads as half-applied (API review M4). The split is actually principled — but
nothing says so, and a consumer can't tell whether an absence is deliberate.

- **Has it** (feature can be disabled / compiled out — a real probe):
  `seccomp` (`seccomp.ex:117`), `cgroup` (`cgroup.ex:85`, `File.exists?` controllers),
  `capabilities` (`capabilities.ex:138`), `user` (`user.ex:104`, `File.exists?` uid_map),
  `netfilter` (`netfilter.ex:159`), `sysctl` (`sysctl.ex:188`, `File.exists?` ostype).
- **Omits it** (mechanism is part of the always-present Linux baseline the library already
  requires at 6.6 LTS): `mount`, `netlink` (+ `rtnl`), `process`, `tty`.
- `nft` (pure-Elixir DSL) and the value types have no kernel feature → N/A.

## Decision (option a)
Make the convention explicit and consistent — **do not** add trivially-`true` probes to
the baseline subsystems.

1. **State the convention once**, in the root `Linx` moduledoc (topic `00`):
   > `supported?/0` is provided by subsystems that gate an *optionally-present* kernel
   > feature — cgroup v2, user namespaces, seccomp, capabilities procfs, nf_tables,
   > sysctl. Subsystems built on the always-present Linux baseline Linx requires
   > (Process, Netlink, Mount, Tty) omit it by design.
2. **Document the omission** with a uniform one-liner in each of the 4 baseline
   subsystems' moduledocs (`Linx.Mount`, `Linx.Netlink`/`Rtnl`, `Linx.Process`,
   `Linx.Tty`), so the absence is visibly intentional.
3. **Normalize the existing 6** for consistency: identical `@doc` phrasing, a `@spec
   supported?() :: boolean()`, and the same side-effect-free cheap-probe style (they're
   already close — mostly `File.exists?` of a procfs marker or a feature probe). No
   behavior change; just align doc + spec + wording.

## Coupling
- `00` (root module) hosts the convention statement; this topic and `00` should agree on
  the wording (write `00` first, or reconcile here).

## Concrete changes
- `lib/linx.ex` — add the convention paragraph (coordinated with `00`).
- `lib/linx/{mount,netlink,process,tty}.ex` (+ `netlink/rtnl.ex`) — uniform "no
  `supported?/0` — baseline mechanism" moduledoc note.
- `lib/linx/{seccomp,cgroup,capabilities,user,netfilter,sysctl}.ex` — align the 6
  `supported?/0` `@doc`/`@spec`/wording; confirm each returns a plain `boolean`.

## Acceptance check
- The 6 `supported?/0` share identical doc phrasing + `@spec ... :: boolean()`.
- The 4 baseline subsystems each carry the uniform omission note.
- The root `Linx` moduledoc states the convention.
- `mix compile --warnings-as-errors` clean; no behavior change (the 6 probes are untouched
  functionally).

## Risk / scope notes
- Docs/spec only; no runtime change. Lowest-risk topic in the release.
- Explicitly **not** adding `supported?/0` to mount/netlink/process/tty — those probes
  would be trivially true, side-effecting, or build-checks (the rejected option b).
