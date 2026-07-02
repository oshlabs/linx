defmodule Linx do
  @moduledoc """
  Linux kernel-interface primitives for Elixir.

  Linx is a library of **primitives, not a runtime** — low-level Linux
  interfaces exposed as idiomatic Elixir, meant to feel as natural to drive
  from the BEAM as anything in the standard library. A container engine, a
  network orchestrator, or an observability tool is a *consumer* of Linx; the
  runtime concepts live in those projects. See the [README](readme.html) for the
  pitch and a quick start.

  This page is the map of the API surface; each module's own documentation is
  the reference.

  ## Subsystems

  **Process & namespaces**
    * `Linx.Process` — `clone(2)` with namespace flags, `setns(2)`, signals,
      `waitpid(2)`, and stdio plumbing, driven by an external C agent (a Port).

  **Networking**
    * `Linx.Netlink` / `Linx.Netlink.Rtnl` — an `AF_NETLINK` client; rtnetlink
      links, addresses, routes, neighbours, rules, and stats.
    * `Linx.Netfilter` — nf_tables over `NETLINK_NETFILTER`: the `~NFT` sigil and
      pipeline DSL, `push`/`pull`/`diff`, socket-owned tables, a live monitor.

  **Resource control**
    * `Linx.Cgroup` — cgroup v2 via direct `/sys/fs/cgroup` I/O: typed
      memory/pids/cpu limits, freeze/thaw, `%Stats{}` counters.

  **Filesystem**
    * `Linx.Mount` — `mount(2)`, `umount2(2)`, `pivot_root(2)`, bind/remount/
      move, a `/proc/<pid>/mountinfo` parser, and a cross-namespace `:in` option.

  **Identity & security**
    * `Linx.User` — user-namespace uid/gid/setgroups mapping.
    * `Linx.Capabilities` — the five per-thread capability sets as `MapSet`s of
      `:cap_*` atoms.
    * `Linx.Seccomp` — pure-Elixir cBPF syscall filters installed at the
      checkpoint.

  **Tuning**
    * `Linx.Sysctl` — `/proc/sys/` knobs with dot-form keys, per-namespace
      routing, and the same `:in` option as `Linx.Mount`.

  **Value types**
    * `Linx.IP` (+ `Linx.IP.Subnet`) and `Linx.MAC` — domain primitives with
      compile-time sigils that `Inspect` round-trips.

  **Declarative**
    * `Linx.Reconcile` — an opt-in, single-subsystem control loop over the
      `Linx.Reconcile.Source` contract.

  ## The composition

  Linx's value isn't any single subsystem — it's that they all hook into the
  same `Linx.Process` **checkpoint**, the window between `clone(2)` and
  `execve(2)` where the child is parked. Inside that window a workload's
  identity, resource ceiling, network, privileges, and syscall surface are all
  decided at once, before its first instruction. The subsystems are otherwise
  independent and compose because they share that one primitive, not because a
  framework holds them together.

  ## Capability detection

  Subsystems that gate an *optionally-present* kernel feature expose a
  `supported?/0` probe — `Linx.Cgroup`, `Linx.User`, `Linx.Capabilities`,
  `Linx.Seccomp`, `Linx.Sysctl`, and `Linx.Netfilter`. Subsystems built on the
  always-present Linux baseline Linx requires (`Linx.Process`, `Linx.Netlink`,
  `Linx.Mount`, `Linx.Tty`) omit it by design.

  ## Declarative reconciliation

  Several subsystems expose the `pull` / `diff` / `push(mode: :reconcile)` /
  `subscribe` template: describe desired kernel state and converge onto it,
  idempotent and self-healing across drift, crashes, and reboots. `Linx.Reconcile`
  is the thin opt-in loop on top; see `docs/reconcile/reconcile-examples.md`.

  ## Getting started

  The [README](readme.html) has installation and the headline composition;
  each subsystem's `docs/<subsystem>/<subsystem>-examples.md` has runnable, copy-paste
  recipes.
  """
end
