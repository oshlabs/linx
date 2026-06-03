# Linx.Process

`Linx.Process` spawns a Linux workload through the **checkpoint**: the window
between `clone(2)` and `execve(2)` where the child is parked — fully created but
not yet running — so every other subsystem can configure it before its first
instruction.

## Overview

A plain `fork`+`exec` gives you no moment to act between "the process exists" and
"the program is running". `Linx.Process` opens exactly that moment. It `clone(2)`s
a child with the namespace flags you ask for, drives it through a small external C
*agent* — a Port, never a NIF, because `clone()`/`unshare()` inside the
multithreaded BEAM would corrupt the VM — and **parks** it at the checkpoint. Only
when you call `proceed/1` does the child `execve` the real workload.

## Where it fits

The checkpoint is the seam the rest of Linx hooks into. While the child is parked,
you reach into it from the host:

- `Linx.User` writes uid/gid maps (the rootless "root inside ↔ me outside" trick).
- `Linx.Cgroup` places it under a memory / cpu / pids ceiling.
- `Linx.Netlink.Rtnl` moves a network interface into its netns.
- `Linx.Capabilities` and `Linx.Seccomp` shrink its privileges and syscall surface.

Identity, resources, network, privilege, and syscalls are all decided *at once*,
before `execve` — so the workload's first instruction already runs fully
constrained. A container engine or network orchestrator is a *consumer* that
sequences these around the checkpoint; `Linx.Process` only provides the moment.

## Flow

```mermaid
flowchart TD
    spawn["Process.spawn/1"] -->|"clone(2) + namespace flags"| parked["child parked at the checkpoint<br/>(created, not yet exec'd)"]
    parked --> setup["host-side setup, all at once:<br/>User · Cgroup · Netlink · Capabilities · Seccomp"]
    setup --> proceed["Process.proceed/1"]
    proceed -->|"execve(2)"| running["workload running —<br/>every constraint already in force"]
```

## Learn more

- **API** — `Linx.Process` (with `Linx.Process.Error` and `Linx.Process.Info`)
- **Examples** — [EXAMPLES.md](EXAMPLES.md): spawning, the checkpoint, namespaces,
  signals, stdio, attaching, supervision
- **References** — [REFERENCES.md](REFERENCES.md): the kernel syscalls and man pages
