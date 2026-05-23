# Linx

**Linux kernel interfaces for Elixir.**

A growing collection of low-level Linux primitives — netlink sockets, process and namespace lifecycle, mounts, cgroups — exposed as idiomatic Elixir. The goal is to make these feel as natural to drive from the BEAM as anything in the standard library.

Linx is a library of **primitives**, not a runtime. A container engine, a network orchestrator, or an observability tool is a *consumer* of Linx; the runtime concepts (images, supervision policies, request routing) live in those projects.

> ⚠️ **Early days.** Linx is just getting started. `Linx.Netlink` is the first piece. The API is still settling and breaking changes are likely until `1.0`.

## Installation

Not on Hex yet. Depend on it from Git:

```elixir
def deps do
  [
    {:linx, github: "oshlabs/linx"}
  ]
end
```

Linux only — the underlying kernel interfaces don't exist on macOS, BSD, or Windows.

## How Linx is organized

Three kinds of top-level module, named for what they organize:

| Kind | When | Examples |
|---|---|---|
| **Mechanism layer** | A coherent transport with shared infrastructure (codec, framing, error handling, …). | `Linx.Netlink` |
| **Subsystem concept** | A grouping of kernel operations that work together for one purpose. Mirrors how Linux man-page section 7 names things. | `Linx.Process` (planned), `Linx.Mount` (later), `Linx.Cgroup` (later) |
| **Value type** | A domain primitive that flows through the mechanisms. Top level. | `Linx.IP`, `Linx.MAC` |

The rule of thumb: name a module after a mechanism only when the mechanism has shared shape worth factoring out. Otherwise name it after the kernel subsystem or concept (`Namespace` isn't a subsystem — it's a cross-cutting flag on `clone(2)` — so it doesn't get its own module; the *operations* live where they belong).

Each subsystem owns its docs under `docs/<subsystem>/` — `EXAMPLES.md` (iex-style usage), `PLAN.md` (roadmap), `COVERAGE.md` (surface tracker), `REFERENCES.md` (external sources).

## What's there today

### `Linx.Netlink` — netlink sockets

An `AF_NETLINK` client with the rtnetlink family fleshed out. Talks netlink directly over a `:socket` socket, encoding and decoding messages in pure Elixir; a small NIF handles the one thing the BEAM can't do safely on its own — entering another network namespace.

Shipped today:

- **Sockets** — opened in the host netns or another netns by pid or path; sequence-correlated requests; the multipart-dump engine.
- **rtnetlink resources**, full CRUD across IPv4 and IPv6:
  - **Links** — `list`, `get`, `delete`, `move_to_netns`, `set_{up,down,mtu,name,address,master}`, plus virtual-link constructors: `macvlan`, `ipvlan`, `veth`, `vlan`, `bridge`, `dummy`.
  - **Addresses** — `list` (all / per-link), `add`, `delete`.
  - **Routes** — `list`, `get` (destination lookup), `add` / `add_default`, `delete` / `delete_default`.
  - **Neighbours** (ARP / NDP table) — `list`, `add`, `delete`.
  - **Rules** (policy routing) — `list`, `add`, `delete`.
  - **Stats** — `get` / `list` for `rtnl_link_stats64` counters.
- **A codec DSL** (`use Linx.Netlink.Codec`) that declares each message's wire format in one `codec do … end` block and generates the struct, `encode/1`, `decode/1`, and reflection. Escape hatches for sub-message dispatch and custom value types.
- **Rich errors** — `Linx.Netlink.Error` carries the errno as a POSIX atom plus the kernel's extended-ack message; verbs sharpen ambiguous "no such interface" into "no such *parent* interface" where they know better.

See [`docs/netlink/EXAMPLES.md`](docs/netlink/EXAMPLES.md) for usage and [`docs/netlink/COVERAGE.md`](docs/netlink/COVERAGE.md) for what's in vs. out.

### Value types

- **`Linx.IP`** — IPv4 or IPv6 address. The `~IP` sigil parses at compile time; `Inspect` round-trips back to the sigil. `Linx.IP.Subnet` adds `contains?/2`, `network/1`, `broadcast/1`.
- **`Linx.MAC`** — link-layer address. The `~MAC` sigil, same shape.

Decoded netlink fields carry these structs directly; verbs accept either the struct or the equivalent string.

## What's next

### `Linx.Process` — clone, setns, unshare *(active, feature branch)*

The next subsystem. Provides process-lifecycle primitives, starting with `clone(2)` with namespace flags so a caller can spawn a child in fresh namespaces of selected types. Setns and unshare follow.

Architecturally, `clone()`/`fork()`/`unshare()` inside the multithreaded BEAM corrupts the VM — so the actual syscall runs in a small external C agent (a Port, not a NIF), with a checkpoint protocol over fd 3/4 letting the orchestrator do host-side setup before the child execs.

This composes with `Linx.Netlink` cleanly: clone with `CLONE_NEWNET` → `Linx.Netlink.Socket.open(0, {:pid, child_pid})` to drive netlink inside the new netns → release the checkpoint → child execs.

### Coming later

- **`Linx.Mount`** — mount, `pivot_root`, `open_tree`, `mount_setattr`.
- **`Linx.Cgroup`** — cgroup v2 controllers (`memory.max`, `pids.max`, `cpu.max`, freezer, …).
- **Within `Linx.Netlink`** — a `Connection` GenServer for concurrent in-flight requests; a `Monitor` for multicast event subscription (the `ip monitor` equivalent); the `NETLINK_GENERIC` family and its subsystems (WireGuard, ethtool, …); more link kinds (`bond`, `vxlan`, `tun`/`tap`).

Roadmap details live in `docs/<subsystem>/PLAN.md`.

## Docs

`mix docs` generates HexDocs-style HTML under `_build/docs/`. The four living markdown docs per subsystem (EXAMPLES, PLAN, COVERAGE, REFERENCES) are surfaced there too. Once Linx has a first hex release, generated docs will be at [hexdocs.pm/linx](https://hexdocs.pm/linx).

## License

Linx is released under the [MIT License](LICENSE).
