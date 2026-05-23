# Linx.Netlink — implementation plan

> **Phase 1 (M0–M4) has shipped** on branch `netlink-foundations` — the
> family-agnostic core and the first rtnetlink slice. **Phase 2** (below,
> after the Decisions section) is a proposal, for review.

## Goal

Build the foundations of `Linx.Netlink`: a **family-agnostic netlink core**, plus
the first protocol family — **rtnetlink (`NETLINK_ROUTE`)** — covering the
first-release scope in the README (netns-correct sockets; create/configure/delete
links incl. `macvlan`/`ipvlan`; move links between netns; IPv4 addresses and
routes).

It must be architected so that **all** netlink protocol families (generic
netlink, and genl subsystems such as WireGuard and nl80211) and **multicast
monitoring** slot in later without reworking the core.

Starting material is the proven `~/src/silo` POC: its flat ~320-line
`Silo.Netlink` rtnetlink client and its `netlink_nif.c` `setns` NIF. This work
**decomposes that flat module into a layered structure** and **generalizes the
NIF beyond `NETLINK_ROUTE`**. It is extraction + restructure, not greenfield.

## Guiding principles

**Two levels, kept strictly separate:**

- **Level A — wire primitives.** `nlmsghdr` framing; `rtattr` TLV encode/decode
  (4-byte padding, nesting); multipart-dump assembly; `NLMSG_ERROR` ACK/error
  parsing. Identical for every family. **One shared, tested implementation.**
- **Level B — per-message knowledge.** Which attributes a message carries and
  their types. Per-family, per-message.

**Level B is hand-written first, then a DSL is extracted** from the observed
repetition — never designed up front against a blank page.

**The codec DSL** is a compile-time macro (`use Linx.Netlink.Message`) that
generates the struct, `encode/1`/`decode/1`, and documentation from declarative
`header`/`field`/`attr` calls. It has **escape hatches** (`custom:`/`with:`) for
the irregular ~5%: sub-messages (e.g. `IFLA_LINKINFO` data dispatched on link
kind), attribute arrays, legacy binary-struct attributes.

**Synchronous now, process-ready.** Request/reply is synchronous for the first
release, but the request engine stays *pure protocol logic* so a `Connection`
GenServer (owning a socket, correlating by sequence number) and a `Monitor`
(multicast subscription) can be layered on later with no rewrite.

**AGENTS.md style throughout:** `@moduledoc`/`@doc`/`@spec` everywhere; domain
data as structs with `@enforce_keys`; one module per file; kernel-ABI citations
(man page / UAPI struct / kernel source) in comments.

## Module structure

```
Linx.Netlink                     — namespace + library overview docs

  family-agnostic core
  Linx.Netlink.Socket            — AF_NETLINK socket; protocol-number param;
                                   netns-aware open (:host | {:pid,_} | {:path,_})
  Linx.Netlink.Socket.Native     — the setns-on-throwaway-thread NIF
  Linx.Netlink.Constants         — shared netlink constants (NLM_F_*, NLMSG_*, AF_*)
  Linx.Netlink.Attr              — rtattr TLV codec: encode/decode, nesting, padding   [Level A, pure]
  Linx.Netlink.Message           — nlmsghdr framing + the codec DSL macro             [Level A, pure]
  Linx.Netlink.Request           — synchronous talk + multipart-dump engine

  rtnetlink family
  Linx.Netlink.Rtnl              — family namespace: protocol number, multicast groups
  Linx.Netlink.Rtnl.Link         — %Link{} + verbs
  Linx.Netlink.Rtnl.LinkInfo     — nested IFLA_LINKINFO (macvlan / ipvlan kinds)
  Linx.Netlink.Rtnl.Address      — %Address{} + verbs
  Linx.Netlink.Rtnl.Route        — %Route{} + verbs

  build
  c_src/netlink_socket.c
  lib/mix/tasks/compile.netlink_nif.ex

  deferred — architected-for, NOT built in this plan
  Linx.Netlink.Connection        — GenServer owning a socket; seq correlation
  Linx.Netlink.Monitor           — multicast subscription; decoded events
  Linx.Netlink.Generic.*         — generic netlink + subsystems (WireGuard, nl80211, …)
```

Dependencies flow strictly downward: `Socket` → `Message`/`Attr`/`Constants` →
`Rtnl.*` codecs → `Request` → verbs. The pure layers (`Attr`, `Message`, the
generated `Rtnl.*` codecs) have no socket or process dependency and are tested
in isolation.

## The codec DSL

Every netlink message has the same shape: **a fixed C-struct header followed by
a stream of TLV attributes** — the same model the kernel's own `netlink-raw`
YAML schema uses. The DSL describes that declaratively; the macro generates the
code. Target shape (illustrative):

```elixir
defmodule Linx.Netlink.Rtnl.Link do
  use Linx.Netlink.Message, header: :ifinfomsg
  @moduledoc "RTM_*LINK — network interface configuration."

  # struct ifinfomsg — include/uapi/linux/rtnetlink.h
  header do
    field :family, :u8
    field :type,   :u16
    field :index,  :s32
    field :flags,  :u32
    field :change, :u32
  end

  # IFLA_* — include/uapi/linux/if_link.h
  attr 3,  :ifname,   :string, doc: "IFLA_IFNAME — interface name"
  attr 5,  :link,     :u32,    doc: "IFLA_LINK — parent ifindex"
  attr 18, :linkinfo, :nested, with: Linx.Netlink.Rtnl.LinkInfo
end
```

Generates: `%Link{}` + `@type t`; `encode/1` and `decode/1` (delegating all
Level A framing/padding/nesting to `Message`/`Attr`); `@doc`/`@spec`; and a
documentation table of attributes rendered from the declarations — docs that
cannot drift from the code. `doc:` / kernel-source citations live structurally
in each `attr`.

**Escape hatches**, designed in from the first DSL version:
- `with: Module` — the attribute's value is itself a message (nested set).
- `custom: &Mod.fun/1` — hand-written encode/decode for an irregular attribute
  or message; the DSL handles the regular case, explicit code the rest.

## Sequencing — milestones

Each milestone is an independently reviewable commit.

### M0 — Scaffolding & the NIF
- Module skeleton: every module above with `@moduledoc`, no logic yet.
- Port `silo`'s `netlink_nif.c` → `c_src/netlink_socket.c`, **parameterized by
  protocol number** (`open_in_netns(path, protocol)`), so genl and others reuse
  it. `Linx.Netlink.Socket.Native`.
- Port the custom Mix compiler → `lib/mix/tasks/compile.netlink_nif.ex`; wire
  into `mix.exs` `:compilers`.
- `Linx.Netlink.Socket`: `%Socket{}` struct (`@enforce_keys`); `open/2`
  (`:host` opens directly via `:socket`; `{:pid,_}`/`{:path,_}` via the NIF),
  `close/1`, `next_seq/1`. The struct carries an `:atomics` sequence counter,
  so request seq is correct without a process.
- **Tests:** unit tests opening/closing a `:host` socket and exercising
  `next_seq/1` (unprivileged, plain `mix test`); entering another netns via
  the NIF is tagged `:integration`.

### M1 — Level A wire primitives (hand-written, no DSL yet)
- `Linx.Netlink.Constants`.
- `Linx.Netlink.Attr`: `rtattr` TLV encode/decode, nested attributes, 4-byte
  padding. Pure.
- `Linx.Netlink.Message`: `nlmsghdr` encode; decode a received buffer into a
  list of messages; multipart iteration. Pure. (The DSL macro is added in M3.)
- `Linx.Netlink.Request`: synchronous `talk` — send, recv, parse `NLMSG_ERROR`
  (errno 0 = ACK), assemble `NLM_F_MULTI` dumps to `NLMSG_DONE`. Drives
  `Socket`; pure protocol logic otherwise.
- **Tests:** `Attr`/`Message` get unit + property (encode/decode round-trip) +
  golden tests against captured kernel bytes — all plain `mix test`. `Request`
  is exercised against the live host netns with an unprivileged dump, also
  plain.

### M2 — First rtnetlink message, hand-written explicit
- `Linx.Netlink.Rtnl` namespace (the `NETLINK_ROUTE` family; `open/1`);
  `Linx.Netlink.Rtnl.Link` written **by hand, explicit** — no DSL: the
  `%Link{}` struct, a hand-written `decode/1`, the `ifinfomsg` header and a
  handful of `IFLA_*` attributes.
- Read verbs, all unprivileged: `Link.list/1` (an `RTM_GETLINK` dump) and
  `Link.get/2` (a single `RTM_GETLINK` by name — which also exercises request
  *encoding*: an `ifinfomsg` plus an `IFLA_IFNAME` attribute).
- **This is the "get a feel" step.** Done when `Rtnl.Link.list(socket)`
  returns `[%Link{}]` against the host netns.
- **Tests:** the `Rtnl.Link` codec gets unit + golden tests; `list/1` and
  `get/2` are unprivileged, tested against the live host netns — all plain
  `mix test`.

### M3 — Extract the DSL
- Extract the codec DSL into `Linx.Netlink.Codec` — its own module, kept
  separate from the `Message` nlmsghdr struct. A codec module does
  `use Linx.Netlink.Codec` and declares its wire format in one `codec do … end`
  block (a `header do field/pad … end` and `attr` lines); the macro generates
  the struct, `encode/1`, `decode/1`, `@type t`, `@spec`s, and a `__codec__/0`
  schema-reflection function.
- Rewrite `Rtnl.Link` through the DSL; M2's tests pass unchanged.
- One escape hatch: an attribute's type may be a **module** exporting
  `encode/1`/`decode/1` — covering both a nested codec and a hand-written
  custom value type with a single mechanism (simpler than separate
  `with:`/`custom:` options).
- **Tests:** M2's `Rtnl.Link` tests pass unchanged — the proof the extraction
  preserved behaviour; plus codec unit tests for the DSL, the escape hatch,
  and `__codec__/0` reflection.

### M4 — Complete the rtnetlink first-release scope, via the DSL
- `Rtnl.Link` full: `create_macvlan`/`create_ipvlan`, `delete`,
  `move_to_netns`, `set_up`/`set_down`. The regular attributes (`IFLA_LINK`,
  `IFLA_NET_NS_PID`, …) are DSL-declared; `IFLA_LINKINFO` — whose data is
  kind-specific — is built by an explicit per-kind helper (approach B: the
  escape hatch as hand-written code for the irregular case; DSL-level
  sub-message dispatch deferred until a second/third kind needs it).
- `Rtnl.Address`: `add/4` — an IPv4 address on a link.
- `Rtnl.Route`: `add_default/2` — an IPv4 default route via a gateway.
  (General destination-prefix routes are a later follow-up.)
- Verbs grouped per resource module. Matches the README's first-release scope.
- **Tests:** the `Address`/`Route` codecs get plain unit tests; the mutating
  verbs need `CAP_NET_ADMIN`, so are tagged `:integration` — run against a
  fresh `ip netns` with a `dummy` parent interface (root + iproute2).

## Testing

Every milestone ships **with its tests** — code and tests land in the same
commit. Three bands:

- **Unit + property tests.** The pure layers (`Attr`, `Message`, the DSL macro,
  the generated `Rtnl.*` codecs) get encode/decode round-trip and property
  tests, plus golden tests against captured kernel byte dumps. No root, no
  network — these run in plain `mix test`.
- **Read-path integration.** Netlink *dumps* (`RTM_GETLINK`, …) are
  unprivileged, so `Socket`, `Request` and the `list`/`get` verbs are tested
  against the live host netns — also in plain `mix test`.
- **Privileged integration.** Anything that mutates kernel state (create/delete
  a link, add an address or route) or enters another netns needs
  `CAP_NET_ADMIN`. Those tests are tagged `:integration` and excluded from the
  default run; a self-contained one creates a fresh netns and a `dummy`
  interface — no external fixture. `mix test --include integration` runs them.

Only **CI** — *where* the `:integration` suite runs automatically — is
deferred. The tests themselves ship with the milestone they belong to.

## Deferred — architected-for, not built here

- `Linx.Netlink.Connection` — GenServer owning a socket, concurrent in-flight
  requests correlated by seq. The synchronous `Request` logic is reused as-is.
- `Linx.Netlink.Monitor` — joins `RTNLGRP_*` multicast groups, decodes events,
  fans out to subscribers.
- `Linx.Netlink.Generic.*` — generic netlink (runtime family-id resolution via
  the `CTRL` family) and genl subsystems. Codec strategy decided then: likely
  kernel-YAML-generated DSL declarations feeding the *same* macro backend.
- `tc` and the long tail of rtnetlink (neighbours, rules, qdiscs).

## Decisions

1. **Sequence numbers** — `%Socket{}` carries an `:atomics` counter; each
   `Request.talk` bumps and validates seq. Correct without needing a process.
2. **Family namespace** — `Linx.Netlink.Rtnl` (avoids the routing resource
   being `Route.Route`).
3. **Shared constants module** — `Linx.Netlink.Constants`.
4. **Integration-test tag** — `:integration`. CI (running that suite
   automatically) is deferred until the project has CI.

---

# Phase 2 — rtnetlink breadth

Phase 1 shipped the family-agnostic core and a thin first slice of rtnetlink.
Phase 2 widens rtnetlink toward day-to-day completeness. Every milestone here
is a *declarative addition* — a `codec do … end` block plus verbs — riding the
finished `Socket` / `Message` / `Attr` / `Request` / `Codec` layers; no new
infrastructure. Same rules as Phase 1: code ships with its tests (plain for
codecs, `:integration` for mutating verbs), commit and push per milestone.

## M5 — Address & Route: full CRUD, IPv4 and IPv6

The cheapest, highest-value gap: each resource has one write verb and no reads.

- `Rtnl.Address` — `list/1` (and per-link `list/2`) via an `RTM_GETADDR` dump;
  `delete/4`.
- `Rtnl.Route` — `list/1` via an `RTM_GETROUTE` dump; a general `add/4` for a
  destination-prefix route (`add_default/2` becomes the `0.0.0.0/0` case);
  `delete`.
- **IPv6** across both — `AF_INET6`, 16-byte addresses, `:inet.parse_address`.
  The codec needs no change: the address attributes are already `:binary`,
  length-agnostic; only the verb logic picks the family and address width.
- **Tests:** codec tests stay plain; dumps are unprivileged (host netns);
  `add`/`delete` are `:integration`.

## M6 — Link kinds, and DSL sub-message dispatch

- More virtual link kinds — at least **veth** (the pair that, with a bridge,
  is the other container-networking model), **vlan**, **bridge**; `dummy` and
  `vxlan` as they fall out cheaply.
- These are the second and third customers of kind-specific `IFLA_INFO_DATA`,
  so **generalize the sub-message dispatch into the `Codec` DSL** — an
  attribute whose sub-codec is chosen at runtime from the `kind` value. This
  is the M4 deferral (approach B): now extract it, with real customers.
- Link configuration verbs: `set_mtu/3`, `set_name/3`, `set_master/3` (enslave
  to a bridge or bond), `set_address/3` (MAC).
- **Tests:** codec and dispatch tests plain; create/config verbs
  `:integration`, in a fresh netns.

## M7 — Neighbours and Rules

New resource modules, the same machinery:

- `Rtnl.Neighbour` — the ARP / NDP table (`RTM_*NEIGH`): `add`, `delete`,
  `list`.
- `Rtnl.Rule` — policy-routing FIB rules (`RTM_*RULE`): `add`, `delete`,
  `list`.
- **Tests:** as above.

## Beyond Phase 2 — separate tracks

- **Traffic control** (`RTM_*QDISC` / `*TCLASS` / `*TFILTER`) — qdiscs,
  classes, filters, actions: the largest part of rtnetlink by far. Its own
  later effort, not a Phase 2 milestone.
- **The process layer** — `Linx.Netlink.Connection` (a supervised socket with
  concurrent in-flight requests) and `Linx.Netlink.Monitor` (multicast
  link/addr/route events). Cross-cutting, not rtnetlink-specific; the
  synchronous `Request` engine was built to accept this without rework.
- **Generic netlink** (`Linx.Netlink.Generic`) — genl family resolution and
  subsystems (WireGuard, nl80211). Where the kernel's YAML specs become
  attractive: breadth turns into a code-generation problem feeding the same
  `Codec` DSL, rather than hand-writing.
