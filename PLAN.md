# Linx.Netlink — foundations plan

> Status: **proposal, for review.** Branch `netlink-foundations`.
> Nothing here is committed code yet — review and amend before we build.

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
- Port the custom Mix compiler → `Mix.Tasks.Compile.NetlinkNif`; wire into
  `mix.exs` `:compilers`.
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
- `Linx.Netlink.Rtnl` namespace; `Linx.Netlink.Rtnl.Link` written **by hand,
  explicit** — no DSL: the `%Link{}` struct, hand-written `encode/1`/`decode/1`,
  the `ifinfomsg` header, a handful of `IFLA_*` attributes.
- Verbs that exercise the full cycle both ways: `Link.list/1` and `Link.get/2`
  (decode + dump), `Link.set_up/2` / `Link.set_down/2` (header-flag encode).
- **This is the "get a feel" step.** Done when `Rtnl.Link.list(socket)` returns
  `[%Link{}]` against the host netns.
- **Tests:** the `Rtnl.Link` codec gets unit + golden tests (plain). `list/1`
  and `get/2` are unprivileged dumps, tested against the host netns in plain
  `mix test`; `set_up/2`/`set_down/2` mutate state, so tagged `:integration`.

### M3 — Extract the DSL
- From M2's hand-written `Rtnl.Link`, extract the macro into
  `Linx.Netlink.Message` (`use`, `header`, `field`, `attr`).
- Rewrite `Rtnl.Link` through the DSL; M2's tests must still pass unchanged.
- Build the `custom:`/`with:` escape hatches now and exercise at least one,
  even minimally.
- Generated `@doc`/`@type`/`@spec` and the attribute documentation table.
- **Tests:** M2's `Rtnl.Link` tests must pass unchanged — the proof the
  extraction preserved behaviour; add unit tests for the DSL macro itself and
  each escape hatch.

### M4 — Complete the rtnetlink first-release scope, via the DSL
- `Rtnl.Link` full: `create_macvlan`/`create_ipvlan` (first real customer of
  `with: LinkInfo` + sub-message dispatch on link kind), `delete`,
  `move_to_netns`.
- `Rtnl.Address`: add an IPv4 address.
- `Rtnl.Route`: add a route / default route.
- Verbs grouped per resource module. Matches the README's first-release scope.
- **Tests:** the `Link`/`LinkInfo`/`Address`/`Route` codecs get unit + golden
  tests (plain); the mutating verbs need `CAP_NET_ADMIN`, so tagged
  `:integration`, run against a fresh netns with a `dummy` interface.

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
