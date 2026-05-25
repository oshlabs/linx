# Linx.Netfilter coverage

What of the kernel's netfilter surface `Linx.Netfilter` exposes
today, what is planned, and what is deferred.

A living doc — update as primitives ship. Status legend:

| | |
|---|---|
| ✅ | done — shipped and tested |
| 🟡 | partial — some sub-features in, others not |
| ⬜ | todo — not yet |
| ⏳ | architected-for — design accommodates it, no code yet |

## Transport

| Feature | Status | Notes |
|---|---|---|
| `Linx.Netlink.Nfnl.open/1` | ✅ | N0 — `:host` / `{:pid, n}` / `{:path, p}` via `Linx.Netlink.Socket` |
| `nfgenmsg` codec | ✅ | N0 — 4-byte header, BE `res_id`, encode/decode round-trip tested |
| Subsys-id multiplexing on `nlmsghdr.type` | ✅ | N0 — `nlmsg_type/2` + `split_type/1`; constants for NFTABLES/ULOG/CT/QUEUE |
| Batch envelopes (`BATCH_BEGIN`/`BATCH_END`) | ✅ | N0 — `batch_begin/1` + `batch_end/1` |
| `NFT_MSG_GETGEN` round-trip | ✅ | N0 — `Codec.get_gen/1` returns `%{id, proc_pid, proc_name}` |
| `Linx.Netfilter.supported?/0` | ✅ | N0 — kernel-feature probe via socket open |

## Value types + pipeline DSL

| Feature | Status | Notes |
|---|---|---|
| `%Linx.Netfilter.Ruleset{}` value type | ⬜ | N1 |
| `%Table{} / %Chain{} / %Rule{} / %Expr{} / %Verdict{}` | ⬜ | N1 |
| `%Set{} / %Map{} / %Vmap{} / %Object{} / %Flowtable{}` | ⬜ | N1 (Set/Map basic) → N4 (concat + dynamic) |
| Tag-as-converged-identity (handle / tag / comment) | ⬜ | N1 |
| Pipeline DSL (`Ruleset.new/0`, `add_table/3`, `add_chain/4`, …) | ⬜ | N1 — validator-setter functions |
| Validation (chain hooks, vmap key types, rule expr sequence, set element types) | ⬜ | N1 |

## Wire encoder / decoder

| Feature | Status | Notes |
|---|---|---|
| Encoder: Ruleset → batched nfnetlink messages (`:replace`) | ⬜ | N2 |
| Decoder: nfnetlink messages → Ruleset | ⬜ | N2 (basic) → N4 (sets/elements) |
| `push/2 :replace` mode | ⬜ | N2 |
| `pull/1` (whole netns) | ⬜ | N2 |
| `pull/2` (scoped to one table) | ⬜ | N2 |
| `create_table/2` with `owner: true` default | ⬜ | N2 |
| `persist: true` opt-out | ⬜ | N2 — feature-detected on 6.9+ |

## Minimal expression encoder

| Feature | Status | Notes |
|---|---|---|
| `Expr.immediate/2` (constants + verdicts) | ⬜ | N2 |
| `Expr.payload/3` (IP/TCP/UDP header field extraction) | ⬜ | N2 |
| `Expr.meta/2` (iif, oif, mark, iifname, oifname) | ⬜ | N2 / N3 |
| `Expr.cmp/3` (eq, neq, lt, le, gt, ge) | ⬜ | N2 |
| `Expr.bitwise/3` (AND with mask — required for CIDR) | ⬜ | N2 |
| `Expr.ct/2` (state matching) | ⬜ | N2 (state only) |
| `Expr.lookup/2` (set / map / vmap) | ⬜ | N2 (set ref) → N4 (anon + dynset) |
| `Expr.reject/2` (icmp / tcp-reset / icmpx) | ⬜ | N2 |
| `Expr.counter/1` | ⬜ | N2 |
| Verdicts (`:accept`, `:drop`, `:continue`, `:return`, `{:jump, _}`, `{:goto, _}`) | ⬜ | N2 |

## NAT

| Feature | Status | Notes |
|---|---|---|
| `type nat` chain support | ⬜ | N3 |
| `Expr.nat/2` (dnat / snat with address + port ranges, flags) | ⬜ | N3 |
| `Expr.masquerade/1` | ⬜ | N3 |
| `Expr.redirect/1` | ⬜ | N3 |
| Hairpin NAT (DNAT + SNAT pattern) | ⬜ | N3 — documented in EXAMPLES |

## Sets / maps / vmaps

| Feature | Status | Notes |
|---|---|---|
| Named set element types (ipv4_addr, ipv6_addr, ether_addr, inet_proto, inet_service, mark, ifname) | ⬜ | N4 |
| Anonymous sets (inline `{1, 2, 3}`) | ⬜ | N4 |
| Set element add/del (NFT_MSG_NEWSETELEM / DELSETELEM) | ⬜ | N4 |
| Interval sets (CIDRs, port ranges; `flags interval`, `auto_merge`) | ⬜ | N4 |
| Concatenations (`type ipv4_addr . inet_service`) | ⬜ | N4 |
| Verdict maps (vmaps) | ⬜ | N4 |
| Dynamic sets (`flags dynamic`, `timeout`; `Expr.dynset/3`) | ⬜ | N4 |

## Diff + `:reconcile` + CAS

| Feature | Status | Notes |
|---|---|---|
| `%Patch{ops: [...]}` value type | ⬜ | N5 |
| `diff/2 :: Ruleset → Ruleset → Patch` | ⬜ | N5 — identity rules: name / tag-or-position / element-value |
| Topological sort of patch ops | ⬜ | N5 |
| In-place vs delete+recreate detection (per-entity allowlist) | ⬜ | N5 |
| `push/2 mode: :reconcile` | ⬜ | N5 |
| `dry_run/2` (alias for `diff/2`) | ⬜ | N5 |
| `NFTA_BATCH_GENID` CAS with bounded retry | ⬜ | N5 |
| Tag enforcement for `:reconcile` (untagged → `:tag_required` error) | ⬜ | N5 |

## Live monitor

| Feature | Status | Notes |
|---|---|---|
| Monitor socket on `NFNLGRP_NFTABLES` | ⬜ | N6 |
| `Linx.Netfilter.Monitor` GenServer | ⬜ | N6 |
| `subscribe/1` → `{:linx_netfilter, :event, %Event{}}` | ⬜ | N6 |
| Event decoder (NEWTABLE/DELTABLE/.../NEWGEN/DELGEN) | ⬜ | N6 |
| Exactly-once-from-snapshot pattern (`subscribe_first:` opt on pull) | ⬜ | N6 |
| ENOBUFS recovery (`{:linx_netfilter, :resync_needed}`) | ⬜ | N6 |
| Batch grouping by gen_id | ⬜ | N6 |

## NFLOG (NFNL_SUBSYS_ULOG)

| Feature | Status | Notes |
|---|---|---|
| `Linx.Netfilter.Log` GenServer | ⬜ | N7 |
| `log_listen/2` API (group, copy_mode, qthresh, timeout, flags, families) | ⬜ | N7 |
| Per-group CFG_CMD_BIND / PF_BIND | ⬜ | N7 |
| `%Log.Event{}` decoder (every NFULA_* attribute) | ⬜ | N7 |
| Per-protocol payload decode (`%Packet.{IPv4,IPv6,TCP,UDP,ICMP}{}`) | ⬜ | N7 |
| Linx-default group `5000` convention | ⬜ | N7 |

## `~NFT` sigil + Conf parser

| Feature | Status | Notes |
|---|---|---|
| `Linx.NFT.Tokenizer` (handwritten char-by-char state machine) | ⬜ | N8 |
| `Linx.NFT.Parser` (handwritten token-stream recursive descent) | ⬜ | N8 |
| `Linx.NFT.Compiler` (AST → validator-setter calls → `%Ruleset{}`) | ⬜ | N8 |
| `Linx.NFT.ParseError` (file:line:column + code_snippet) | ⬜ | N8 |
| `sigil_NFT/2` | ⬜ | N8 — `~NFT"table inet ... { ... }"` |
| `parse/1` / `parse_file/1` | ⬜ | N8 — same parser, different entry |
| `format/1` (canonical emit) | ⬜ | N8 — Inspect.Algebra; no trivia preservation |
| Compile-time type-aware Elixir interpolation | ⬜ | N8 |
| ~85% grammar subset (tables, chains, common matches, common statements, basic sets/maps, NAT) | ⬜ | N8 |
| `mix format` plugin (`Linx.NFT.Formatter`) | ⬜ | N9 |

## Error reporting

| Mechanism | Status | Notes |
|---|---|---|
| `%Linx.Netfilter.Error{operation, errno, code, message, subsys, msg_type, batch_seq, attr_offset, ruleset_gen}` | ✅ | N0 — struct + Exception impl |
| `Exception` impl with extack message rendering | ✅ | N0 |
| `from_posix/2..3` with optional netfilter context fields | ✅ | N0 |
| Decoded `NLMSGERR_ATTR_*` extended-ack attributes populated | ⬜ | N2 — when push/pull are real |
| `{:bad_chain, _}` / `{:bad_rule, _}` / `{:bad_set_element, _}` / `{:tag_required, _}` | ⬜ | N1 / N5 |

## Composition with other subsystems

| Pairing | Status | Notes |
|---|---|---|
| `Linx.Process` checkpoint via `Nfnl.open({:pid, host_pid})` | ⏳ | N2+ — same lifecycle-agnostic shape as `Linx.Mount` / `Linx.Sysctl` |
| `Linx.Netlink.Rtnl` co-composition (network + firewall at checkpoint) | ⏳ | N2+ — host_rtnl + host_nfnl + ct_rtnl + ct_nfnl all from one supervisor |
| `Linx.Capabilities` + `Linx.Seccomp` lock-down (deny CAP_NET_ADMIN + setsockopt(AF_NETLINK)) | ⏳ | EXAMPLES at N7 |
| `Linx.Sysctl.write("net.ipv4.ip_forward", 1)` companion | ⏳ | EXAMPLES at N2 |

## Deferred — not in N0–N9

See `PLAN.md`'s "Deferred — architected-for, not built here" for
the full list with reasoning:

- **NFQUEUE** (`NFNL_SUBSYS_QUEUE`) — synchronous packet
  interception with userspace verdicts. Needs careful
  backpressure design. Future `Linx.Netfilter.Queue`.
- **ctnetlink event stream** (`NFNL_SUBSYS_CTNETLINK`) — live
  conntrack events for "connections" UI. Shares the Nfnl
  transport. Future `Linx.Netfilter.Conntrack`.
- **ctnetlink write side** (force-delete entries, update
  mark/label/timeout) — useful for "flush conntrack after
  changing NAT". Future addition to `Linx.Netfilter.Conntrack`.
- **Flowtable expression encoding** (`flow add @ft`) —
  declarative side (flowtable declaration) is in N4-ish scope;
  the expression encoding defers until a use case appears.
- **ct named objects** (timeout / helper / zone) — needed for
  ALG-required NAT, multi-tenant zone NAT. Per-demand.
- **Advanced expressions** (`synproxy`, `socket`, `tproxy`,
  `osf`, `xfrm`, `tunnel`, `secmark`, `numgen`, `jhash`,
  `hash` symmetric, `fib`, `exthdr`, `dup`, `fwd`, `last`,
  `connlimit`, `quota`, `objref`) — each a small additive
  milestone; ship per-demand.
- **`xt` compat shims** — out of scope (migration territory).
- **`ipset` legacy** — out of scope (superseded by nft sets).
- **Hook introspection** (`NFNL_SUBSYS_HOOK`, 5.16+) — niche.
- **Trivia-preserving Conf parser** (preserve `#` comments,
  define names, whitespace, ordering on emit) — v2 enhancement.
- **JSON form** (`nft -j`) — N0–N9 doesn't go through JSON. If
  a consumer needs JSON interop, a `Linx.NFT.Json` shim could
  live outside this milestone set.
