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
| `%Linx.Netfilter.Ruleset{}` value type | ✅ | N1 — `%Ruleset{tables}` keyed by `{family, name}` |
| `%Table{} / %Chain{} / %Rule{} / %Expr{} / %Verdict{}` | ✅ | N1 |
| `%Set{} / %Map{} / %Vmap{} / %Object{} / %Flowtable{}` | 🟡 | N1 (basic shape + atomic key/data types) → N4 (concat + dynamic + intervals) |
| Tag-as-converged-identity (handle / tag / comment) | ✅ | N1 — Rule fields, tag uniqueness enforced |
| Pipeline DSL (`Ruleset.new/0`, `add_table/3`, `add_chain/4`, …) | ✅ | N1 — validator-setter shape + `!` variants for pipeline use |
| Validation: chain family/hook/type/device + base-vs-regular consistency | ✅ | N1 |
| Validation: vmap value types are all verdicts | ✅ | N1 — Map normalises verdict-input values |
| Validation: set element types match key_type (basic shape check) | ✅ | N1 — strict validation in N4 |
| Validation: rule tag uniqueness within chain | ✅ | N1 — `:duplicate_tag` |
| Validation: rule expression-sequence type correctness | ⬜ | N2 — needs typed expressions |
| Custom `Inspect` for Rule / Expr / Verdict | ✅ | N1 — compact rendering |
| Custom `Inspect` for Set / Map / Table | ⬜ | future — atomic structs render fine by default |

## Wire encoder / decoder

| Feature | Status | Notes |
|---|---|---|
| Encoder: Ruleset → batched nfnetlink messages (`:replace`) | ✅ | N2 — `Linx.Netfilter.Encoder.to_batch/2` |
| Decoder: nfnetlink messages → Ruleset | ✅ | N2 (tables / chains / rules + N2 expressions) → N4 (sets/elements) |
| `push/2 :replace` mode | ✅ | N2 — DESTROYTABLE+NEWTABLE+NEWCHAIN+NEWRULE in one batch |
| `pull/1` (whole netns) | ✅ | N2 — three dumps (GETTABLE, GETCHAIN, GETRULE), assembled |
| `pull/2` (scoped to one table) | ✅ | N2 — GETTABLE single + filtered chains/rules |
| `create_table/3` with `owner: true` default | ✅ | N2 — `:owner` flag set by default; `persist: true` opts out |
| `persist: true` opt-out | ✅ | N2 — swaps to `:persist` flag (6.9+) or empty flags |
| `Linx.Netlink.Nfnl.batch/2` — batched request engine | ✅ | N2 — BATCH_BEGIN + N inner + BATCH_END; per-msg ACK tracking |
| Big-endian integer helpers (`Wire.u32_be/1`, `u64_be/1`, `s32_be/1`) | ✅ | N2 — nftables wire-format quirk |

## Minimal expression encoder

| Feature | Status | Notes |
|---|---|---|
| `Expr.immediate/1` (verdict load into reg 0) | ✅ | N2 |
| `Expr.immediate/1` constant load into value register | 🟡 | N2 — encoder supports it (`%{value, dreg}`), no high-level constructor yet |
| `Expr.payload/3` + `Expr.payload/2` (named aliases: `:tcp_dport`, `:ip_saddr`, etc.) | ✅ | N2 — base/offset/len + 10 named aliases |
| `Expr.meta/2` (iif, oif, mark, iifname, oifname, nfproto, l4proto, …) | ✅ | N2 — 14 meta keys |
| `Expr.cmp/3` (eq, neq, lt, lte, gt, gte) | ✅ | N2 |
| `Expr.bitwise/3` (AND with mask + XOR) | ✅ | N2 |
| `Expr.ct/2` (state, direction, status, mark, secmark) | ✅ | N2 — state via `Wire.ct_state_bits/1` |
| `Expr.lookup/2` (set / map / vmap) | 🟡 | N2 — set-ref shape; anonymous + dynset land with N4 |
| `Expr.reject/2` (icmp_unreach / tcp_reset / icmpx_unreach) | ✅ | N2 — default code 3 (port-unreach) for icmp types |
| `Expr.counter/1` | ✅ | N2 — `%{packets, bytes}` round-trips on pull |
| Verdicts (`:accept`, `:drop`, `:continue`, `:return`, `{:jump, _}`, `{:goto, _}`, `{:queue, _}`) | ✅ | N2 — full set, jump/goto carries chain name |

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
| `{:bad_table, _}` / `{:bad_chain, _}` / `{:bad_rule, _}` / `{:bad_set, _}` / `{:bad_set_element, _}` / `{:bad_map, _}` / `{:bad_map_element, _}` / `{:bad_object, _}` / `{:bad_flowtable, _}` / `{:bad_verdict, _}` | ✅ | N1 — tagged-tuple validator errors |
| `{:duplicate_table, _}` / `{:duplicate_chain, _}` / `{:duplicate_set, _}` / `{:duplicate_map, _}` / `{:duplicate_object, _}` / `{:duplicate_flowtable, _}` / `{:duplicate_tag, _}` | ✅ | N1 — uniqueness errors |
| `{:no_such_table, _}` / `{:no_such_chain, _}` / `{:ambiguous_table_name, _}` | ✅ | N1 — navigation errors |
| `{:tag_required, _}` for `:reconcile`-mode pushes of untagged rules | ⬜ | N5 |

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
