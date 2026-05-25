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
| `type nat` chain support | ✅ | N3 — chain validator allows it in ip/ip6/inet; restricted to nat-applicable hooks |
| `Expr.nat/2` (low-level dnat / snat with register references + flags) | ✅ | N3 |
| `Expr.dnat_to/3` / `Expr.snat_to/3` (high-level: addr + optional port → list of expressions) | ✅ | N3 — accepts IPv4/IPv6 tuples, binaries, strings, `%Linx.IP{}` |
| `Expr.masquerade/1` | ✅ | N3 — flags `:random` / `:fully_random` / `:persistent`; port-range option |
| `Expr.redirect/1` | ✅ | N3 — optional `:port` and flags |
| Hairpin NAT (DNAT + SNAT pattern) | ✅ | N3 — composes naturally with the pipeline DSL; tested |
| `Rule.build` flattens nested list expressions | ✅ | N3 — `Expr.dnat_to/3` etc. drop into a rule's expression list directly |

## Sets / maps / vmaps

| Feature | Status | Notes |
|---|---|---|
| Named set element types (ipv4_addr, ipv6_addr, ether_addr, inet_proto, inet_service, mark, ifname) | ✅ | N4 — wire codec round-trip; element tuples normalised |
| Set encoder + decoder (NEWSET / GETSET dump) | ✅ | N4 — `Encoder.set/3`, `Decoder.set/1`; NFTA_SET_ID auto-assigned |
| Set element encoder + decoder (NFT_MSG_NEWSETELEM) | ✅ | N4 — batched per-set elements, key/data NLA_NESTED |
| Verdict maps (vmaps) | ✅ | N4 — `Vmap.new!/2` round-trips; elements with `%Verdict{}` data |
| Anonymous sets (inline `{22, 80, 443}`) | ✅ | N4 — `Expr.set_literal/3`; expanded at `to_batch` time, NFT_SET_F_ANONYMOUS\|CONSTANT |
| Set element add/del at the verb level | 🟡 | N4 — encoder ships, no Linx.Netfilter.add_set_elements/3 verb yet |
| Interval sets (CIDRs, port ranges; `flags interval`) | 🟡 | N4 — `:interval` flag ships; interval-element encoding (range-pair format) deferred |
| Concatenations (`type ipv4_addr . inet_service`) | ⬜ | N4+ — bit-packed type IDs, doubled key_len |
| Dynamic sets (`flags dynamic`, `timeout`; `Expr.dynset/3`) | ⬜ | N4+ — value type ships, encoder for dynset expression deferred |
| Userdata for set type display (so `nft list` renders typed) | ⬜ | future — anonymous sets currently render as `@nh,...` hex |

## Diff + `:reconcile` + CAS

| Feature | Status | Notes |
|---|---|---|
| `%Linx.Netfilter.Patch{ops: [...]}` value type | ✅ | N5 — custom Inspect with op-kind summary |
| `Linx.Netfilter.diff/2 :: Ruleset → Ruleset → Patch` | ✅ | N5 — identity: name for tables/chains/sets; tag-or-position for rules; element value for set elements |
| Diff scoped to `to`'s tables (don't touch tables Linx doesn't own) | ✅ | N5 — coexists with Docker / firewalld in the same netns |
| Topological sort of patch ops | ✅ | N5 — `Patch.sort/1`: deletes before creates of dependencies |
| In-place vs delete+recreate detection | 🟡 | N5 — rules use `NLM_F_REPLACE`; chains always delete+create on structural change |
| `Linx.Netfilter.push/2 mode: :reconcile` | ✅ | N5 — pull, diff, encode, BATCH_GENID, retry on ERESTART |
| `Linx.Netfilter.dry_run/2` (alias for `diff/2`) | ✅ | N5 |
| `NFNL_BATCH_GENID` CAS with bounded retry (default 3, exponential backoff) | ✅ | N5 — exhaust → `%Error{errno: :erestart, ruleset_gen: gen}` |
| Tag enforcement for `:reconcile` | ✅ | N5 — untagged rule in multi-rule chain → `{:error, {:tag_required, _}}` |
| Rule tag + comment round-trip via NFTA_RULE_USERDATA TLV | ✅ | N5 — Linx-specific UDATA type 16 for tags, type 0 for comments (libnftnl-compatible) |
| Chain-policy equivalence: `nil` matches kernel default `:accept` | ✅ | N5 — pulled chains always carry a policy; user-built ones may not |

## Live monitor

| Feature | Status | Notes |
|---|---|---|
| Monitor socket on `NFNLGRP_NFTABLES` | ✅ | N6 — `Linx.Netlink.Socket.add_membership/2` joins group 7 |
| `Linx.Netfilter.Monitor` GenServer | ✅ | N6 — short-timeout polling loop; 4 MiB SO_RCVBUF default |
| `Linx.Netfilter.subscribe/2` → `{:linx_netfilter, :event, %Event{}}` | ✅ | N6 — `unsubscribe/1` stops the monitor |
| `%Linx.Netfilter.Event{gen_id, proc_pid, proc_name, op, entity}` value type | ✅ | N6 — custom Inspect with op + path summary |
| Event decoder dispatches on NEW/DEL of TABLE/CHAIN/RULE/SET/SETELEM + NEWGEN | ✅ | N6 — reuses N2-N4 entity decoders |
| Snapshot+tail (`subscribe_first:` opt on pull/1..2) | ✅ | N6 — captures gen before dump; Monitor.set_min_gen filters pre-snapshot events |
| ENOBUFS recovery (`{:linx_netfilter, :resync_needed}`) | ✅ | N6 — owner re-runs snapshot+tail |
| Batch grouping by gen_id | ✅ | N6 — entity events buffered until NEWGEN closes the batch; all dispatched with that gen + committer |
| Netlink socket auto-bind with `nl_pid = 0` | ✅ | N6 — added `Native.bind_netlink/2` NIF; required for multicast |

## NFLOG (NFNL_SUBSYS_ULOG)

| Feature | Status | Notes |
|---|---|---|
| `Linx.Netfilter.Log` GenServer | ✅ | N7 — short-timeout polling loop, ENOBUFS → `:resync_needed` |
| `Linx.Netfilter.log_listen/2` + `unlog_listen/1` | ✅ | N7 — group/copy_mode/qthresh/timeout/flags/families/rcvbuf |
| Per-group CFG_CMD_BIND + CFG_CMD_PF_BIND | ✅ | N7 — `:families` defaults to `[:ipv4, :ipv6]`; UNBIND on stop |
| CFG_MODE (copy_mode + snaplen) | ✅ | N7 — `:none` / `:meta` / `:packet` / `{:packet, snaplen}` |
| CFG_FLAGS (`:seq`, `:seq_global`, `:conntrack`) | ✅ | N7 |
| CFG_QTHRESH (batching threshold) | ✅ | N7 — sent only when `> 1` |
| CFG_TIMEOUT (kernel-side time batching) | ✅ | N7 — converted from ms to kernel's 100ms units |
| `Linx.Netfilter.Expr.log/1` (`NFTA_LOG_*`) | ✅ | N7 — group/prefix/snaplen/qthreshold/flags |
| `%Log.Event{}` decoder (NFULA_* attributes) | ✅ | N7 — packet_hdr / mark / timestamp / iif/oif (incl. phys) / hwaddr / payload / prefix / uid/gid / seq / seq_global |
| Per-protocol payload decode (`%Packet.{IPv4,IPv6,TCP,UDP,ICMP}{}`) | ⬜ | future — raw payload bytes available now; structured decode is a small additive layer |
| Linx convention: group 5000 default | ✅ | N7 — documented in `Linx.Netfilter.Log` and the moduledoc of `Expr.log/1` |

## `~NFT` sigil + Conf parser

| Feature | Status | Notes |
|---|---|---|
| `Linx.NFT.Tokenizer` (handwritten char-by-char state machine) | ✅ | N8a — start-condition stack (`:default`/`:string`/`:line_comment`/`:block_comment`/`:elixir_expr`); identifiers, integers (dec/hex/bin), time literals (`5m`/`1h`/`30s`), strings with escapes, IPv4/IPv6/MAC/CIDR literals, statement separators, line + nested block comments, `\#{...}` Elixir interpolation when opted in |
| `Linx.NFT.Parser` (handwritten token-stream recursive descent) | ✅ | N8b — tables (all families), chains (base headers + named/integer priorities), rules (matches on `tcp/udp/ip/ip6/icmp/icmpv6 + field`, `meta`, `ct`; verdicts; `counter`/`log`/`limit`/`dnat`/`snat`/`masquerade`/`redirect`; `meta mark set`), named sets/maps/vmaps with `type`/`flags`/`timeout`/`elements`, objects (`counter`/`quota`/`limit`), flowtables, `include`/`define` at top-level. AST carries file:line:column on every node |
| `Linx.NFT.Compiler` (AST → validator-setter calls → `%Ruleset{}`) | 🟡 | N8c — tables, chains (base headers with named-alias priorities resolved via `Wire.priority_int/2`), rules (verdicts; payload/meta/ct matches against integer/address/CIDR/set_ref/inline-set; counter/log/reject/dnat/snat/masquerade/redirect), sets (declarations + simple element types), maps/vmaps (declarations). Deferred with clean ParseError: limit, meta-set/ct-set, named objects, flowtables, includes, concatenated set/map keys |
| `Linx.NFT.ParseError` (file:line:column + code_snippet) | ✅ | N8a — Elixir-compiler-style caret rendering via `code_snippet/2`; `raise_syntax_error!/2` helper |
| `sigil_NFT/2` | ✅ | N8d — `~NFT"table inet ... { ... }"` compile-time → `%Ruleset{}` literal; raises `ParseError` at compile time on bad syntax with `__CALLER__.file:line` |
| `Linx.NFT.parse/1` / `parse_file/1` | ✅ | N8d — same Tokenizer/Parser/Compiler pipeline as the sigil; `parse_file/1` carries the file path into error messages and returns `{:error, posix}` for missing files |
| `Linx.NFT.format/1` (canonical emit) | 🟡 | N8d — `Linx.NFT.Formatter` walks the Ruleset and emits canonical nft syntax for everything the compiler supports. Round-trip (`parse → format → parse`) is structurally identical for the supported slice. Unknown expression shapes emit `# <unsupported expression: NAME>` in-line so the output stays valid nft. Trivia (comments / blank lines / original ordering) is not preserved |
| Compile-time-detected, runtime-typed Elixir interpolation | 🟡 | N8e — uppercase `~NFT` (HEEx pattern); our tokenizer parses `\#{...}` itself rather than relying on Elixir's interpolation (which lowercase sigils would force, with `Kernel.to_string` wrapping in the way). When any interpolation is present, the macro dispatches to `Linx.NFT.RuntimeCompiler`, which emits Elixir code that calls `Linx.NFT.Runtime.cmp!/3` at the interpolation positions with the field kind inferred from the surrounding nft syntax. Static-only bodies stay on the compile-time path (literal `%Ruleset{}` via `Macro.escape`). Supported at match RHS for `{:int, _}` / `:ipv4` / `:ipv6` / `:ifname`; keyword positions (names / families / hooks) deferred |
| ~85% grammar subset (tables, chains, common matches, common statements, basic sets/maps, NAT) | 🟡 | reached for the compiler-supported slice; long-tail constructs (`limit`, `meta`-set, named objects, flowtables, includes, concat keys) ship as per-construct follow-ups |
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
