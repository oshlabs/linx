# ~NFT — plan to parity with nftables

Goal: make the `~NFT` sigil / `.nft` file path a flagship-quality part of Linx —
behaviorally faithful to the official nftables parser wherever both accept an
input, honest (loud, located errors) wherever we don't accept something yet,
and with grammar coverage raised toward 100% of the *declarative ruleset
language*.

This is a maintainer doc — not shipped in the hex package, does not render on
hexdocs.

## Current status (updated 2026-07-02)

Six work passes done in one day. **Every architectural capability is in
place** — the remaining work is breadth (more selectors / statements /
object kinds), each a mechanical repeat of an existing pattern.

**Measured coverage:** the aspirational corpus
(`test/linx/nft/fixtures/aspirational/*.nft`, realistic real-world-style
configs) is at **9/9 fixtures fully supported** (parse → compile → format →
round-trip). Every encoding is **kernel-verified**:
`kernel_acceptance_test.exs` pushes 13 rules across every construct through a
real netlink socket and reads them back (runs unprivileged in dev via
`unshare -r -n`, and in the privileged CI job).

### What works end-to-end (parse → compile → kernel)

- Tables (all families), base-chain headers (type/hook/priority incl. named
  aliases + offsets), policies, chain/table/rule comments, `flush ruleset`
- Matches: tcp/udp/icmp/icmpv6/ip/ip6 headers (incl. `ip6 nexthdr/hoplimit`),
  `meta` (iif/oif by name→index, iifname/oifname/mark/…), `ct state`,
  `ip protocol`
- **Protocol-context dependency generation** — `tcp dport` auto-materializes
  `meta l4proto`, `ip saddr` in `inet` chains auto-materializes `meta
  nfproto`; contradictions are located errors (fixed a real bug where `tcp
  dport 22` also matched UDP)
- **Bitwise/flag matching** — `tcp flags syn` (bit test), `tcp flags == syn`
  (exact), `tcp flags & (fin|syn|rst|ack) == syn`, `ct mark & 0xff == 0x4`,
  `(a|b)` / bare `a|b` OR-combinations
- Sets, maps, named + anonymous **vmaps**, dynamic sets with per-element
  timeout + nested stateful exprs (`add @rl { ip saddr limit rate over
  3/minute }`)
- **Concatenations** — plain (`ipv4_addr . inet_service`) and **pipapo
  interval** concats (`10.0.0.0/24 . 80-443`), including rule-side reg32
  selector loads
- Named objects: **counter / quota / limit** (+ `counter name`/`quota
  name`/`limit name` references), inline `quota`/`limit`/`counter`
- NAT (dnat/snat/masquerade/redirect, incl. `addr:port` and port ranges),
  `log`, `reject`, `queue` (bare)
- `include` (relative + search paths + glob + depth cap + cycle detection)
  and `define`/`$var` substitution
- **Multi-error reporting** (recover at statement boundaries, up to 10
  errors) and the full Phase 0 correctness-divergence set

### What's still missing (breadth, no architectural blockers)

- **Selector families**: `exthdr`, `rt`, `socket`, `fib`, `numgen`, `hash`,
  `osf`, `xfrm`, `tunnel`; payload headers `ether`/`vlan`/`arp`/`th`/
  `udplite`/`igmp`/`gre`/`geneve`/`vxlan`; full `meta`/`ct` key sets
- **Statements**: `tproxy`, `dup`/`fwd`, `synproxy`, `map`/`meter`,
  `connlimit`, `last`, `optstrip`, inline `chain`, full `queue`, `meta`/`ct`
  *set* forms
- **Objects**: `secmark`, `synproxy`, ct helper/timeout/expectation;
  flowtables
- **Set/map/chain/table declaration options**: `typeof`, `policy`,
  `auto-merge`, per-element timeouts/counters, chain `flags offload` +
  multi-device, table flags
- **Expression tail**: full `&|^<<>>` arithmetic cascade for non-flag binops,
  `value/mask` slash form, generic prefix, wildcard `eth*` strings, byteorder
  ranges (`meta mark 10-20`), ether-type deps for bridge/netdev
- **Polish**: expected-token-set error messages, warning channel, fuzzing,
  full nftables `tests/shell` corpus import, interpolation beyond match-RHS

### Reference

nftables master — `src/scanner.l` (1,418 lines, 56 start conditions),
`src/parser_bison.y` (6,594 lines, 398 tokens, 471 nonterminals),
`src/evaluate.c` (6,611 lines). Load-bearing findings restated inline below so
this doc is self-contained. Hard-won kernel facts collected across the
implementation are marked ⚠ where they'd bite a reimplementation.

## Scope: what "100%" means

We target the **declarative ruleset-definition language** — everything that
can appear in an `nftables.conf` loaded with `nft -f`: `table`/`chain`/rule
bodies, sets/maps/vmaps, named objects, flowtables, `include`/`define`.

Explicit non-goals (would not make sense inside `~NFT`, which produces a
`%Ruleset{}` value):

- The imperative CLI verb layer (`add`/`delete`/`insert`/`replace`/`list`/
  `flush`/`monitor`/`describe`/`get`/`rename`/…). Runtime mutation is the
  pipeline DSL's and `Linx.Netfilter`'s job.
- The JSON frontend (`libnftables-json`). Our second frontend *is* the
  pipeline DSL; both converge on the same Ruleset validators, mirroring how
  nft's bison and JSON parsers converge on `struct cmd` before `evaluate.c`.
- `xt`/iptables-compat statements — nft's own grammar rejects them with
  "unsupported xtables compat expression"; we do the same.

## Guiding principles (what we adopt from the original, and what we don't)

1. **Syntax-permissive, semantics-strict.** The official design's deepest
   idea: the scanner *cannot fail* (unknown bytes become a `JUNK` token; the
   parser rejects it with a located error) and the grammar is type-oblivious —
   literals stay strings until `evaluate.c` interprets them against the
   datatype expected by context. We keep our eagerly-classified token kinds
   (`:ipv4`, `:cidr_v6`, `:time`, …) because they give better early errors,
   **but** the lexer must never hard-reject something the official scanner
   would swallow as a string. Where classification fails, fall back to a
   `:symbol` token and let the parser/compiler produce the located error.
2. **Same input ⇒ same meaning.** Wherever both parsers accept an input, the
   resulting kernel state must be identical. Divergences are bugs even when
   our behavior is "nicer" (see Phase 0: octal, escapes).
3. **Supersets must not leak.** Conveniences we add on purpose (nested block
   comments, `0b` binary literals, escape sequences in strings, unquoted
   keyword-named chains) are fine *inbound* but the `Formatter` must only ever
   emit syntax `nft -f` accepts. Round-trip contract: `format/1` output passes
   `nft --check` byte-for-byte semantically.
4. **Parse everything, reject in the compiler.** The parser should accept the
   full grammar even for constructs the compiler can't lower yet, so users get
   "X is not supported yet by the compiler" at the right source location
   instead of a bogus syntax error.
5. **Recursive descent stays.** nft needs 56 flex start conditions, 68 push
   sites, ~50 `close_scope_*` epsilon rules and a deferred-pop refcount just
   to make its ~394 keywords context-dependent. Our parser gets that for free
   by matching identifier strings in context. No keyword table, ever.
6. **The compiler is our `evaluate.c`.** Type interpretation, byteorder,
   dependency materialization and cross-object validation belong in
   `Compiler`/`Ruleset` validators, never in the parser.

## Phase 0 — correctness divergences (bugs) — ✅ DONE

Verified against `scanner.l` on master. Each item landed with tests pinning
the official behavior (`test/linx/nft/divergence_test.exs` + unit tests),
plus formatter checks where relevant.

- [x] **Octal integers.** nft: leading-zero `decstring` parses base-8
  (`scanner.l:930`), and a partial conversion (`08`) demotes the lexeme to a
  string. Implemented exactly: `010` = 8, `08` = `:symbol` token. (Advisory
  "octal is a footgun" warning waits for Phase 5's diagnostics channel.)
- [x] **Quoted-string escapes.** Default tokenizer mode matches nft
  byte-for-byte (`\"[^"]*\"`, backslash literal); Elixir-style escapes are a
  sigil-only convenience behind the `escapes?: true` option. The Formatter
  replaces `"` with `'` in emitted strings (nft has no escape syntax) and
  never emits backslash escapes. Deliberate remaining divergence: nft allows
  raw newlines inside quoted strings; we reject them (almost certainly user
  error).
- [x] **Block comments.** Docs corrected: nft has *no* `/* */` — only `#`
  line comments (`scanner.l:134`). Still accepted inbound as a documented
  Linx extension; never emitted.
- [x] **Dotted/slashed bare strings.** `example.com`, `eth0.10`, `br-lan/wan0`
  lex as single identifier tokens; a spaced `.` remains the concatenation
  operator. (Leading `.`/`_` strings, allowed by nft, remain unsupported —
  revisit if a real conf uses them.)
- [x] **Compound time literals.** Full nft `timestring` (`1h30m10s`, `250ms`;
  strictly descending units; no week unit — `5w` lexes as `5` + `w` like
  nft). Time-vs-address ambiguity resolved by emulating flex longest-match.
  ⚠ `{:time, ms, meta}` carries **milliseconds** — this fixed a real wire
  bug: `%Set{}.timeout` is a ms field (`NFTA_SET_TIMEOUT`), and the old
  seconds token made `timeout 1h` install a 3.6-second timeout.
- [x] **Unclassifiable literals never raise in the lexer.** `1.2.3.4.5`,
  `999.0.0.1`, `08` demote to `{:symbol, …}`; the compiler rejects them with
  a located error. `0x` with no digits lexes as `0` + `x`, as nft would.
- [x] ~~Formatter quoting of reserved words~~ — **not possible**: nft's
  grammar has `identifier : STRING | LAST` (`parser_bison.y:2937`), so quoted
  strings are NOT accepted in name positions. Names colliding with active
  keywords are inexpressible in nft text; our parser stays a documented
  superset.
- [x] **`0b` binary literals** stay sigil sugar; regression test asserts the
  Formatter emits decimal only.
- [x] **Doc rot.** All `docs/**/DESIGN.md` / `EXAMPLES.md` references fixed.

## Phase 1 — expression grammar

- [x] **Bitwise/flag matching** — `tcp flags syn` (implicit bit test →
  bitwise+cmp_neq_0), `tcp flags == syn` (exact), `tcp flags &
  (fin|syn|rst|ack) == syn`, `ct mark & 0xff == 0x4`; `(a|b|c)` and bare
  `a|b` OR-combinations; tcp-flag + protocol symbolic names.
- [x] **Implicit relational** — juxtaposition carries `:implicit` (nft's
  `OP_IMPLICIT`): plain equality for ordinary fields, bit-test for flag
  fields; set-membership via `@set`/inline sets. Normalised to `:eq` in the
  static compiler, runtime compiler, and proto-context pinning.
- [x] **Concatenations** — plain and pipapo-interval; declarations, elements,
  and rule-side reg32 selector loads. (Details in Phase 6.)
- [x] **vmaps as expressions** — `tcp dport vmap @named` (verdict-register
  lookup) and inline `ct state vmap { … }` (via `__anon_vmap` sentinel the
  encoder expands). Still open: data maps (`dnat to ip saddr map @m`).
- [~] **Typed symbol resolution in the compiler** — done: icmp/icmpv6 type
  tables keyed by LHS kind, iif/oif names via `if_name2index`, ct-state names
  in vmap keys, tcp-flag names. Still open: service names (`ssh`/`https` —
  decide frozen table vs `/etc/services`), dscp/ecn/priority-class names. One
  datatype registry keyed by LHS field, shared by compiler + formatter.
- [ ] Full **`&|^<<>>` arithmetic cascade** for non-flag binops (structural
  precedence, `parser_bison.y:4397-4553`), parenthesized sub-expressions.
- [ ] Explicit **`value/mask` slash form** (`ct mark 0x4/0xff`) — distinct
  from the `& mask ==` form already done.
- [ ] **Generic prefix operator** `expr / NUM` beyond address CIDR.
- [ ] **Wildcard strings** — bare `eth*` (`ASTERISK_STRING`) + `\*` escape,
  lowering trailing-`*` to a string prefix expression. (Quoted `"eth*"` works.)
- [ ] **Symbolic ranges** deferred to the compiler (`EXPR_RANGE_SYMBOL`
  analog).
- [ ] Full **selector inventory**: `exthdr` (+ exists), `rt`, `socket`,
  `fib`, `numgen`, `hash` (jhash/symhash), `osf`, `xfrm`, `tunnel`.
- [ ] Full **payload header inventory**: `ether`, `vlan`, `arp`, `th`,
  `udplite`, `igmp`, `gre`/`gretap`, `geneve`, `vxlan`; plus full per-header
  field sets (validate against per-header tables in the compiler, not the
  parser).
- [ ] Full **`meta` key set** (~40: `time`, `day`, `hour`, `cgroup`,
  `pkttype`, `priority`, `random`, `secmark`, …) and full **`ct` key set**
  (direction-qualified `ct original saddr`, `ct helper`, `ct expiration`,
  `ct count over N`, …).

## Phase 2 — statement completeness

Official `stmt` inventory: verdict, match, payload/meta/ct set, log, reject,
nat, masq, redir, tproxy, queue, dup, fwd, set, map, synproxy, chain,
optstrip, meter, objref, stateful (counter/limit/quota/connlimit/last), xt
(rejected).

- [x] **`set` statement** — `add`/`update`/`delete @set { key }` with
  per-element `timeout` and nested stateful statements → `Expr.dynset/2` +
  nft_dynset codec (single expr via NFTA_DYNSET_EXPR, multiple via
  NFTA_DYNSET_EXPRESSIONS).
- [x] **`objref`** — `counter name`, `quota name`, `limit name` →
  `Expr.objref/2`. Still open: `synproxy name`, ct helper/timeout/expectation.
- [x] **inline `quota`** — `quota [over|until] N <unit>` → `Expr.quota/1`
  (nft_quota).
- [~] **`log`** — prefix/group/snaplen/queue-threshold/`flags
  all|skuid|ether`; plain `log` correctly uses the kernel logger (not nflog
  group 5000). Still open: `level`, per-flag `tcp seq,options`.
- [~] **`limit`** — `rate [over] N/unit [burst N packets|bytes]` +
  `limit name @obj`. Still open: byte-rate unit scaling
  (`kbytes`/`mbytes`).
- [~] **`nat`** — `to addr:port` and `to addr:port-port`. Still open: `to ip
  saddr map @m`, `netmap`, prefix targets, interval concat targets.
- [ ] `queue` full form: `queue num 3`, ranges, `bypass`/`fanout`.
- [ ] `map` statement (dynamic map updates) and `meter`.
- [ ] `dup to <addr> [device <dev>]`, `fwd to <dev>`.
- [ ] `tproxy to :port / addr:port` (family-sensitive).
- [ ] `synproxy [mss N wscale N …]` + named synproxy objref.
- [ ] Stateful statements attached to set/map elements (not just rules).
- [ ] `connlimit` (`ct count [over] N`) and `last` (`last used`).
- [ ] `optstrip` (`reset tcp option N`), tcp-option payload stmts.
- [ ] `chain` statement (inline anonymous chain jump target).
- [ ] `reject` full matrix: `with icmp/icmpv6/icmpx type <sym>`, `with tcp
  reset`, family validity rules.
- [ ] `meta`/`ct` **set** forms (`meta mark set`, `meta priority set`,
  `ct mark set`, …) — needs a setter `%Expr{}`.

## Phase 3 — table-level objects & declarations

- [~] **Named objects** — `counter`, `quota` (over/until, used; ⚠ nft accepts
  only bytes/kbytes/mbytes units, no gbytes, verified against v1.1.6), and
  `limit` land end-to-end (kind-specific body grammars, NFTA_OBJ_DATA
  encodings, objref references), all kernel-verified. Still open: `secmark`,
  `synproxy`, `ct helper`, `ct timeout`, `ct expectation`.
- [ ] **Flowtables**: full body (`hook … priority …; devices = {…}; flags
  offload; counter`) + compiler lowering + `flow add @ft` statement.
- [ ] **Set/map declaration options**: `policy performance|memory`,
  `auto-merge`, `dynamic`/`interval`/`constant` semantics enforced, `typeof
  <expr>` type spec, element `comment`s, per-element timeout/expires,
  stateful-attached elements.
- [ ] **Chain declarations**: `flags offload`, `devices = { … }` multi-device
  (have single `device`), per-family/hook priority validity, `policy` only on
  base chains.
- [ ] **Table declarations**: `flags dormant|owner|persist`, `comment`.

## Phase 4 — `include` / `define` — ✅ mostly done

- [x] **`include`** — resolved during `parse/2`/`parse_file/2`: relative to
  the including file's dir, then `:include_paths`; glob (empty wildcard OK,
  missing literal is a located error); depth cap 16; cycle detection; errors
  inside included files carry the included file's location; defines flow
  across include boundaries. Sigil mode forbids includes with a clear error.
- [~] **`define`** — top-level defines with parse-time substitution,
  order-dependent references, duplicate-define errors, use-site error
  locations, did-you-mean on unknown `$var`. Still open: `redefine`/
  `undefine`, table/chain-block scopes (nft's `SCOPE_NEST_MAX` 4).
- [ ] Property: a ruleset split across includes+defines compiles identically
  to its hand-inlined equivalent.

## Phase 5 — error quality & recovery

- [x] **Multi-error mode** — recover at rule and top-level-item boundaries
  (brace-depth-aware resync), collecting up to 10 errors like nft's
  `parser_max_errors`. `%ParseError{}` gained an `others` field (contract
  unchanged); `Exception.message/1` renders the full report with an "(N
  errors)" trailer. Tokenizer errors remain structural aborts. (Table-BODY
  item recovery is coarser than rule-level — refine if it bites.)
- [ ] **Expected-set messages** — extend dispatch-point errors ("expected
  rule statement") to enumerate the valid words in context (RD equivalent of
  bison LAC).
- [ ] **Always-located compiler errors** — thread AST meta through
  `wrap_add!` everywhere (validator `ArgumentError`s still fall back to line
  0); did-you-mean for unknown chain/set/field names.
- [ ] **Warning channel** — non-fatal diagnostics (octal literal, unused
  define, shadowed define) at compile time for sigils and as a list for
  `parse/1`.

## Phase 6 — compiler/backend parity

- [x] **Concatenated set types + pipapo interval concats** — `flags interval`
  concat sets emit NFT_SET_CONCAT + NFTA_SET_DESC_CONCAT field bounds; each
  interval element is a single entry with NFTA_SET_ELEM_KEY (start bounds) +
  NFTA_SET_ELEM_KEY_END (end bounds), 4-byte-padded per field; `10.0.0.0/24 .
  80-443` works (kernel ≥ 5.6). Address ranges work as elements + concat
  parts; compiler enforces "range elements need `flags interval`". ⚠ nft
  sends DESC_CONCAT + the flag ONLY for interval concat sets
  (`evaluate.c:5300`) — plain concat = flagless hash set with the padded
  combined key length; kernel EINVALs DESC_CONCAT without the flag.
- [x] **Protocol-context dependency generation** — per-rule proto context:
  transport matches materialise `meta l4proto`, `ip`/`ip6` matches in `inet`
  chains materialise `meta nfproto`; explicit guards pin the context;
  tcp-vs-udp and icmp-vs-ipv6 contradictions are located errors. Formatter
  folds the guard into the following payload load + uses it as a rendering
  hint (fixing `udp dport`-as-`tcp dport` and `icmpv6 type`-as-`icmp type`).
  ⚠ Kernel acceptance caught a latent Wire bug: `NFT_META_NFPROTO`/`L4PROTO`
  are **15/16**, not 12/13 (12/13 = NFTRACE/RTCLASSID); enum order after
  SKGID(11) is NFTRACE, RTCLASSID, SECMARK, NFPROTO, L4PROTO. Still open:
  ether-type deps for bridge/netdev families.
- [ ] **Ranges over host-byte-order fields** (`meta mark 10-20`) — byteorder
  conversion before range/set lookup (compiler currently refuses rather than
  mis-encode).
- [ ] **Constant folding** of binops the kernel can't evaluate; reject
  non-constant forms with a clear error.
- [ ] **Interpolation growth** — `#{…}` works in match-RHS only; extend to
  element lists, named quantities (rates/timeouts), NAT targets, and (with
  per-validator wiring) names. Every position gets a `Linx.NFT.Runtime` kind
  check.

## Verification strategy

- [x] **Differential testing against real `nft`** —
  `test/linx/nft/differential_test.exs` runs `nft --check -f` on each corpus
  file's input AND its `format/1` output, via `unshare -r -n` (unprivileged
  in dev; privileged CI job). ⚠ Running `mix` inside `unshare -r -n` needs
  `$(asdf which mix)`, an explicit `MIX_HOME`, and a private `TMPDIR` (the
  Mix pubsub dir collides with root-owned `/tmp`).
- [x] **Kernel acceptance** — `kernel_acceptance_test.exs` (`:integration`)
  pushes every emitted encoding through a real netlink socket and reads it
  back. This layer has caught 4 real bugs the text tests structurally
  couldn't (ms timeouts, ct_state key type, DESC_CONCAT flag, meta key enum).
- [x] **Measured corpus** — `aspirational_test.exs` ratchet, 9/9 fixtures.
  Each new feature adds a fixture; promotion is enforced.
- [x] **Divergence tests** — `divergence_test.exs` pins every Phase 0 item to
  official behavior with `scanner.l` line references.
- [~] **Round-trip properties** — `round_trip_property_test.exs` fixpoint +
  per-feature round-trip tests. Still open: a "tokenizer never raises on
  arbitrary bytes" totality property.
- [ ] **Import the nftables `tests/shell` corpus** + `man nft(8)` examples as
  a larger tagged golden set (beyond the hand-written aspirational fixtures).
- [ ] **Fuzzing** — StreamData over token sequences + corpus mutation for
  parser crash-freedom.
- [ ] **Behavioral test** — send real traffic through a netns pair to confirm
  rules *filter* as intended (not just that the kernel accepts them). This is
  the one rung above kernel-acceptance we don't yet have.

## Suggested next targets

Ordered by value for "load the most complex real-world rulesets":

1. **Full selector/payload inventory** (Phase 1) — `ether`/`vlan`/`arp`
   payloads and `fib`/`rt`/`socket`/`exthdr` selectors unblock bridge
   firewalls, rp_filter-style rules, and IPv6 extension-header matching.
   Each is a dispatch-table entry + field metadata + formatter case.
2. **Remaining statements** (Phase 2) — `tproxy`/`dup`/`fwd`/`synproxy` and
   full `queue`; each is parser clause + `Expr` + codec + formatter.
3. **`meta`/`ct` set forms** (Phase 2) — needed for mark-based routing
   pipelines; needs a setter `%Expr{}`.
4. **Flowtables + remaining objects** (Phase 3) — offload configs.
5. **Error/verification polish** (Phase 5 + verification) — expected-set
   messages, warning channel, fuzzing, the behavioral netns test.

Definition of done: real-world corpus pass rate ≈100% on the declarative
subset with documented exclusions; every accepted input semantically
identical to `nft` (differential + kernel-acceptance green); `format/1`
output always `nft --check`-clean; located multi-error reporting.
