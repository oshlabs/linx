# ~NFT — plan to parity with nftables

Goal: make the `~NFT` sigil / `.nft` file path a flagship-quality part of Linx —
behaviorally faithful to the official nftables parser wherever both accept an
input, honest (loud, located errors) wherever we don't accept something yet,
and with grammar coverage raised from today's ~85% common subset to
approaching 100% of the *declarative ruleset language*.

This is a maintainer doc — not shipped in the hex package, does not render on
hexdocs. Companion to `PLAN.md` (which keeps two `~NFT` compiler items that
are absorbed into Phase 6 here).

Status 2026-07-02: Phase 0 complete; differential + measured-coverage
harnesses live (`differential_test.exs` / `aspirational_test.exs` — corpus at
**4/5 fixtures fully supported**, the fifth waits on dynamic-set statements
and concat lowering); first slices of Phases 1–4 landed (see `[x]`/`[~]`
marks inline).

Baseline (2026-07): `Tokenizer` ~1,100 lines, `Parser` ~1,300 lines (recursive
descent), `Compiler` ~1,070 lines onto the `Linx.Netfilter.Ruleset`
validator-setter surface; ~169 tests incl. golden + round-trip property tests.
Reference implementation: nftables master — `src/scanner.l` (1,418 lines, 56
start conditions), `src/parser_bison.y` (6,594 lines, 398 tokens, 471
nonterminals), `src/evaluate.c` (6,611 lines). The comparative assessment that
produced this plan lives in the 2026-07-02 session notes; the load-bearing
findings are restated inline below so this doc is self-contained.

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
   instead of a bogus syntax error. (This is already the house pattern —
   flowtables/objects parse today and the compiler raises.)
5. **Recursive descent stays.** nft needs 56 flex start conditions, 68 push
   sites, ~50 `close_scope_*` epsilon rules and a deferred-pop refcount just
   to make its ~394 keywords context-dependent. Our parser gets that for free
   by matching identifier strings in context. No keyword table, ever.
6. **The compiler is our `evaluate.c`.** Type interpretation, byteorder,
   dependency materialization and cross-object validation belong in
   `Compiler`/`Ruleset` validators, never in the parser.

## Phase 0 — correctness divergences (bugs; do first) — DONE 2026-07-02

Verified against `scanner.l` on master. Each item landed with tests pinning
the official behavior (`test/linx/nft/divergence_test.exs` + unit tests),
plus formatter checks where relevant.

- [x] **Octal integers.** nft: leading-zero `decstring` parses base-8
  (`scanner.l:930`), and a partial conversion (`08`) demotes the lexeme to a
  string. Implemented exactly: `010` = 8, `08` = `:symbol` token. The
  advisory "octal is a footgun" warning waits for Phase 5's diagnostics
  channel.
- [x] **Quoted-string escapes.** Default tokenizer mode now matches nft
  byte-for-byte (`\"[^"]*\"`, backslash literal); Elixir-style escapes are a
  sigil-only convenience behind the new `escapes?: true` option. The
  Formatter replaces `"` with `'` in emitted strings (nft has no escape
  syntax, so a literal `"` is unrepresentable) and never emits backslash
  escapes. Known remaining divergence, deliberate: nft technically allows
  raw newlines inside quoted strings (`[^"]*` spans lines); we keep
  rejecting those with a located error — almost certainly user error.
- [x] **Block comments.** Docs corrected: nft has *no* `/* */` at all — only
  `#` line comments (`scanner.l:134`). Still accepted inbound as a
  documented Linx extension; never emitted.
- [x] **Dotted/slashed bare strings.** `example.com`, `eth0.10`,
  `br-lan/wan0` now lex as single identifier tokens; a spaced `.` remains
  the concatenation operator. Leading `.`/`_` strings (allowed by nft)
  remain unsupported — revisit if a real conf ever uses them.
- [x] **Compound time literals.** Full nft `timestring` implemented
  (`1h30m10s`, `250ms`; strictly descending units; no week unit — `5w` now
  lexes as `5` + `w` exactly like nft). Time-vs-address ambiguity resolved
  by emulating flex longest-match (`7d10:...` stays an IPv6 address; `10s5m`
  is two timestrings). `{:time, ms, meta}` now carries **milliseconds** —
  this also fixed a real wire bug: `%Set{}.timeout` is a millisecond field
  (`NFTA_SET_TIMEOUT`), and the old seconds-valued token made `timeout 1h`
  install a 3.6-second element timeout.
- [x] **Unclassifiable literals no longer raise in the lexer.** `1.2.3.4.5`,
  `999.0.0.1`, `08` demote to a `{:symbol, raw, meta}` token (nft's
  scanner-never-fails principle); the parser accepts it in value position
  and the compiler rejects it with a located "cannot interpret literal"
  error. `0x` with no digits lexes as `0` + `x`, as nft would.
- [x] ~~Formatter quoting of reserved words~~ **Corrected during
  implementation**: nft's grammar has `identifier : STRING | LAST`
  (`parser_bison.y:2937`) — quoted strings are NOT accepted in table/chain
  name positions, so quoting cannot help. Names colliding with always-active
  nft keywords are simply inexpressible in nft text syntax. Our parser stays
  a documented superset (accepts them bare); the differential harness flags
  such rulesets as nft-inexpressible.
- [x] **`0b` binary literals** stay as sigil sugar; regression test asserts
  the Formatter emits decimal only.
- [x] **Doc rot.** All `docs/**/DESIGN.md` / `EXAMPLES.md` references fixed
  to the real `<subsystem>-overview.md` / `<subsystem>-examples.md` names
  (also outside the NFT modules).

## Phase 1 — expression grammar completeness

Today the parser has no real expression grammar: match RHS is a single value
/ range / list / inline set, and LHS is a fixed `header field` shape. The
official grammar layers precedence structurally (C-style cascade,
`parser_bison.y:4397-4553`): `primary → shift → and → xor → or → basic →
concat → expr`, duplicated for RHS with extra forms. Recursive descent
mirrors this as one function per layer.

- [ ] Binary operators `&`, `|`, `^`, `<<`, `>>` with the official structural
  precedence; parenthesized sub-expressions. (Needed for `ct mark & 0xff`,
  `tcp flags & (syn|ack) == syn`.)
- [ ] **Implicit relational**: `expr rhs_expr` juxtaposition = `OP_IMPLICIT`
  (we already default to `:eq`; extend to set membership and flag semantics).
- [ ] Explicit `value/mask` forms (`ct mark 0x4/0xff`).
- [~] **Concatenations** (2026-07-02): parse into `{:concat_lhs, …}` /
  `{:concat, …}` AST on both key and element side; compiler rejects with a
  located error until the pipapo/concat backend lands (Phase 6).
- [ ] **Prefix as generic operator**: `expr / NUM` beyond address CIDR
  (string prefixes come via wildcard strings; see below).
- [ ] Ranges over any ordered type, including symbolic ranges deferred to the
  compiler (`EXPR_RANGE_SYMBOL` analog).
- [ ] **Wildcard strings**: nft lexes `eth*` (incl. `\*` escape) as
  `ASTERISK_STRING` and evaluation turns trailing-`*` into a prefix
  expression over the string bits. We only handle `"eth*"` in quotes; accept
  the bare form and the `\*` literal escape.
- [x] **vmaps as expressions** (2026-07-02): `tcp dport vmap @named` lowers
  to a verdict-register lookup; inline `ct state vmap { … }` lowers to an
  `__anon_vmap` sentinel the encoder expands (anonymous map + NEWSETELEM,
  mirroring `__anon_set`). Still open: data maps (`dnat to ip saddr map @m`).
- [ ] Full **selector inventory** (LHS families). Have: payload (subset),
  `meta` (subset), `ct` (subset). Missing selector families from
  `selector_expr`: `exthdr` (+ `exthdr_exists`), `rt`, `socket`, `fib`,
  `numgen`, `hash` (jhash/symhash), `osf`, `xfrm`, `tunnel`.
- [ ] Full **payload header inventory**. Have: ip ip6 tcp udp icmp icmpv6
  sctp dccp ah esp comp. Missing from `payload_expr`: `ether`, `vlan`, `arp`,
  `th` (transport-header generic), `udplite`, `igmp`, `gre`/`gretap`,
  `geneve`, `vxlan`; plus the full per-header field sets for the ones we have
  (e.g. `tcp` has `ackseq doff window urgptr mss sack-permitted mptcp md5sig
  …`; our field atoms are unvalidated pass-through today — validate against
  per-header field tables in the compiler, not the parser).
- [ ] Full `meta` key set (we list 10; nft has ~40 incl. `time`, `day`,
  `hour`, `cgroup`, `pkttype`, `priority`, `random`, `secmark`, …) and full
  `ct` key set (direction-qualified forms: `ct original saddr`, `ct reply
  proto-dst`, `ct helper`, `ct expiration`, `ct count over N`, …).
- [~] **Typed symbol resolution in the compiler** (started 2026-07-02:
  icmp/icmpv6 type tables keyed by LHS kind; iif/oif names via
  if_name2index; ct-state names in vmap keys) — our analog of
  `symbol_parse` against the contextual datatype: service names (`ssh`,
  `https` — decide: ship a frozen table or read `/etc/services`), icmp type/
  code names, ct states/statuses, dscp/ecn names, priority class names,
  `tcp flags` names. One datatype registry keyed by the LHS field, used by
  compiler and formatter both (formatter emits the symbolic name back).

## Phase 2 — statement completeness

Official `stmt` inventory: verdict, match, payload (set), meta (set), ct
(set), log, reject, nat, masq, redir, tproxy, queue, dup, fwd, set, map,
synproxy, chain, optstrip, meter, objref, stateful (counter, limit, quota,
connlimit, last), xt (rejected).

Have today: verdicts, match, counter, log, limit (partial), nat/masq/redir,
meta-set, ct-set (partial), reject, queue (bare).

- [ ] `queue` full form: `queue num 3`, ranges, `bypass`/`fanout` flags.
- [ ] `set` statement: `add @s { tcp dport }`, `update`, `delete` — dynamic
  set updates from rules, with element timeout/expiration options.
- [ ] `map` statement (dynamic map updates) and `meter` (legacy flow tables).
- [ ] `dup to <addr> [device <dev>]`, `fwd to <dev>`.
- [ ] `tproxy to :port / addr:port` (family-sensitive).
- [ ] `synproxy [mss N wscale N timestamp sack-perm]` + named synproxy objref.
- [ ] `objref` forms: `counter name @c`/string (partially there), `quota
  name`, `limit name`, `synproxy name`, `ct helper/timeout/expectation set`.
- [ ] Stateful statements attached to set/map elements, not just rules.
- [ ] `connlimit` (`ct count [over] N`) and `last` (`last used`).
- [ ] `optstrip` (`reset tcp option N`), tcp option payload stmts.
- [ ] `chain` statement (inline anonymous chain jump target).
- [ ] `reject` full matrix: `with icmp/icmpv6/icmpx type <sym>`, `with tcp
  reset`, family validity rules (compiler).
- [~] `log` (2026-07-02): prefix/group/snaplen/queue-threshold/`flags
  all|skuid|ether` land end-to-end, and plain `log` no longer silently gets
  the pipeline-DSL nflog group 5000 (kernel-logger semantics preserved).
  Still open: `level`, per-flag `tcp seq,options` forms.
- [~] `limit` (2026-07-02): `rate [over] N/unit [burst N packets|bytes]`
  lowers to a new `Expr.limit/1` + nft_limit encoder/decoder support.
  Still open: byte rates with unit scaling (`kbytes`/`mbytes`), `limit
  name @obj`.
- [~] `nat` (2026-07-02): `to addr:port` and `to addr:port-port` land (the
  tokenizer now splits `1.2.3.4:8080` the way flex longest-match does).
  Still open: `to ip saddr map @m`, `netmap`, prefix targets, interval
  concat targets.
- [ ] `meta` statement forms that *set* (`meta mark set`, `meta priority set`,
  `meta pkttype set`, `meta nftrace set`) — compiler lowering included
  (PLAN.md's "no setter %Expr{} yet" item).

## Phase 3 — table-level objects & declarations

- [~] Named objects (2026-07-02): `counter` objects land end-to-end —
  declaration → `%Object{}` in the table, NEWOBJ batch encoding, `counter
  name "x"` → new `Expr.objref/2` (nft_objref). Still open: `quota`
  (incl. `over`/`until`, used bytes), `limit`, `secmark`, `synproxy`,
  `ct helper`, `ct timeout`, `ct expectation` — per-kind grammars,
  NFTA_OBJ_DATA encodings, and validation.
- [ ] Flowtables: full body (`hook … priority …; devices = {…}; flags
  offload; counter`) + compiler lowering + `flow add @ft` statement.
- [ ] Set/map declarations: missing options — `policy performance|memory`,
  `auto-merge`, `dynamic`/`interval`/`constant` flag semantics enforced,
  `typeof <expr>` as the type spec (in addition to `type <datatype>`),
  element `comment`s, per-element timeout/expires, `counter`/stateful
  attached to elements.
- [ ] Chain declarations: `flags offload`, `devices = { … }` multi-device
  (have single `device`), named priorities per family/hook validity table
  (compiler currently resolves aliases; add validity), `policy` only on base
  chains (validate).
- [ ] Table declarations: `flags dormant|owner|persist`, `comment`.
- [ ] `flush ruleset` semantics beyond noop when we grow multi-table merge.

## Phase 4 — `include` / `define` semantics

nft resolves both **during parsing**: `include` pushes a flex buffer
(depth cap `MAX_INCLUDE_DEPTH` 16, `-I` search paths + default path, full
glob(3) expansion, directories skipped, FIFOs rejected); `define` binds an
*unevaluated* expression in a lexically nested scope (`SCOPE_NEST_MAX` 4,
scopes opened by table/chain blocks) and `$var` resolves at parse time, with
did-you-mean suggestions.

- [ ] `include`: resolve in `parse_file/1` relative to the including file,
  add `:include_paths` option, glob support, depth cap 16, cycle detection
  (nft only has the depth cap — we can do better), errors located at the
  `include` line. Sigil mode: either forbid (clear error, current behavior)
  or resolve relative to the `.ex` file — decide during implementation;
  forbidding is the safe default.
- [~] `define` (2026-07-02): top-level defines with parse-time substitution,
  order-dependent references, duplicate-define errors, use-site error
  locations, and did-you-mean on unknown `$var`. Still open: `redefine`/
  `undefine`, table/chain-block scopes (max nesting 4).
- [ ] Property: a ruleset split across includes+defines compiles identically
  to its hand-inlined equivalent.

## Phase 5 — error quality & recovery

nft recovers at statement separators (one `error stmt_separator` production),
reports up to `parser_max_errors` (10) per run, and uses bison LAC to print
exact "expected any of: …" token sets; every error carries a source-excerpt
location. We fail fast on the first error with a caret snippet.

- [ ] **Multi-error mode**: on parse error, synchronize to the next
  `:stmt_sep` at the current nesting depth (RD can sync smarter than nft's
  line-level recovery), collect up to 10 `%ParseError{}`s, return
  `{:error, [errors]}` from `parse/1` (keep raising the *first* in sigil
  mode, but print the rest as compiler diagnostics).
- [ ] **Expected-set messages**: our `expect_*!` helpers already know what
  they wanted; extend dispatch-point errors ("expected rule statement") to
  enumerate the valid words in that context — the RD equivalent of LAC, and
  we can curate phrasing where 40 alternatives would be noise.
- [ ] Compiler errors: always located (today validator `ArgumentError`s fall
  back to line 0 — thread AST meta through `wrap_add!` everywhere), and
  did-you-mean for unknown chain/set/field names.
- [ ] Warning channel (non-fatal diagnostics: octal literal, unused define,
  shadowed define) surfaced at compile time for sigils and as a list for
  `parse/1`.

## Phase 6 — compiler/backend parity items

The parser accepting a construct is not "support"; these close the loop so
accepted syntax reaches the kernel. Includes the two items parked in
`PLAN.md`:

- [ ] Ranges over host-byte-order fields (`meta mark 10-20`) — byteorder
  conversion before range/set lookup.
- [ ] Concatenated set types + pipapo-backed concatenated ranges
  (`NFTA_SET_ELEM_KEY_END`, kernel ≥ 5.6).
- [ ] **Protocol-context dependency generation** — the crown feature of
  `evaluate.c`: `tcp dport 22` in an `inet` chain auto-materializes `meta
  l4proto tcp`; `ip saddr` in a netdev/bridge chain materializes the ether
  type dependency. Track a per-rule protocol context in the compiler; reject
  contradictions (`ip saddr` after `meta nfproto ipv6`) with both locations.
- [ ] Constant folding of binops the kernel can't evaluate (nft folds in
  `evaluate.c`); reject non-constant forms with a clear error.
- [ ] Interpolation growth: today `#{…}` works in match-RHS only. Extend to
  element lists, named quantities (rates, timeouts), NAT targets, and —
  with per-validator wiring — names (table/chain/set) where the runtime
  type-check story is clear. Every new position gets a `Linx.NFT.Runtime`
  kind check.

## Verification strategy (how we know we're at parity)

This is the backbone; each phase above lands with its slice of these:

- [ ] **Differential testing against real `nft`** (the single highest-value
  item). In the privileged CI job: for every corpus file, run `nft --check
  -f` on (a) the input and (b) our `format/1` output, and compare our
  compiled netlink bytes against `nft --debug=netlink -f` where practical.
  Locally available via `sudotest.sh` (mind the asdf-shim/MIX_HOME quirks
  noted in memory).
- [ ] **Corpus**: import the nftables source tree's `tests/shell/testcases`
  ruleset payloads and the `man nft(8)` examples as golden files, tagged by
  phase, with a tracked pass-rate number. This replaces the fuzzy "~85%"
  with a measured coverage figure; "approaching 100%" = corpus pass rate on
  the declarative subset, reported in CI.
- [ ] **Round-trip properties** (extend existing): `parse |> format |> parse`
  fixpoint; tokenizer never raises on arbitrary bytes once Phase 0's symbol
  fallback lands (property: tokenize/2 total); compound-time and numeric
  literal round-trips against nft's interpretation.
- [ ] **Divergence tests**: a dedicated test module pinning every Phase 0
  item to the official behavior with `scanner.l` line references in
  comments, so a future "cleanup" can't silently reintroduce them.
- [ ] Fuzzing pass (StreamData over token sequences + mutation of corpus
  files) for parser crash-freedom: every input either parses or returns a
  located `ParseError` — never an exception escape or infinite loop.

## Sequencing & sizing

Rough order of attack; phases are independent enough to interleave, but 0 and
the corpus harness come first because everything else is measured against
them.

1. **Phase 0 + corpus harness** (small/medium) — correctness first; the
   differential harness turns the rest of the plan into a burndown.
2. **Phase 1** (large) — the expression grammar is the structural
   prerequisite for most of Phase 2's statements.
3. **Phase 2 + 3** (large, parallelizable per-statement) — each statement/
   object lands parser + compiler + formatter + corpus tests together.
4. **Phase 4** (medium) — include/define; unblocks importing real-world
   distro rulesets into the corpus.
5. **Phase 5** (medium) — error/recovery polish once the grammar is stable.
6. **Phase 6** (large) — backend parity, protocol-context tracking last since
   its scope depends on which selectors landed.

Definition of done: corpus pass rate ≈100% on the declarative subset with
documented exclusions; every accepted input semantically identical to `nft`
(differential job green); `format/1` output always `nft --check`-clean;
multi-error reporting with located, expected-set messages; zero
tokenizer-raises on arbitrary input.
