# Linx.Netfilter — implementation plan

> 🟢 **N0–N8 shipped; N9 (mix format plugin) remaining.** The
> v1.0 core (N0 scaffolding + Nfnl socket → N1 value types +
> pipeline DSL → N2 minimal expressions + push → N3 NAT → N4
> sets/maps/vmaps → N5 diff + `:reconcile` + BATCH_GENID CAS →
> N6 monitor socket → N7 NFLOG) all landed on the
> `netfilter-foundations` branch (commits N0..N7). N8 (`~NFT`
> sigil + Conf parser) shipped as eleven sub-commits N8a..N8k on
> `netfilter-nft-sigil` — see the N8 section below for what each
> covered. The remaining N9 work (the `mix format` plugin) plus a
> long tail of per-construct extensions (`limit`, meta/ct
> setters, named objects, flowtables, concat keys, NPTv6,
> includes/defines, the deferred expressions listed in
> *Deferred*) ships as future per-feature commits. `COVERAGE.md`
> is the canonical "what's in / what's deferred" tracker.

## Goal

Build `Linx.Netfilter`: the kernel's modern firewall surface
(**nf_tables** via the **nfnetlink** netlink protocol family,
`NETLINK_NETFILTER` = 12), exposed as idiomatic Elixir primitives.
Plus the live-monitoring side (subscription to `NFNLGRP_NFTABLES`
multicast) and the packet-event side (NFLOG via `NFNL_SUBSYS_ULOG`).

The driving use cases — concrete and load-bearing:

1. **Nerves as a firewall appliance.** Full incoming / outgoing /
   forwarding policy + SNAT/DNAT/masquerade, configured
   programmatically from an embedded Elixir release, supervised
   under OTP. Kernel target: stock Nerves system (currently 6.6
   LTS-based).

2. **Container firewalling, both sides of the veth.** From the host:
   govern the veth peer of a `Linx.Process`-spawned workload via
   the host's nftables. From inside the workload's netns: push
   container-local rules via `Nfnl.open({:pid, host_pid})`. Same
   value type, same verbs, just pointed at a different netns.

3. **Source-of-truth round-trip with `nftables.conf` files.** Import
   a hand-written conf, edit programmatically, export back. Reach
   parity with what `nft -f` / `nft list ruleset` do, but with the
   ruleset as a first-class Elixir value at every step.

4. **Live observability.** Subscribe to ruleset-change broadcasts
   (catch out-of-band edits by `nft` / `firewalld` / operators);
   receive packet-match events via NFLOG with structured prefix and
   mark identifiers — both as messages in the owner-process mailbox,
   the same idiom every other Linx subsystem uses.

`Linx.Netfilter` is **not** a firewall policy engine, a container
runtime, or an `iptables-translate` substitute. It exposes
"build/push/pull/diff a Ruleset", "subscribe to changes", "log
packets to me" — the policy decisions (what to allow, what to log,
how to compose) live in consumers.

## Guiding principles

### Value, not handle

`%Linx.Netfilter.Ruleset{}` is plain data — tables containing
chains containing ordered rules, plus sets/maps/vmaps and named
objects (counters, quotas, ct helpers). Pure Elixir values, no
references to kernel state, freely composable and inspectable.
Four verbs in / out:

- **`build`** — construct a ruleset value (pipeline DSL or
  `~NFT` sigil).
- **`push/2`** — write it to the kernel atomically (`:replace`
  rebuilds, `:reconcile` computes minimal diff).
- **`pull/1..2`** — read kernel state into a ruleset value (whole
  netns, or one table by name).
- **`diff/2`** — compute the patch between two ruleset values.

Kernel state lives in the kernel; the Elixir value is the Elixir
value. Identity is by name (tables, chains, sets, maps, named
objects) or by tag (rules — see *Tag-as-converged-identity*
below).

The model mirrors `%Linx.Seccomp.Filter{}` scaled to a much
larger surface: testability, composability, and a single
encoder/decoder pair between value and kernel.

### Peers, not layers

`~NFT` sigil and pipeline DSL are **peer authoring surfaces**, not
one built on top of the other. Both produce the same
`%Linx.Netfilter.Ruleset{}` value, the way HEEx
(`Phoenix.LiveView.HTMLEngine`) and Phoenix function components
both produce `%Phoenix.LiveView.Rendered{}`.

Plumbing:

```
              ┌───────────────────┐
   Pipeline   │                   │   Pipeline construction:
   DSL  ──────┤                   │   Ruleset.new()
              │   validator-      │   |> Ruleset.add_table(...)
              │   setter          │   |> Table.add_chain(...)
              │   functions       │
   ~NFT ──────┤                   │   ~NFT sigil:
   sigil      │   produce         │   ~NFT"""
              │   %Ruleset{}      │     table inet myapp {...}
              │                   │   """
   .nft  ─────┤                   │
   file       │                   │   File mode:
              └─────────┬─────────┘   Conf.parse/1
                        │
                        ▼
              ┌───────────────────┐
              │  wire encoder     │   Encoder.to_batch/1 → nfnetlink
              │  (Ruleset →       │   batched netlink messages over
              │   nfnetlink)      │   the Linx.Netlink.Nfnl socket.
              └───────────────────┘   No re-validation here.
                        │
                        ▼
                     kernel
```

A small set of **validator-setter functions** —
`Ruleset.add_table/3`, `Table.add_chain/3`, `Chain.add_rule/2`,
`Set.add_elements/2`, … — are the only path that mutates a
Ruleset. They validate (chain hooks well-formed, vmap key types
match, expression sequences type-consistent, set elements match
the declared key type) and return `{:ok, ruleset}` or
`{:error, reason}`. The pipeline DSL is exactly the public-API
export of those functions; the sigil parser calls the same
validators internally. **No duplicated validation.**

The AST is the contract. Once `%Ruleset{}` is public-stable,
sigil-parsed and pipeline-constructed values are interchangeable —
you can write half a rule via pipeline and `~NFT` the other half,
and they merge.

### Transactions are mandatory

Every ruleset mutation goes through a `NFNL_MSG_BATCH_BEGIN` /
`NFNL_MSG_BATCH_END` envelope; the kernel applies the whole batch
atomically or rejects it whole. **`push/2` is the only kernel
mutator**, and it's batch-shaped from the outside in. Partial
commits are an anti-pattern we never expose.

Modes:

- **`:replace`** — tear down and rebuild the named tables; simple,
  brief disruption to existing connections.
- **`:reconcile`** — compute the minimal patch between current
  kernel state and the desired Ruleset, emit as one batch. No
  service interruption when only adding/removing rules at the
  margins.

Both useful. `:reconcile` is the LiveView-of-firewalls mode.

### Optimistic concurrency via `NFNL_BATCH_GENID`

`NFNL_BATCH_BEGIN` accepts an optional `NFTA_BATCH_GENID` attribute:
"I computed this batch against generation N; reject if the current
generation isn't N." Kernel returns `ERESTART` on mismatch.

This is the canonical compare-and-swap primitive — `push/2` with
`:reconcile` mode threads it automatically:

1. `pull` captures generation N.
2. Compute diff against N.
3. Emit batch with `NFTA_BATCH_GENID = N`.
4. If `ERESTART`: retry from step 1 (with bounded attempts).

Lets callers cooperate cleanly with `nft` CLI, firewalld, k8s
kube-proxy, and any other writer in the same netns.

### Tag-as-converged-identity

Three per-rule fields, one for each layer:

- **`handle`** — kernel-assigned `u64`, opaque, returned in
  `NEWRULE` ACK / on `pull`. `nil` until the rule has been pushed.
  Used for in-place `NLM_F_REPLACE` and `DELRULE` by handle.
- **`tag`** — user-chosen semantic identifier. Survives across
  reloads. Used for **stable identity in `:reconcile` diffing**
  (so reordering two adjacent rules in source doesn't produce
  spurious delete+create pairs) AND for **NFLOG/NFQUEUE callback
  identity** (the prefix string the rule sets via `log prefix
  "ssh-attempt"` is derived from the tag).
- **`comment`** — free-form, round-trips via `NFTA_*_USERDATA`,
  also visible to `nft list ruleset` consumers.

The convergence — tags double as the diff identity and the
log-event identity — is what makes tagging the natural thing for
the user to do rather than an obligation. **In `:reconcile`
mode, tags are required**; the `:replace` path tolerates
untagged rules.

### Ownership is a kernel-enforced default

`flags owner` on a table (Linux 5.19+) ties the table's lifetime to
the netlink socket that created it: when the socket closes, the
table is destroyed. Linx makes this the **default for
`Linx.Netfilter.create_table/2`**. The supervisor that opens the
Nfnl socket owns the firewall; if it dies (crash, shutdown, redeploy),
rules vanish. No leaked rules across restarts; no zombie state.

Opt out with `persist: true` (uses the `persist` flag, 6.9+, falls
back to no-owner if older kernel) for cases where rules should
survive the BEAM (e.g. shipping a static policy at boot, then
relinquishing).

This is genuinely uniquely Linx-shaped — no other firewall
management tool exposes the kernel's `owner` flag as the default
mode. It's the BEAM-process-owns-the-firewall story.

### Per-netns isolation, free

Each netns has fully independent nftables state — own tables, own
generation counter, own commit mutex, own multicast group.
`Linx.Netlink.Nfnl.open({:pid, child_pid})` opens the socket
inside that netns for its whole life; reads/writes through that
socket land in the child's nftables instance, not the host's.
Same value type, same verbs.

### Direct netlink, no externals

No `nft` binary dependency, no `libnftables` FFI, no subprocess.
Linx encodes/decodes the nfnetlink wire format directly using the
existing `use Linx.Netlink.Codec` DSL, parallel to how
`Linx.Netlink.Rtnl` works. The kernel target floor is
**Linux 6.6 LTS** (the practical Nerves baseline; supported by
gregkh through Dec 2027); the design target is **6.12 LTS**
(features like `persist` available unconditionally); 6.6→6.11
gets the same surface with `persist`-using features
feature-detected and gracefully downgraded.

### `~NFT` is the headline ergonomic feature

A Phoenix-HEEx-style sigil that parses real nft syntax verbatim
at compile time. Compile-time errors with file:line:column,
type-aware Elixir interpolation (`~NFT"tcp dport #{port} accept"`
where `port` must be an integer or set-of-integers — checked at
the interpolation site), and lossless round-trip with
`nftables.conf` files. Both surfaces converge on the same AST.

Scope at v1.5: **the ~85% subset** — tables, chains (all
hooks/priorities/policies), rules with the common matches
(`ip/ip6 saddr/daddr`, `tcp/udp sport/dport`, `meta iif/oif/mark`,
`ct state`) and the common statements
(`accept/drop/reject/jump/goto/return/log/counter/limit/dnat/snat/masquerade/redirect`),
basic named/anonymous sets/maps/vmaps, includes. The 15% tail
(`tproxy`, `osf`, `synproxy`, `secmark`, raw payload `@th,0,16`,
`numgen`, `jhash`, `xt` compat) ships as later milestones.

Implementation: **handwritten** char-by-char tokenizer +
token-stream parser + AST compiler — same pattern as
`Phoenix.LiveView.TagEngine.Tokenizer/Parser/Compiler`. Not
NimbleParsec (context-sensitive lexing with 50+ start conditions
in nft's flex grammar is genuinely awkward for combinator
libraries).

### `AGENTS.md` style throughout

`@moduledoc` / `@doc` / `@spec` everywhere; domain data as
structs with `@enforce_keys`; one module per file; cite kernel
UAPI headers (`include/uapi/linux/netfilter/nf_tables.h`,
`nfnetlink.h`, `nfnetlink_log.h`) and `wiki.nftables.org` in
comments where interpretation is non-obvious.

## Module structure

```
Linx.Netfilter                — public-facing concept module:
                                supported?/0, create_table/2,
                                push/2, pull/1..2, diff/2,
                                subscribe/1, log_listen/2.

Linx.Netfilter.Ruleset        — %Ruleset{} top-level value type;
                                pipeline DSL: new/0, add_table/3,
                                pull validation, encode/decode helpers.

Linx.Netfilter.Table          — %Table{family, name, flags,
                                use_count, handle, chains, sets,
                                maps, objects, flowtables}; add_chain/4,
                                add_set/4, add_map/4, add_object/3,
                                add_flowtable/4.

Linx.Netfilter.Chain          — %Chain{table, name, type, hook,
                                priority, policy, device, handle,
                                rules}; add_rule/2.

Linx.Netfilter.Rule           — %Rule{chain, expressions, handle,
                                tag, comment}; expression-tree
                                construction helpers.

Linx.Netfilter.Expr           — %Expr{name, data} tagged-union;
                                construction helpers per kind
                                (Expr.cmp/3, Expr.payload/3, Expr.ct/2,
                                Expr.bitwise/3, Expr.immediate/2,
                                Expr.lookup/2, Expr.nat/2, …).

Linx.Netfilter.Verdict        — %Verdict{kind, target}: :accept |
                                :drop | :continue | :return |
                                {:jump, chain} | {:goto, chain} |
                                {:queue, num} | :reject | …

Linx.Netfilter.Set            — %Set{table, name, key_type,
                                flags, elements, timeout,
                                gc_interval, size, handle};
                                add_elements/2, delete_elements/2.

Linx.Netfilter.Map            — %Map{table, name, key_type,
                                data_type, ...}; same shape as Set.

Linx.Netfilter.Vmap           — verdict map (`%Map{}` with
                                `data_type: :verdict`).

Linx.Netfilter.Object         — %Object{kind, table, name, data}
                                for counters, quotas, limits,
                                ct helpers, ct timeouts, secmarks,
                                synproxies.

Linx.Netfilter.Flowtable      — %Flowtable{table, name, hook,
                                priority, devices, flags}.

Linx.Netfilter.Patch          — %Patch{ops: [...]} value returned
                                by diff/2; ops are :create_table,
                                :create_chain, :create_rule (with
                                position: {:after, handle: n}),
                                :replace_rule, :delete_rule,
                                :add_elements, :delete_elements, …

Linx.Netfilter.Encoder        — Ruleset / Patch → nfnetlink
                                batched messages. Uses
                                Linx.Netlink.Codec DSL.

Linx.Netfilter.Decoder        — nfnetlink messages → Ruleset
                                / per-entity values.

Linx.Netfilter.Monitor        — GenServer wrapping a second
                                Nfnl socket subscribed to
                                NFNLGRP_NFTABLES; emits
                                {:linx_netfilter, :event, ...}
                                to the owner; handles ENOBUFS
                                recovery via re-pull.

Linx.Netfilter.Log            — GenServer wrapping a NFLOG socket
                                (NFNL_SUBSYS_ULOG); per-group
                                config; emits {:linx_netfilter,
                                :log, %Log.Event{}} to the owner.

Linx.Netfilter.Error          — %Error{operation, errno, code,
                                subsys, msg_type, attr_offset,
                                batch_seq, ruleset_gen, message}
                                + Exception impl + from_posix/N.

Linx.Netlink.Nfnl             — transport layer: open/0, open/1
                                (with {:pid, n} or {:path, p}),
                                close/1, request/2, batch/2,
                                subscribe/2 — parallel to
                                Linx.Netlink.Rtnl.

Linx.Netlink.Nfnl.Codec       — wire encoders/decoders for the
                                nfnetlink-specific framing
                                (nfgenmsg header, subsys_id high
                                byte of nlmsghdr.type, BATCH_BEGIN
                                / BATCH_END semantics).

Linx.NFT                      — public-facing module for the
                                ~NFT sigil and Conf file mode:
                                sigil_NFT/2, parse/1, parse_file/1,
                                format/1, format_file/1.

Linx.NFT.Tokenizer            — handwritten char-by-char lexer
                                (state machine with explicit
                                start-condition stack, mirroring
                                nft's scanner.l).

Linx.NFT.Parser               — handwritten token-stream parser
                                (recursive-descent, with a token_stack
                                + buffer stack, mirroring HEEx's
                                tag_engine/parser.ex).

Linx.NFT.Compiler             — AST → calls to validator-setter
                                functions on Linx.Netfilter.Ruleset
                                producing %Ruleset{} (or compile-time
                                error with file:line:column). Used by
                                the static-body sigil path and by
                                parse/1 + parse_file/1.

Linx.NFT.RuntimeCompiler      — AST → quoted Elixir code that
                                builds a %Ruleset{} at runtime.
                                Used by the sigil's interpolation-
                                bearing path (HEEx-style): at each
                                :elixir_expr value position, emits
                                a Linx.NFT.Runtime call so the
                                interpolated value is encoded for
                                the typed field.

Linx.NFT.Runtime              — runtime helpers for interpolated
                                ~NFT bodies. cmp!/3, encode_int!/2,
                                encode_ipv4!/1, encode_ipv6!/1,
                                encode_ifname!/1. Raises ArgumentError
                                on type mismatch.

Linx.NFT.ParseError           — dedicated error struct with
                                {file, line, column, snippet, message}
                                + raise_syntax_error!/2 helper,
                                modelled on
                                Phoenix.LiveView.TagEngine.Tokenizer.ParseError.

Linx.NFT.Formatter            — canonical-emit pretty-printer.
                                format/1 walks a %Ruleset{} and
                                produces syntactically-valid nft
                                source. Round-trip (parse → format →
                                parse) is structurally identical
                                for the supported slice.

Linx.NFT.Formatter (N9 work)  — mix format plugin behaviour
                                (features: [sigils: [:NFT],
                                extensions: [".nft"]]) — ships in
                                N9 by delegating to the existing
                                canonical-emit Formatter.

  build
  c_src/                      — no C source for Linx.Netfilter
                                proper. The existing
                                c_src/netlink_socket.c handles
                                the NETLINK_NETFILTER socket
                                (just a different protocol number;
                                no new NIF needed).
```

No NIF, no Port, no external binary. Pure Elixir over the
existing netlink-socket NIF infrastructure.

## The nfnetlink wire surface

A short primer so the milestones can refer back to wire-format
specifics without re-explaining.

### Transport

```
socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER /* = 12 */)
```

Every message:

```
+-------------------+
| struct nlmsghdr   |    16 bytes
|   nlmsg_len       |    total message length (incl. nlmsghdr)
|   nlmsg_type      |    (subsys_id << 8) | msg_type   -- 16 bits
|   nlmsg_flags     |    NLM_F_REQUEST | _DUMP | _ACK | _CREATE | …
|   nlmsg_seq       |    caller-chosen, kernel echoes in ACK
|   nlmsg_pid       |    kernel-assigned on bind
+-------------------+
| struct nfgenmsg   |    4 bytes
|   nfgen_family    |    NFPROTO_IPV4=2, IPV6=10, INET=1, ARP=3,
|                   |    BRIDGE=7, NETDEV=5, UNSPEC=0
|   version         |    NFNETLINK_V0 = 0
|   res_id          |    per-subsystem; for nf_tables mostly unused,
|                   |    for ULOG: big-endian u16 group number
+-------------------+
| NLA TLVs ...      |    attributes (NFTA_*)
+-------------------+
```

### Sub-subsystem multiplexing

`nlmsghdr.type` is `(subsys_id << 8) | msg_type`. nfnetlink
sub-subsystems live inside one netlink family (`nfnetlink.h`):

| subsys_id | Name | Linx module |
|---|---|---|
| 0 | NONE | — |
| 1 | CTNETLINK (conntrack) | (deferred — `Linx.Netfilter.Conntrack`) |
| 2 | CTNETLINK_EXP (expectations) | (deferred) |
| 3 | QUEUE (NFQUEUE) | (deferred — `Linx.Netfilter.Queue`) |
| 4 | ULOG (NFLOG) | N7 — `Linx.Netfilter.Log` |
| 5 | OSF | (deferred) |
| 6 | IPSET | (out of scope — superseded by nft sets) |
| 7 | ACCT | (deferred) |
| 8 | CTNETLINK_TIMEOUT | (deferred) |
| 9 | CTHELPER | (deferred — named-object surface) |
| **10** | **NFTABLES** | **N0–N7 — `Linx.Netfilter` core** |
| 11 | NFT_COMPAT | (out of scope — migration shim) |
| 12 | HOOK | (deferred — hook introspection) |

### Batched transactions

```
NFNL_MSG_BATCH_BEGIN  res_id = NFNL_SUBSYS_NFTABLES (10)
                      family = AF_UNSPEC
                      seq    = N
                      [optional: NFTA_BATCH_GENID = current_gen]

  NFT_MSG_NEWTABLE    seq = N+1
  NFT_MSG_NEWCHAIN    seq = N+2
  NFT_MSG_NEWRULE     seq = N+3
  ...

NFNL_MSG_BATCH_END    res_id = NFNL_SUBSYS_NFTABLES
                      seq    = N+k
```

Properties:

- **All-or-nothing**: any inner message rejection rolls back the
  whole batch. Kernel returns `NLMSG_ERROR` with the offending
  inner seq + attr offset.
- **Missing BATCH_END** ⇒ kernel discards (deliberate rollback;
  libnftables uses this for `nft --check`).
- **`NFTA_BATCH_GENID`** on `BATCH_BEGIN` ⇒ kernel rejects with
  `ERESTART` if generation has moved. The CAS primitive.

### Message type opcodes (nf_tables, subsys 10)

Combined wire-type = `0x0a00 | low_byte`:

| Op | Name | Direction |
|---|---|---|
| 0x00/01/02 | NEW/GET/DEL TABLE | mutate / query / delete |
| 0x03/04/05 | NEW/GET/DEL CHAIN | |
| 0x06/07/08 | NEW/GET/DEL RULE | |
| 0x09/0a/0b | NEW/GET/DEL SET | |
| 0x0c/0d/0e | NEW/GET/DEL SETELEM | |
| 0x0f/10/11 | NEWGEN / GETGEN / TRACE | gen broadcast / query / per-rule trace |
| 0x12-0x15 | NEW/GET/DEL/GETRESET OBJ | named objects |
| 0x16/17/18 | NEW/GET/DEL FLOWTABLE | |
| 0x19 | GETRULE_RESET | get + atomic counter reset |
| 0x1a-0x20 | DESTROYTABLE/CHAIN/RULE/SET/SETELEM/OBJ/FLOWTABLE | idempotent delete (5.18+) |
| 0x21 | GETSETELEM_RESET | get + atomic stateful-set reset |

`DESTROY*` variants **suppress ENOENT** — the right primitive for
declarative reconcile ("ensure absent"). Linx uses these on 6.6+;
falls back to `DEL*` only on `EOPNOTSUPP` from older kernels.

### Generation counter

`NFTA_GEN_ID` (32-bit, monotonic, bumped per successful commit) is
the consistency primitive:

- `NFT_MSG_GETGEN` query reads it; reply carries
  `NFTA_GEN_ID + NFTA_GEN_PROC_PID + NFTA_GEN_PROC_NAME`
  (last two attribute the most recent committer — free
  observability).
- `NFT_MSG_NEWGEN` broadcast after each commit carries the same.
- Used three ways:
  - `:reconcile`-mode CAS via `NFTA_BATCH_GENID`.
  - Subscribe-then-pull-then-process: capture gen at pull, discard
    queued events with `gen_id ≤ N` to avoid re-processing.
  - Batch grouping in broadcast: events between `NEWGEN(N)` and
    `NEWGEN(N+1)` belong to the same commit.

### Handles vs names

- Tables, chains, sets, maps, objects addressed by **name**
  (user-chosen, unique within scope).
- Rules addressed by **handle** (kernel-assigned u64, returned in
  `NEWRULE` ACK when `NLM_F_ECHO` is set).
- `NLM_F_REPLACE` on `NEWRULE` with the handle swaps a rule in
  place atomically.
- **In-place mutable**: rule body (via REPLACE), table flags,
  chain policy, set elements, object contents.
- **Requires delete + recreate**: chain hook type / hooknum /
  family; set key_type / key_len / data_type; table family.
  Linx's diff detects these and synthesises del+new inside one
  batch.

### User data

`NFTA_*_USERDATA` is an opaque byte blob the kernel doesn't
interpret. libnftables uses it for the `comment "..."` string and
private metadata, with its own private TLV format. Linx
defines its own TLV encoding for our `tag` field and `comment`
field, marked with a Linx-specific magic prefix so we can
distinguish "ours" from "someone else's userdata" on pull. Foreign
blobs are preserved verbatim on read (so we don't clobber
firewalld/nft metadata on round-trip).

## Architecture deep-dive

### The two-socket pattern

Each `Linx.Netfilter` instance opens **two** Nfnl sockets:

1. **RPC socket** — request/reply + batched transactions. Used by
   `push/2`, `pull/1..2`, `create_table/2`. Short-lived requests,
   no multicast subscription, ENOBUFS doesn't apply.

2. **Monitor socket** (lazy, opened only when `subscribe/1` is
   called) — subscribed to `NFNLGRP_NFTABLES`. Receives multicast
   events from every successful commit in the netns (yours and
   others'). Aggressively read; ENOBUFS-prone under high churn.

Mixing them is a footgun: a slow consumer on the RPC socket
makes ENOBUFS on the monitor side harder to recover from, and
vice versa. Each gets its own GenServer with its own `recv` loop.

NFLOG opens a **third** socket of its own when `log_listen/2` is
called — different sub-subsystem (NFNL_SUBSYS_ULOG, not
NFTABLES), different multicast group, different config protocol.
Same plumbing, different decoder.

### Validator-setter functions

Every Ruleset mutation goes through one of these — the only path
that writes to `%Ruleset{}` fields. Shape:

```elixir
@spec add_chain(Ruleset.t(), table_name, opts) ::
        {:ok, Ruleset.t()} | {:error, reason}
def add_chain(%Ruleset{} = rs, table_name, opts) do
  with {:ok, table} <- fetch_table(rs, table_name),
       {:ok, chain} <- build_chain(opts),
       :ok          <- validate_chain(chain, table) do
    put_chain(rs, table_name, chain)
  end
end
```

Validations enforced at this layer:

- Names unique within scope (chain names within table, table
  names within family, etc.).
- Chain hook + priority + type combinations are valid for the
  family (e.g. `type nat` is invalid in `arp` family; `ingress`
  hook requires `device`; bridge family has its own priority
  range).
- Rule expressions form a well-typed sequence (loaded register
  types match compare types; verdict is terminal).
- Set element types match the set's declared `key_type`
  (including concatenations).
- Vmap data values are all verdicts.
- Rule tag uniqueness within chain (for `:reconcile`).

Errors come back as `{:error, {:bad_chain, reason}}` /
`{:error, {:bad_rule, reason}}` / etc. — distinct from kernel
rejection errors (`%Error{}`). Same `:bad_X` / `%Error{}` split
as `Linx.Mount` / `Linx.User` / `Linx.Sysctl`.

### Diff and patch

`diff/2` between two `%Ruleset{}` values produces a
`%Patch{ops: [...]}`. Identity rules per entity type:

- **Tables, chains, sets, maps, objects, flowtables**: identity
  is `name`. Standard dict diff (add / remove / modify).
- **Rules within a chain**: identity is `tag` if set, else
  positional index within chain.
- **Set elements**: identity is the element value (set
  semantics, no "modified").

Patch operations:

- `{:create_table, %Table{}}`
- `{:delete_table, name}`
- `{:create_chain, table_name, %Chain{}}`
- `{:delete_chain, table_name, chain_name}`
- `{:create_rule, table_name, chain_name, %Rule{}, position}` —
  `position` is `:append` | `{:after, handle: n}` | `{:before,
  handle: n}` | `{:at_index, n}` (for untagged rules)
- `{:replace_rule, table_name, chain_name, handle, %Rule{}}` —
  via `NLM_F_REPLACE`
- `{:delete_rule, table_name, chain_name, handle}`
- `{:add_elements, table_name, set_name, [elements]}`
- `{:delete_elements, table_name, set_name, [elements]}`
- `{:create_object, ...}` / `{:delete_object, ...}` / ... etc.

**Patch ordering matters even within a batch.** Creates of
dependencies before dependents; deletes in reverse. Otherwise
kernel rejects with `EOPNOTSUPP`. Linx topologically sorts ops
before encoding.

**In-place vs delete+recreate detection.** A per-entity allowlist
of attributes that are `NLM_F_REPLACE`-modifiable; mutations
outside the allowlist (chain hook change, set key type change)
become `{:delete_*, ...} + {:create_*, ...}` pairs in the patch.
Detected at diff time, not push time.

`dry_run/2 = diff/2` — same function, the name choice is
ergonomic.

### Owner flag mechanics

```elixir
{:ok, nfnl} = Linx.Netlink.Nfnl.open()
{:ok, ruleset} = Netfilter.create_table(nfnl, "myapp", family: :inet)
# Table has NFT_TABLE_F_OWNER set; nfnl.socket is the owner.

# ... do stuff ...

Linx.Netlink.Nfnl.close(nfnl)
# Kernel observes socket close, atomically destroys the table
# and everything in it. No leaked state.
```

When BEAM crashes, `:erlang.port_close/1` runs in `terminate/2`
of the supervising GenServer; if not, the OS reaps the socket on
process exit and the kernel sees the same close. Belt-and-braces.

Opt-out: `persist: true` on `create_table` — uses `NFT_TABLE_F_PERSIST`
(6.9+) for "no owner; live forever even if unreferenced". On
older kernels, falls back to "no owner, no persist flag" — table
survives socket close until explicitly deleted.

### `~NFT` sigil compile flow

`~NFT` is uppercase, so Elixir's parser leaves `#{...}` alone
and the sigil macro receives the literal binary verbatim. This
is the same pattern Phoenix HEEx uses for `~H` (HEEx defines its
own `{...}` interpolation, parsed from raw bytes); Linx.NFT
uses `#{...}` as the marker because nft already reserves bare
`{` for braces. Lowercase multi-letter sigils don't exist in
Elixir — `~nft` is a SyntaxError.

```
~NFT"""              ──┐
table inet myapp {     │  (1) sigil_NFT/2 macro receives the
  chain input {        │      literal binary (uppercase sigil; no
    tcp dport 22       │      Elixir-side interpolation expansion).
      accept           │
  }                  ──┘
}
"""

(2) Linx.NFT.Tokenizer.tokenize/2 with interpolation?: true
    char-by-char state machine with explicit start-condition
    stack (mirrors nft's scanner.l + HEEx's tokenizer). Produces
    a flat list of tokens — punctuation, identifiers, integers,
    addresses, time literals, statement separators — plus
    {:elixir_expr, raw_source, meta} tokens for every #{...}
    block (the tokenizer counts braces, skips Elixir strings /
    charlists / comments).

(3) Linx.NFT.Parser.parse/2
    recursive-descent token-stream parser. Produces internal
    AST nodes: {:table, family, name, body, meta},
    {:chain, name, opts, stmts, meta}, {:rule, stmts, opts, meta},
    {:match, lhs, op, rhs, meta}, {:verdict, kind, meta}, …
    :elixir_expr tokens flow through to value-position AST
    nodes ({:elixir_expr, raw_source, meta}).

(4) The macro inspects the token list. Two paths:

    (4a) STATIC — no :elixir_expr tokens present.
         Linx.NFT.Compiler.compile/2 walks the AST and calls
         validator-setter functions on Linx.Netfilter.Ruleset
         (the SAME surface the pipeline DSL uses — no parallel
         validation layer). Produces a %Linx.Netfilter.Ruleset{}
         value at compile time. The macro emits it via
         Macro.escape/1 — zero runtime cost.

    (4b) RUNTIME — at least one :elixir_expr token present.
         Linx.NFT.RuntimeCompiler.emit/2 walks the AST and
         produces an Elixir AST (quoted code) that, when
         evaluated at runtime, builds the %Ruleset{} via the
         same validator-setter calls. At each :elixir_expr
         value position, the emitted code calls into
         Linx.NFT.Runtime — Runtime.cmp!/3 takes the evaluated
         Elixir value plus the field kind the surrounding nft
         syntax expects ({:int, 1|2|4|8} / :ipv4 / :ipv6 /
         :ifname), encodes it per kind, and returns an
         %Expr{name: :cmp} ready to splice into the rule's
         expression list. Type mismatches raise ArgumentError
         at runtime with a message naming the expected kind.

Validation errors (in either path) raise Linx.NFT.ParseError
with the AST node's source location and an Elixir-compiler-
style caret rendering of the offending source line.
```

The static / runtime split is the headline architectural call:
hand-authored static rulesets pay no runtime cost (literal
%Ruleset{}), and dynamic rulesets get position-typed runtime
encoding without `Kernel.to_string` getting in the way (which
would be unavoidable if we'd used a lowercase sigil and relied
on Elixir's own interpolation expansion).

### Monitor socket: snapshot + tail

Canonical exactly-once-from-snapshot:

```elixir
{:ok, mon} = Linx.Netfilter.subscribe(self())
# (1) Monitor socket now buffering events into its mailbox.

{:ok, ruleset} = Linx.Netfilter.pull(nfnl)
# (2) Captures generation N as part of the pull; included in ruleset.gen.

# (3) Replay buffered events from mon, discarding any with gen_id ≤ N;
#     applied to ruleset to bring it up to current.
# (4) Live events from mon arrive in mailbox as
#     {:linx_netfilter, :event, %Event{gen_id, op, entity, ...}}
#     in commit order; consumer applies them to the live Ruleset value.
```

ENOBUFS recovery: monitor detects on `:recvmsg`, emits
`{:linx_netfilter, :resync_needed}` to owner; owner re-runs
the snapshot+tail dance.

Batch grouping recovery: every event carries the gen_id of the
commit that produced it; consumer groups consecutive same-gen
events to recover transactional units.

### NFLOG: per-group config

```elixir
{:ok, log} = Linx.Netfilter.log_listen(self(), group: 5000)
# (1) Binds NFNL_SUBSYS_ULOG socket; sends CFG_CMD_PF_BIND per family;
#     sends CFG_CMD_BIND res_id=5000; sets CFG_MODE (copy_mode + range),
#     CFG_QTHRESH, CFG_TIMEOUT, CFG_FLAGS.

# (2) Rules with `log prefix "ssh-attempt" group 5000` now fire events.
#     Per-packet messages arrive as:
#     {:linx_netfilter, :log,
#       %Log.Event{
#         group: 5000,
#         prefix: "ssh-attempt",
#         mark: 0xdeadbeef,
#         indev: "eth0",
#         outdev: nil,
#         hwaddr: <<...>>,
#         packet: %{network: %{src: ~IP"10.0.0.5", dst: ...}, transport: ...},
#         timestamp: ~U[...],
#         seq: 42
#       }}
```

Performance levers: `copy_mode: :none` for metadata-only logging;
`copy_mode: {:packet, snaplen}` for tcpdump-style capture;
`qthresh: 20` to batch packets; `timeout_ms: 100` for max flush
delay. Documented in the EXAMPLES.md when N7 ships.

## Sequencing — milestones

Each milestone is an independently reviewable commit; tests ship
with the code that needs them; commit + push per milestone.

### N0 — Scaffolding + Nfnl socket

- `Linx.Netfilter` module skeleton (`@moduledoc`, public API stubs
  returning `{:error, :not_yet_implemented}`).
- `Linx.Netfilter.supported?/0` — true iff the system can open
  an `AF_NETLINK` socket with `NETLINK_NETFILTER` protocol AND the
  kernel exposes nftables (probe via `NFT_MSG_GETGEN`).
- `Linx.Netlink.Nfnl` — open/0, open/1, close/1, request/2,
  batch/2 (the latter just wraps an op list in BATCH_BEGIN/END).
  Parallel to `Linx.Netlink.Rtnl`.
- `Linx.Netlink.Nfnl.Codec` — nfgenmsg header encoding/decoding;
  subsys-id high-byte multiplexing on `nlmsghdr.type`;
  BATCH_BEGIN / BATCH_END envelope helpers.
- `Linx.Netfilter.Error` — struct + `Exception` impl +
  `from_posix/N` builder. Operations list (covers everything
  through N7): `:push`, `:pull`, `:diff`, `:subscribe`,
  `:log_listen`, plus the wire-level stages
  `:batch_begin`, `:batch_end`, `:newtable`, `:newchain`,
  `:newrule`, `:newset`, `:newsetelem`, `:newobj`, `:newflowtable`,
  `:delgen`, `:open_ns`, `:setns`, `:unshare`.
- `docs/netfilter/{PLAN,EXAMPLES,COVERAGE,REFERENCES}.md` skeletons
  (this doc; the others stubbed for fill-in as primitives ship).
- Wire `docs/netfilter/*.md` into `mix.exs` `docs.extras` + groups.

**Tests** (plain): `supported?/0` returns a boolean; agrees with
"netlink-netfilter socket can be opened". `Nfnl.open/0`
round-trips a `GETGEN` request and parses the reply. `Codec`
encodes BATCH_BEGIN to the expected bytes (golden test).

### N1 — Value types + pipeline DSL

- All the value structs declared in *Module structure*:
  `Ruleset`, `Table`, `Chain`, `Rule`, `Expr`, `Verdict`, `Set`,
  `Map`, `Vmap`, `Object`, `Flowtable`. `@enforce_keys` per
  conventional, `@type t` declarations, custom `Inspect` for the
  ones that need compact rendering (Rule, Expr, Verdict).
- **Validator-setter functions** at the layer described above —
  `Ruleset.new/0`, `Ruleset.add_table/3`, `Ruleset.delete_table/2`,
  `Table.add_chain/4`, `Chain.add_rule/2`, `Set.add_elements/2`,
  etc. Cover the validation rules listed in *Architecture
  deep-dive → Validator-setter functions*.
- The **pipeline DSL** is exactly these functions exported with
  pipe-friendly arg order. No new code beyond the validator-setters.
- Tag-as-identity: every Rule struct has `:tag` (atom or nil) and
  `:handle` (nil until pushed). Comment field round-trips via
  userdata.
- No codec or kernel interaction yet — this milestone is pure
  Elixir data + validation.

**Tests** (plain): struct shapes; validator rejects invalid
chain hooks, mismatched vmap value types, set element type
mismatches; pipeline DSL builds expected Ruleset; Inspect
rendering for Rule and Expr; `:bad_chain` / `:bad_rule` /
`:bad_set_element` shapes.

### N2 — Minimal expression encoder + push :replace

- `Linx.Netfilter.Expr` constructors for the foundational +
  essential expressions: `immediate/2` (constant or verdict
  loaded into register), `payload/3` (extract from packet
  header), `meta/2` (read metadata), `cmp/3` (eq/neq/lt/le/gt/ge),
  `bitwise/3` (AND with mask — required for CIDR matching),
  `ct/2` (state matching only; advanced ct fields deferred to
  N4 / later), `lookup/2` (set/map lookup), `reject/2` (icmp /
  tcp-reset / icmpx), `counter/1`, plus the verdict atoms
  `:accept | :drop | :continue | :return | {:jump, chain} |
  {:goto, chain}`.
- `Linx.Netfilter.Encoder.to_batch/2` — `Ruleset → [nfnetlink_msg]`
  for `:replace` mode. Topologically sorts table → chain → rule
  creation order; wraps in BATCH_BEGIN/END; uses `DESTROY*` to
  clean up existing tables of the same name before creating
  fresh ones.
- `Linx.Netfilter.Decoder.from_msgs/3` — `(tables, chains, rules)
  → Ruleset`, where each input is the per-entity list from one
  GET* dump. Assembles a `%Ruleset{}`, attaching chains to tables
  and rules to chains by name. Drives the response to `pull/1..2`.
- `Linx.Netfilter.push/2` with `mode: :replace` (default).
- `Linx.Netfilter.pull/1` for the whole netns; `pull/2` scoped
  to one table by `{family, name}`.
- `create_table/2` with `owner: true` (default), `persist: true`
  opt-out.

**Tests** (integration, `:integration` tag, run via
`./sudotest.sh`):

- Push a single-rule table: `inet linx_test`, chain `input` with
  hook `input`/priority 0/policy `drop`, one rule
  `tcp dport 22 accept`. Verify with `nft list ruleset` (system
  call) that the rule landed.
- Pull the table back; assert the Ruleset round-trips equal to
  what was pushed (modulo kernel-assigned handles).
- Push, close the Nfnl socket, observe the table is gone (owner
  flag working).
- Pull a nonexistent table → `%Error{errno: :enoent}`.

### N3 — NAT chains + NAT expressions

- `type nat` chain support: extends `Chain` validation to allow
  the nat type with `hook: prerouting/output` (DNAT-side) and
  `hook: postrouting` (SNAT-side); priority aliases `dstnat` and
  `srcnat`.
- NAT expressions: `Expr.nat/2` (dnat/snat), `Expr.masquerade/1`,
  `Expr.redirect/1`. Each accepts address ranges, port ranges,
  flags (`random`, `fully-random`, `persistent`).
- `meta` extensions for the common cases: `iif`, `oif`, `mark`,
  `iifname`, `oifname`.
- `payload` for IP saddr/daddr (network header + offset/length)
  and TCP/UDP sport/dport (transport header + offset/length).

**Tests** (integration):

- DNAT port forward: `inet linx_test`, prerouting chain DNATs
  `tcp dport 8080` → `10.0.0.5:80`. Verify via netns + scapy
  packet injection (or simpler: check via `nft list table` that
  the rule encoded correctly + a smoke test through a real
  veth pair).
- Masquerade postrouting on `oifname` matches.
- Hairpin NAT: DNAT in prerouting + SNAT in postrouting,
  both targeting the same internal IP — verify the two-rule
  composition works.

### N4 — Sets, maps, vmaps, dynamic sets

- `Linx.Netfilter.Set` / `Map` / `Vmap` value types with element
  types: `:ipv4_addr`, `:ipv6_addr`, `:ether_addr`, `:inet_proto`,
  `:inet_service`, `:mark`, `:ifname`. Plus concatenations as
  `{:concat, [:ipv4_addr, :inet_service]}` etc.
- `flags: [:interval, :dynamic, :timeout, :constant, :auto_merge]`
  per the kernel's flag enum.
- Element-level codec: `NFT_MSG_NEWSETELEM` / `NFT_MSG_DELSETELEM`
  carry one or more elements per message; Linx batches element
  ops separately from rule ops within the same transaction.
- Anonymous sets at the rule-builder API: `Expr.lookup/2` accepts
  either a named-set reference (`{:set_ref, name}`) or an inline
  set value (`{:set_literal, [1, 2, 3]}` — encoded as an
  anonymous set tied to the rule).
- Dynamic-set updates: `Expr.dynset/3` — `update @set { ip saddr
  timeout 5m }` shape. Required for SSH-bruteforce / rate-limit
  patterns.
- ct extension: `ct state` matching now uses an interval set
  literal (since the kernel's `ct state` returns a bitmask
  matched against a set), so this milestone depends on the set
  codec being in place.

**Tests** (integration):

- Named set `blocklist { type ipv4_addr; flags interval; }` with
  `add_elements` and `delete_elements`; verify via `pull`.
- Anonymous set in a rule: `tcp dport { 22, 80, 443 } accept`.
- Vmap dispatch: chain that does `ip daddr vmap @services` →
  jumps to per-service chains.
- Dynamic set: `ssh_flood { type ipv4_addr; flags dynamic, timeout;
  timeout 5m; }` populated by `update @ssh_flood { ip saddr }`
  in a rule; verify elements appear with correct timeouts.

### N5 — Diff + `:reconcile` + tag enforcement + BATCH_GENID CAS

- `Linx.Netfilter.Patch` value type and operations enumerated
  above.
- `Linx.Netfilter.diff/2 :: Ruleset.t() → Ruleset.t() → Patch.t()`
  implementing identity rules (name for tables/chains/sets/
  objects; tag-or-position for rules; element-value for set
  elements). Topological sort for create/delete dependencies.
  In-place vs delete+recreate detection via per-entity allowlist.
- `Linx.Netfilter.push/2` gains `mode: :reconcile` —
  internally pulls current state, diffs against desired,
  encodes the patch into one batch with `NFTA_BATCH_GENID`.
- `Linx.Netfilter.dry_run/2 = diff/2` (alias for ergonomics).
- **Tag enforcement** at the `:reconcile` entry point — if any
  rule in the desired Ruleset has `tag: nil` AND the chain has
  more than one rule, `push/2` returns
  `{:error, {:tag_required, chain_path}}`. Untagged rulesets
  can still use `mode: :replace`.
- ERESTART retry loop in `:reconcile` mode: bounded retries
  (default 3), exponential backoff, eventually surfaces
  `{:error, {:concurrent_modification, ruleset_gen}}` to the
  caller.

**Tests** (integration):

- Reconcile: push Ruleset A, modify a single rule attribute
  (e.g. change a port number), push A' in `:reconcile` mode;
  verify only one `REPLACE` message was sent and existing
  connections weren't broken (test indirectly via generation
  counter — only one `gen` bump).
- Reconcile with reordering: push tagged rules in order
  `[a, b, c]`, then `[c, b, a]`, verify the diff is no-op
  (tags identity them, order is logical not physical).
- Reconcile against concurrent change: start a `nft -f` that
  changes the table while our reconcile is in flight; verify
  `ERESTART` then successful retry.
- Tag enforcement: untagged rule in `:reconcile` → `{:error,
  {:tag_required, _}}`.

### N6 — Monitor socket: subscription + snapshot+tail

- `Linx.Netfilter.subscribe/1` opens a second Nfnl socket
  subscribed to `NFNLGRP_NFTABLES`. Returns `{:ok, monitor_ref}`.
- `Linx.Netfilter.Monitor` GenServer wraps the socket; emits
  to the owner:
  - `{:linx_netfilter, :event, %Event{gen_id, proc_pid,
    proc_name, op, entity}}` — one per multicast message.
  - `{:linx_netfilter, :resync_needed}` — on ENOBUFS; consumer
    re-runs snapshot+tail.
- The `pull/1..2` verbs gain `subscribe_first: monitor_ref` opt
  that does the canonical snapshot+tail (capture gen, discard
  ≤gen events queued before the pull).
- `Linx.Netfilter.unsubscribe/1` closes the monitor socket.
- Event decoder handles all the broadcast message types:
  `NEWTABLE`/`DELTABLE`/`NEWCHAIN`/`DELCHAIN`/`NEWRULE`/`DELRULE`/
  `NEWSET`/`DELSET`/`NEWSETELEM`/`DELSETELEM`/`NEWOBJ`/`DELOBJ`/
  `NEWFLOWTABLE`/`DELFLOWTABLE`/`NEWGEN`.

**Tests** (integration):

- Subscribe, push a Ruleset, receive expected `:event` messages
  (one `NEWGEN` + one per entity).
- Subscribe + pull + concurrent external change: confirm the
  external change shows up as a subsequent event with higher
  gen_id.
- ENOBUFS recovery: artificially shrink `SO_RCVBUF`, drive
  heavy churn, observe `:resync_needed`, re-run snapshot.

### N7 — NFLOG via NFNL_SUBSYS_ULOG

- `Linx.Netfilter.Log` GenServer wrapping a third Nfnl socket
  (different sub-subsystem); per-group config via the
  `NFULNL_MSG_CONFIG` command flow.
- `Linx.Netfilter.log_listen/2` API:
  ```
  log_listen(owner_pid, opts \\ [])
    :group        — integer 1..65535 (required; caller-supplied)
    :copy_mode    — :none | :meta | {:packet, snaplen}
    :qthresh      — int 1..1024 (default 1)
    :timeout_ms   — int (default 0 = no batching delay)
    :flags        — [:seq, :seq_global, :conntrack]
    :families     — [:ipv4, :ipv6, :bridge, :arp]
                    (CFG_CMD_PF_BIND for each)
  ```
- `%Log.Event{}` decoder handles every NFULA_* attribute:
  packet header, payload, prefix, mark, indev/outdev/physindev/
  physoutdev, hwaddr, timestamp, uid/gid, seq, seq_global, ct
  tuple (when `:conntrack` flag set), vlan, l2hdr.
- Convenience: when consuming, the `:payload` field is decoded
  into per-protocol structs (`%Packet.IPv4{}`, `%Packet.IPv6{}`,
  `%Packet.TCP{}`, `%Packet.UDP{}`, `%Packet.ICMP{}`) if
  `copy_mode != :none`. Raw bytes still available.
- **Linx-default group `5000`** reserved for the
  "I don't care which group" caller; documented as a convention,
  not a hardcoded default.

**Tests** (integration):

- Push a Ruleset with `log prefix "test" group 5000` on a
  specific rule; trigger that rule (via veth + packet inject);
  receive `:log` event with the right prefix and packet.
- Verify mark channel: `meta mark set 0xdeadbeef` before the
  log rule; receive event with `mark: 0xdeadbeef`.
- Multi-group: two `log_listen` calls with different groups;
  verify events route to the right owner.
- High-rate: with `qthresh: 50`, verify packets are batched
  into multipart netlink messages.

**v1.0 release here.** Usable Linx.Netfilter via pipeline DSL —
Nerves firewall appliance, container firewalling, monitor +
NFLOG observability. The N0–N7 stretch is the load-bearing
"first wedge"; everything beyond is ergonomics and
extension-of-surface.

### N8 — `~NFT` sigil + Conf parser (shipped as N8a–N8k)

Shipped as eleven sub-commits on the `netfilter-nft-sigil`
branch. Each sub-commit is independently reviewable; they were
sequenced to add architectural layers first, then ergonomics
on top, then real-world-driven extensions.

**Core layers (the structural commitments):**

- **N8a** — `Linx.NFT.Tokenizer` (~970 LOC) + `Linx.NFT.ParseError`
  (~95 LOC). Handwritten char-by-char lexer with an explicit
  start-condition stack: `:default` / `:string` / `:line_comment`
  / `:block_comment` / `:elixir_expr`. The stack discipline is
  load-bearing — every future long-tail extension adds at most
  one condition + clause, none touch existing ones. Mirrors
  nft's own `scanner.l` (50+ start conditions) and HEEx's
  tokenizer.

- **N8b** — `Linx.NFT.Parser` (~880 LOC). Handwritten
  recursive-descent over the token stream. AST nodes for tables
  / chains / rules / matches / verdicts / actions / sets / maps
  / vmaps / objects / flowtables / `include` / `define`. Every
  node carries `{file, line, column}` meta.

- **N8c** — `Linx.NFT.Compiler` (~600 LOC). AST → validator-
  setter calls on `Linx.Netfilter.Ruleset`. The SAME surface the
  pipeline DSL uses — no parallel validation layer. Returns
  `%Ruleset{}` or raises `Linx.NFT.ParseError` with the AST
  node's location.

- **N8d** — `Linx.NFT` public module + `Linx.NFT.Formatter`
  (~440 LOC). `sigil_NFT/2`, `parse/1`, `parse_file/1`, `format/1`
  for canonical emit. Round-trip works for the supported slice.

- **N8e** — `Linx.NFT.RuntimeCompiler` + `Linx.NFT.Runtime`.
  Wires `#{...}` interpolation via the tokenizer's existing
  `:interpolation?` mode (HEEx pattern, not Elixir's interpolation
  expansion). The macro dispatches to RuntimeCompiler when any
  `:elixir_expr` tokens are present; emitted code calls
  `Runtime.cmp!/3` at the value position with the typed
  field kind. Static-only sigils stay on the compile-time
  literal path.

- **N8f** — round-trip golden tests against a curated corpus of
  fixtures in `test/linx/nft/fixtures/*.nft`. Each fixture
  asserted three ways: parses, `parse → format → parse` is
  structurally equal, `format → parse → format` is byte-stable.

**Real-world-driven extensions (added when fixtures exposed gaps):**

- **N8g** — bare `iifname` / `oifname` / `iif` / `oif`
  shorthand at rule top level (no `meta` prefix needed). What
  every real-world host firewall config actually uses.

- **N8h** — `ct state` matches via the kernel-correct
  `bitwise(mask) + cmp_neq_0` pattern. Supports the brace form
  (`ct state { established, related }`), the comma-no-brace
  form (`ct state established,related`), and inverted op
  (`ct state != invalid`). Fixes both single-state and
  multi-state shapes; the older `ct + cmp_eq` pattern was a
  pre-existing subtle bug.

- **N8i** — `icmpv6 type` / `icmpv6 code` payload dispatch +
  18 symbolic ICMPv6 type names (`echo-request`,
  `nd-router-solicit`, etc.). Identifier elements inside
  integer-typed sets resolve through `parse_int_keyword/1`,
  so `icmpv6 type { echo-request, echo-reply, ... }` compiles
  cleanly.

- **N8j** — `flush ruleset` top-level directive. Compiler
  noop (we always start from `Ruleset.new()`); accepted so
  real configs parse from the first line.

- **N8k** — fixture 08, an anonymized real-world home-router
  config exercising every N8g–N8j addition plus the older
  core. Surfaced two formatter handlers that needed adding
  (`meta + __anon_set` for inline-set matches on meta fields;
  key-type-aware element rendering so `:ifname` strings get
  quoted in formatted output).

**Scope: the ~85% subset, end-to-end working:**

- **Top level**: tables, `flush ruleset`. `include` /
  `define` parse but the compiler doesn't substitute yet.
- **Tables**: all families (ip / ip6 / inet / arp / bridge /
  netdev).
- **Chains**: all hooks; integer or named-alias priorities
  resolved via `Wire.priority_int/2`, with optional `+N` / `-N`
  offset; policy `accept` / `drop`; jump-target (regular)
  chains.
- **Matches**: `ip` / `ip6 saddr` / `daddr` (with CIDR),
  `tcp` / `udp sport` / `dport` (single + range + inline set +
  named set ref), `icmp` / `icmpv6 type` / `code` (integer +
  symbolic names + inline set), `meta iif` / `oif` / `iifname` /
  `oifname` / `mark` / `protocol`, `ct state` (single + comma
  list + brace set, with proper bitwise pattern), `ip protocol
  NAME` with symbolic names. Bare meta shorthand for the four
  common ifname/iif variants.
- **Verdicts**: accept / drop / continue / return / queue /
  `jump <chain>` / `goto <chain>` / `reject [with ...]`.
- **Actions**: `counter`, `log prefix "..." [group N] [level X]`,
  `dnat to ADDR`, `snat to ADDR`, `masquerade`, `redirect`
  (all with optional `random` / `fully-random` / `persistent`
  flags). `meta FIELD set VALUE` and `ct FIELD set VALUE`
  parse but raise a clear ParseError at compile (no setter
  Expr yet).
- **Sets / maps / vmaps**: named declarations with `type`,
  `flags`, `timeout`, `gc-interval`, `size`, `elements`.
  Anonymous inline sets. Maps + vmaps declare cleanly;
  element-side compile for vmap-dispatch deferred to a small
  follow-up.
- **Per-rule**: `comment "..."` trailer, `tag` propagation.
- **Comments**: `#` line, `/* ... */` block (nested OK).
- **Interpolation** (`~NFT` only, HEEx-style): `#{...}` in
  match RHS at `{:int, _}` / `:ipv4` / `:ipv6` / `:ifname`
  positions; runtime-typed via `Linx.NFT.Runtime`.

**Still deferred** (parse cleanly but raise a precise
ParseError naming the missing feature):

- `limit rate N/period` — no `Expr.limit` constructor yet.
- `meta FIELD set` / `ct FIELD set` — no setter `%Expr{}`.
- Named objects at table level (`counter ctr { ... }`,
  `quota q { ... }`, `limit l { ... }`).
- Flowtables (declarative side).
- Concatenated set/map keys (`type ipv4_addr . inet_service`).
- `snat ip6 prefix to ADDR` (NPTv6).
- `include "path"` substitution (parse-only today).
- `define name = value` substitution (parse-only).
- The big-deferred expressions (`synproxy`, `secmark`, `osf`,
  `fib`, `jhash`, `xfrm`, advanced ct fields, `dup`/`fwd`,
  `xt` compat) — each is a per-construct addition: tokenizer
  keyword(s) + parser case + compiler case + wire-codec case.

**Tests**: 866 unit (was 693 at end of N7) + 147 integration.
Golden suite is 9 fixtures × 3 assertions = 27 tests; each
fixture has a header comment naming its source / inspiration
so the corpus stays curatable. Aspirational corpus (Debian /
Arch defaults, Kubernetes nftables kube-proxy, firewalld
exports, nftables wiki samples) deferred to a separate test
module once the remaining long-tail features land — see the
comment block at the top of `test/linx/nft/golden_test.exs`
for the per-source feature gap list.

### N9 — `mix format` plugin (still to ship)

`Linx.NFT.Formatter` already exists as the canonical-emit
pretty-printer (shipped in N8d, exercised by every golden-test
fixture). N9 extends it with the `Mix.Tasks.Format` behaviour
callbacks so `mix format` can rewrite both inline `~NFT` sigil
bodies in `.ex` source AND standalone `.nft` files:

- Add to `Linx.NFT.Formatter`:
  - `features(_opts)` → `[sigils: [:NFT], extensions: [".nft"]]`
  - `format(source, opts)` — parses, then delegates to the
    existing `format/1` (or a dedicated pretty-printer with
    `:nft_line_length` / `:inline_matcher` config).
- Users add to `.formatter.exs`:
  ```elixir
  [plugins: [Linx.NFT.Formatter], inputs: ["**/*.nft", ...]]
  ```
- Documented in `docs/netfilter/EXAMPLES.md` with a worked
  example of `mix format` reflowing a sigil and a `.nft` file.
- The output-stability assertion in the N8f golden corpus
  already proves `format → parse → format` is idempotent — the
  invariant `mix format` needs to behave well on repeated runs.

**v1.5 release at the end of N9.** `~NFT` becomes the headline
feature: hand-authored, sigil-interpolated, file-mode, and
`mix format`-rewritable — all converging on the same
`%Linx.Netfilter.Ruleset{}` via the same validator-setter
surface.

## Testing

Same three bands as every other Linx subsystem:

- **Unit / plain (`mix test`).** Struct shapes, validator-setter
  validation errors, wire codec golden tests (encode `%Ruleset{}`
  → expected bytes), decoder golden tests (parse fixture bytes
  → expected `%Ruleset{}`), diff identity rules, patch ordering,
  `~NFT` parser positive + negative tests against fixtures,
  `mix format` plugin output stability.
- **Integration (`:integration` tag, `./sudotest.sh`).** Anything
  that talks to a real netlink socket. Each test creates a
  uniquely-named table under a Linx-reserved prefix
  (`linx-test-#{System.unique_integer([:positive])}`) and cleans
  up via `on_exit` (or relies on the `owner` flag to clean up on
  test-process exit).
- **Manual / `docs/netfilter/EXAMPLES.md`.** End-to-end
  compositions — the Nerves firewall appliance recipe, the
  container lock-down composition, NFLOG-based intrusion-detection
  loop, the `~NFT`-then-`mix-format` workflow.

Integration tests for NAT and forwarding lean on veth-pair
fixtures plus packet injection (scapy via the `:scapy_python`
test helper, or just `iperf3` for throughput smoke tests).
NFLOG tests trigger via packet inject and assert on the
`:log` events.

## Composition examples (target shape — built up across milestones)

### Nerves firewall appliance

```elixir
# At Nerves boot, supervised under the application's supervisor.
defmodule MyApp.Firewall do
  use GenServer

  @impl true
  def init(_) do
    # Enable IPv4 forwarding (sysctl, kernel-wide).
    :ok = Linx.Sysctl.write("net.ipv4.ip_forward", 1)

    # Open the Nfnl socket; table is owner-flagged so it dies with us.
    {:ok, nfnl} = Linx.Netlink.Nfnl.open()

    # Build the desired ruleset.
    ruleset = build_ruleset()

    # Push atomically.
    :ok = Linx.Netfilter.push(nfnl, ruleset)

    # Subscribe to changes (catch out-of-band edits by `nft` CLI).
    {:ok, mon} = Linx.Netfilter.subscribe(self())

    # Log SSH attempts.
    {:ok, log} = Linx.Netfilter.log_listen(self(),
                  group: 5000,
                  copy_mode: :meta,
                  qthresh: 1)

    {:ok, %{nfnl: nfnl, mon: mon, log: log, ruleset: ruleset}}
  end

  defp build_ruleset do
    Linx.Netfilter.Ruleset.new()
    |> Ruleset.add_table(:inet, "appliance")
    |> Table.add_chain("appliance", "input",
         type: :filter, hook: :input, priority: :filter,
         policy: :drop)
    |> Chain.add_rule("appliance", "input",
         Rule.build(tag: :allow_established,
           [Expr.ct(:state), Expr.cmp(:in, [:established, :related]),
            Verdict.accept()]))
    |> Chain.add_rule("appliance", "input",
         Rule.build(tag: :allow_ssh,
           [Expr.payload(:tcp, :dport), Expr.cmp(:eq, 22),
            Expr.log(prefix: "ssh-attempt", group: 5000),
            Verdict.accept()]))
    # ... forward chain, nat chain, etc.
  end

  @impl true
  def handle_info({:linx_netfilter, :log,
                   %Log.Event{prefix: "ssh-attempt"} = ev}, s) do
    # React to SSH attempts — log, push to fail2ban-style dynamic set, etc.
    {:noreply, s}
  end

  def handle_info({:linx_netfilter, :event, _}, s), do: {:noreply, s}
  def handle_info({:linx_netfilter, :resync_needed}, s) do
    # Re-pull state, reconcile against our desired ruleset.
    :ok = Linx.Netfilter.push(s.nfnl, s.ruleset, mode: :reconcile)
    {:noreply, s}
  end
end
```

If `MyApp.Firewall` crashes, the supervisor restarts it; on
shutdown, the `terminate` callback closes `nfnl`, kernel
observes socket close, table is destroyed. No leaked rules.

### Container lock-down composition (the showcase)

```elixir
{:ok, c} = Linx.Process.spawn(
             argv: ["/usr/sbin/nginx"],
             namespaces: [:net, :pid, :user, :mount, :uts, :ipc],
             no_new_privs: true)

receive do {:linx_process, :ready, _} -> :ok end
{:ok, host_pid} = Linx.Process.host_pid(c)

# Host-side plumbing (Rtnl) — veth peer in our netns.
{:ok, host_rtnl} = Linx.Netlink.Rtnl.open()
:ok = Rtnl.Link.create_veth(host_rtnl, "ct0a", "ct0b")
:ok = Rtnl.Link.move_to_netns(host_rtnl, "ct0b", host_pid)
:ok = Rtnl.Address.add(host_rtnl, "ct0a", "10.0.0.1", 24)
:ok = Rtnl.Link.set_up(host_rtnl, "ct0a")

# Host-side firewall governing the veth peer.
{:ok, host_nfnl} = Linx.Netlink.Nfnl.open()
:ok = Linx.Netfilter.push(host_nfnl, host_ruleset_for_ct0a())

# Container-side networking via Rtnl in the child's netns.
{:ok, ct_rtnl} = Linx.Netlink.Rtnl.open({:pid, host_pid})
:ok = Rtnl.Link.set_up(ct_rtnl, "ct0b")
:ok = Rtnl.Address.add(ct_rtnl, "ct0b", "10.0.0.2", 24)
:ok = Rtnl.Route.add_default(ct_rtnl, "10.0.0.1")

# Container-side firewall via Nfnl in the child's netns.
{:ok, ct_nfnl} = Linx.Netlink.Nfnl.open({:pid, host_pid})
:ok = Linx.Netfilter.push(ct_nfnl, container_ruleset())

# Subscribe on the HOST to NFLOG events from the CONTAINER's
# rules. (Container can log to its own netns's NFLOG; host
# can't directly subscribe across netns — that's a separate
# socket per netns.)
{:ok, ct_log} = Linx.Netfilter.log_listen(self(),
                  group: 5000,
                  socket: ct_nfnl)  # opt that uses the per-netns socket

# Lock down the container's privileges so it can't mutate
# its own firewall after exec.
all_caps = Linx.Capabilities.Constants.all()
:ok = Linx.Capabilities.drop_bounding(c,
        MapSet.delete(all_caps, :cap_net_bind_service))

# Seccomp filter blocking firewall-mutation syscalls.
{:ok, filter} = Linx.Seccomp.allow_list(
                  ~w(read write openat close fstat brk mmap munmap
                     mprotect socket bind listen accept4 setsockopt
                     getsockopt rt_sigaction rt_sigprocmask
                     rt_sigreturn exit_group epoll_pwait epoll_ctl
                     epoll_create1 clock_gettime futex)a,
                  default: :kill_process)
:ok = Linx.Seccomp.install(c, filter)

# Release the workload. Network + firewall + identity + privilege
# + syscall surface all locked in.
:ok = Linx.Process.proceed(c)
```

Result: nginx runs with a fully-configured frozen network and
firewall it cannot modify. Host has full observability of rule
hits via NFLOG. If the BEAM supervisor dies, the host_nfnl /
ct_nfnl sockets close, both tables are destroyed (owner flag),
and Linx.Process's child agent reaps the container.

## Deferred — architected-for, not built here

The N0–N9 surface is the v1.5 ship. Beyond:

- **NFQUEUE** (`NFNL_SUBSYS_QUEUE`, `nfnetlink_queue.h`). Userspace
  blocks the kernel until verdict — heavyweight, dangerous default,
  needs careful backpressure design. No immediate use case
  surfaced. Future `Linx.Netfilter.Queue` module. Will reuse the
  Nfnl transport, follow the same owner-mailbox shape.
- **ctnetlink event stream** (`NFNL_SUBSYS_CTNETLINK`,
  `NFNLGRP_CONNTRACK_NEW/UPDATE/DESTROY`). Live conntrack
  events — natural fit for "live connections" UI in a LiveView
  appliance dashboard. Future `Linx.Netfilter.Conntrack` module
  sharing transport plumbing.
- **`Linx.Netfilter.Conntrack` write side** — `conntrack -D` /
  `-U` equivalents (force-delete an entry, update mark/label/
  timeout). Useful for "flush conntrack after pushing new NAT
  rules so existing flows pick up the new mapping". Shares the
  transport.
- **Flowtable expression encoding**. Declarative side
  (`flowtable ft { hook ingress priority filter; devices = {eth0, eth1} }`)
  is in N4-ish scope; the `flow add @ft` expression in a rule
  is what defers (small, but tied to the flowtable's own
  CRUD via `NFT_MSG_NEWFLOWTABLE` / `DELFLOWTABLE`). Likely
  N4.5 / N5.5 once driving use case appears.
- **ct timeout / helper / zone named objects**. The named-object
  surface (`NFT_MSG_NEWOBJ` with `NFT_OBJECT_CT_TIMEOUT` /
  `_HELPER` / `_EXPECT`). N4 ships the `Object` value type for
  counter/quota/limit; named ct objects extend that with the
  per-object data layout. Defer until a specific scenario needs
  them (ALG-required NAT, multi-tenant zone NAT, etc.).
- **Advanced expressions** (`synproxy`, `socket`, `tproxy`,
  `osf`, `xfrm`, `tunnel`, `secmark`, `numgen`, `jhash`, `hash`
  symmetric, `fib`, `exthdr`, `dup`, `fwd`, `last`, `connlimit`,
  `quota`, `objref`). Each is a small additive milestone — wire
  encoder + AST node + (where appropriate) `~NFT` parser
  extension. Ship per-demand; current set covers ~85% of real
  use.
- **`xt` compat shims**. The `xt_*` legacy iptables matches.
  Out of scope — this is migration territory, not greenfield.
- **`ipset` legacy**. Out of scope — superseded by nft sets.
- **Hook introspection** (`NFNL_SUBSYS_HOOK`, kernel 5.16+).
  "Who else has rules at this hook + priority?" Useful for
  coexistence audits. Niche; defer.
- **Trivia-preserving Conf parser** (preserve `#` comments,
  `define` names, whitespace, rule ordering on emit). N8 does
  canonical emit only. The trivia work is ~30% extra parser
  complexity; ship as a v2 enhancement when a real demand
  appears (e.g. a `nft-format`-style tool).
- **JSON form** (`nft -j`). N0–N9 doesn't go through JSON at
  all. If a consumer needs JSON interop, a `Linx.NFT.Json` module
  could shim our value type to/from libnftables's JSON schema
  later. Genuinely external (consumer-side adapter) for now.

## Decisions

1. **Direct netlink only.** No `nft` binary, no `libnftables`
   FFI, no subprocess. The codec lives in
   `Linx.Netlink.Nfnl.Codec`, reusing the `use Linx.Netlink.Codec`
   DSL that powers `Linx.Netlink.Rtnl`. Trade-off: ~3-4k lines of
   codec work vs. zero codec but a fork-per-commit and `nft`
   dependency. The codec is mechanical against the UAPI headers
   and the `Linx.Netlink.Codec` DSL collapses most of the
   boilerplate.

2. **Kernel floor 6.6, design target 6.12.** All features
   universally available on 6.12+; the 6.6→6.11 path
   feature-detects `persist`-flag use and gracefully downgrades.
   The `owner` flag is 5.19, pre-floor — always available.

3. **Owner flag is the default.** `Linx.Netfilter.create_table/2`
   sets `NFT_TABLE_F_OWNER` by default; the table dies with the
   creating socket. Opt out with `persist: true`. This is the
   genuinely unique Linx differentiator — "your supervisor owns
   your firewall, cleanup is automatic".

4. **Value, not handle, with three identity fields per rule.**
   `handle` (kernel), `tag` (user), `comment` (free-form). Tag
   doubles as diff identity (`:reconcile`) and NFLOG/NFQUEUE
   callback identity (the `log prefix` string derives from it).
   The convergence is what makes tagging the natural thing to
   do.

5. **Transactions are mandatory at the API surface.** `push/2`
   wraps every mutation in a `NFNL_MSG_BATCH_BEGIN/END` envelope;
   single-message mutations are not exposed.

6. **Optimistic concurrency via `NFTA_BATCH_GENID`.**
   `:reconcile` mode threads it automatically with bounded
   retries on `ERESTART`. Lets Linx coexist with `nft` /
   firewalld / kube-proxy cleanly.

7. **Two-socket pattern (three for NFLOG).** RPC socket for
   request/reply + batches; monitor socket for
   `NFNLGRP_NFTABLES` subscription; NFLOG socket for
   `NFNL_SUBSYS_ULOG`. Each its own GenServer, each its own
   `recv` loop — mixing them complicates ENOBUFS recovery.

8. **Per-netns isolation falls out automatically.**
   `Linx.Netlink.Nfnl.open({:pid, n})` binds the socket to
   that netns for its lifetime; every operation through that
   socket lands in the target's nftables instance. No new
   abstractions vs the host case.

9. **Peers, not layers, for authoring.** `~NFT` sigil and
   pipeline DSL are peer authoring surfaces that produce the
   same `%Ruleset{}` via shared validator-setter functions.
   No third macro DSL — `~NFT` covers that need.

10. **`~NFT` is handwritten** (no NimbleParsec). Tokenizer with
    explicit start-condition stack, recursive-descent parser
    with token_stack + buffer stack, compiler walking AST →
    validator-setter calls. Mirrors HEEx's
    `Phoenix.LiveView.TagEngine` shape exactly. Scope v1.5 is
    the ~85% subset; extension milestones add the long tail.

11. **`~NFT` and `Linx.NFT.Conf` are one project.** Same
    tokenizer + parser + compiler; only the entry point differs
    (inline binary vs file). The "external library for conf
    parsing" idea from earlier discussions is obsolete.

12. **Canonical emit for round-trip.** `Linx.NFT.format/1`
    produces a syntactically-valid `nftables.conf`-equivalent
    output but doesn't preserve `#` comments, `define` names,
    blank lines, or original ordering. Trivia preservation
    is a v2 enhancement.

13. **NFLOG group numbers are caller-supplied.** No
    auto-allocation, no system registry; the caller picks and
    owns the conflict surface. Linx reserves group `5000` as a
    convention for "I don't care" callers but doesn't enforce.

14. **Tag enforcement for `:reconcile`.** Chains with >1 rule
    where any rule is untagged → `{:error, {:tag_required,
    chain_path}}`. `:replace` mode tolerates untagged. The
    convergence with NFLOG identity means tagging isn't
    overhead, it's the thing you wanted anyway.

15. **Errors as structs.** `%Linx.Netfilter.Error{operation,
    errno, code, subsys, msg_type, attr_offset, batch_seq,
    ruleset_gen, message}`. Decoded from `NLMSG_ERROR` frames;
    carries enough context to point at the offending byte in
    the batch.

16. **`AGENTS.md` style throughout.** `@moduledoc` / `@doc` /
    `@spec` everywhere; domain data as structs with
    `@enforce_keys`; one module per file; cite kernel UAPI
    headers and `wiki.nftables.org` where interpretation is
    non-obvious.

## References

### Kernel UAPI

- [`include/uapi/linux/netfilter/nf_tables.h`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/netfilter/nf_tables.h)
  — message types, attribute tags, expression names, all the
  enums.
- [`include/uapi/linux/netfilter/nfnetlink.h`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/netfilter/nfnetlink.h)
  — `nfgenmsg`, subsys ids, multicast groups, batch envelope
  constants.
- [`include/uapi/linux/netfilter/nfnetlink_log.h`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/netfilter/nfnetlink_log.h)
  — NFLOG message types, NFULA_* attributes, config commands.
- [`include/uapi/linux/netfilter/nfnetlink_queue.h`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/netfilter/nfnetlink_queue.h)
  — NFQUEUE (deferred).
- [`include/uapi/linux/netfilter/nfnetlink_conntrack.h`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/netfilter/nfnetlink_conntrack.h)
  — ctnetlink (deferred).

### Kernel documentation

- [`Documentation/networking/netlink_spec/nftables.html`](https://docs.kernel.org/networking/netlink_spec/nftables.html)
  — generated reference from the YAML netlink spec; the
  authoritative wire-format document.
- [`Documentation/networking/nf_flowtable.html`](https://docs.kernel.org/networking/nf_flowtable.html)
  — flowtable architecture, fast-path semantics, HW offload.

### Community references

- [wiki.nftables.org — Main Page](https://wiki.nftables.org/wiki-nftables/index.php/Main_Page)
  — the project wiki; canonical user-facing reference for
  syntax, expressions, features.
- [wiki.nftables.org — Configuring tables / chains / sets / maps / vmaps / concatenations / meters / NAT / conntrack helpers / logging](https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes)
- [wiki.nftables.org — Portal:DeveloperDocs/nftables internals](https://wiki.nftables.org/wiki-nftables/index.php/Portal:DeveloperDocs/nftables_internals)
  — wire-format internals; the right reading list for codec
  implementers.
- [wiki.nftables.org — List of updates since Linux kernel 3.13](https://wiki.nftables.org/wiki-nftables/index.php/List_of_updates_since_Linux_kernel_3.13)
  — per-version feature additions; lookup table for kernel-floor
  decisions.
- [`nft(8)` manpage (Debian testing)](https://manpages.debian.org/testing/nftables/nft.8.en.html)
  — userspace tool reference; the grammar `~NFT` parses is the
  one documented here.
- [libnftables-json(5)](https://man.archlinux.org/man/libnftables-json.5.en)
  — JSON schema; useful as a structural cross-reference even
  though we don't use JSON ourselves.

### nftables source (parser reference)

- [`src/parser_bison.y`](https://git.netfilter.org/nftables/plain/src/parser_bison.y)
  — full bison grammar, ~6,594 lines. The reference for what
  `~NFT` parses (subset) and emits.
- [`src/scanner.l`](https://git.netfilter.org/nftables/plain/src/scanner.l)
  — flex lexer with 50+ start conditions. Reference for
  `Linx.NFT.Tokenizer`'s start-condition stack.
- [libnftnl source](https://git.netfilter.org/libnftnl/)
  — readable Netlink-message construction reference (we don't
  link it, but it's the canonical implementation of the wire
  format).

### HEEx as a model

- [`phoenix_live_view/lib/phoenix_live_view/tag_engine/tokenizer.ex`](https://github.com/phoenixframework/phoenix_live_view/blob/main/lib/phoenix_live_view/tag_engine/tokenizer.ex)
  — the tokenizer pattern `Linx.NFT.Tokenizer` mirrors.
- [`phoenix_live_view/lib/phoenix_live_view/tag_engine/parser.ex`](https://github.com/phoenixframework/phoenix_live_view/blob/main/lib/phoenix_live_view/tag_engine/parser.ex)
  — the parser pattern.
- [`phoenix_live_view/lib/phoenix_live_view/tag_engine/compiler.ex`](https://github.com/phoenixframework/phoenix_live_view/blob/main/lib/phoenix_live_view/tag_engine/compiler.ex)
  — the compiler pattern.
- [`phoenix_live_view/lib/phoenix_live_view/html_formatter.ex`](https://github.com/phoenixframework/phoenix_live_view/blob/main/lib/phoenix_live_view/html_formatter.ex)
  — `mix format` plugin reference for N9.

### Production-shape references

- [Kubernetes blog — nftables kube-proxy mode (Feb 2025)](https://kubernetes.io/blog/2025/02/28/nftables-kube-proxy/)
  — the canonical "scalable NAT via nftables" design: vmaps with
  concatenated keys for service dispatch.
- [ulogd2 documentation](https://www.netfilter.org/projects/ulogd/)
  — reference NFLOG consumer; useful for understanding the
  per-group worker pattern.
- [firewalld nftables backend](https://firewalld.org/2019/09/libnftables-JSON)
  — large-scale nftables consumer; informative on edge cases.

### Cross-references inside Linx

- `docs/netlink/PLAN.md` — `Linx.Netlink.Rtnl`'s codec DSL and
  socket plumbing; `Linx.Netlink.Nfnl` mirrors this for the
  netfilter family.
- `docs/seccomp/PLAN.md` — the value-type-with-codec
  precedent (`%Linx.Seccomp.Filter{}` is the small-scale version
  of what `%Linx.Netfilter.Ruleset{}` is at large scale).
- `docs/process/PLAN.md` — the checkpoint composition story;
  every cross-namespace verb (Mount, User, Capabilities,
  Seccomp, Sysctl, Netfilter) hooks in the same way.
