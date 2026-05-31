# Linx.Netfilter — post-0.1.0 design notes

Forward-looking design for `Linx.Netfilter` and the `~NFT` sigil. Unlike
the per-subsystem `PLAN.md`/`COVERAGE.md` files (retired in the 0.1.0
docs consolidation), this doc is **kept** — it captures decisions and
open questions for work intentionally deferred past 0.1.0. Nothing here
ships in 0.1.0.

## 1. Round-trippable `Inspect` → `~NFT` source

**Idea.** `inspect/1` output is meant to be valid, paste-able Elixir —
and `~NFT"""…"""` *is* valid Elixir. So rendering a `Ruleset` (and its
container structs) as their `~NFT` source would make `inspect/1` a true
round trip: paste the output back and get an equivalent ruleset.

```
iex> ruleset
~NFT"""
table inet myfw {
  chain input { type filter hook input priority 0; policy drop; ... }
}
"""
```

**The catch.** The formatter renders any construct outside the N8 grammar
subset as a `# <unsupported expression: …>` comment, which does **not**
round-trip. So `Inspect`-as-`~NFT` needs a fallback: if a ruleset uses
features the formatter can't faithfully emit, fall back to the 0.1.0
summary form (`#Linx.Netfilter.Ruleset<2 tables, 8 chains, 240 rules>`)
rather than emit a sigil that won't parse back. Decision needed: detect
unsupported constructs up front, or attempt the format and downgrade on
any `# <unsupported>` marker.

This supersedes the minimal summary `Inspect` that shipped in 0.1.0
(D3) — that stays as the fallback.

## 2. `~NFT.Chain` / `~NFT.Rule` sub-sigils

**Idea.** Today `~NFT` parses a whole ruleset (or table). Sub-sigils
would let callers author a single chain or rule inline:

```
chain = ~NFT.Chain"chain input { type filter hook input priority 0; policy drop; }"
rule  = ~NFT.Rule"ip saddr 10.0.0.0/8 drop"
```

Open question: Elixir sigils are single-token (`~X`), so `~NFT.Chain` is
not a real sigil name. Options: separate sigils (`~NC`, `~NR` — cryptic),
or a macro/function API (`Linx.NFT.chain!/1`, `Linx.NFT.rule!/1`) that
reuses the tokenizer/parser at the chain/rule entry point. The
function-macro route is almost certainly the right one; the parser
already has the sub-productions.

## 3. `Linx.NFT` ↔ `Linx.Netfilter` namespace

Today `Linx.Netfilter` is the programmatic API (build/push/pull/diff +
the value structs) and `Linx.NFT` is the sigil/parser front-end. The
split mirrors kernel "netfilter" vs userspace "nft", and both authoring
surfaces call the same `Ruleset` validator-setters. Open question for a
major version: is the dual namespace worth the newcomer confusion, or
should the sigil live under `Linx.Netfilter` (e.g. `import
Linx.Netfilter.Sigil`)? Lean: keep the split, document the relationship
prominently. Revisit only if user feedback says it confuses.

## 4. Verb naming — `create_*` vs `add_*`

The Phase-1 audit flagged `Ruleset.add_table`/`add_chain`/`add_rule` vs
`Cgroup.create`/`Rtnl.Link.create_*` as a cross-subsystem inconsistency.
Deferred here deliberately: `add_*` reads correctly for *membership
insertion into a value* (a `Ruleset` is a value, not a kernel handle),
whereas `create`/`create_*` elsewhere materialises a kernel object. The
two verbs may legitimately mean different things. If unified, the rule
would be "`create` materialises in the kernel; `add` inserts into a
value" — which actually argues for keeping `Ruleset.add_*`. Decide
alongside any other 0.2 API renames so it lands as one breaking change.

## 5. Feature breadth (formerly the separate TODO list)

Tier-1 constructs deferred past 0.1.0 (also tracked in the 0.1.0 release
plan's Deferred section): `limit rate`, `meta FIELD set` / `ct … set`,
named objects, flowtables, concatenated set/map keys, NPTv6, `include`
substitution, the `nftables.conf` codec, and a `mix format` plugin for
`~NFT` blocks. These are grammar/codec breadth, not architecture — they
slot into the existing tokenizer → parser → compiler → encoder pipeline.
