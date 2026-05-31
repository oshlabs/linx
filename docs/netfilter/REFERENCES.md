# Linx.Netfilter references

The kernel docs, man pages, source files, and external designs this
subsystem encodes or learns from. Cite specific sections in the
source when interpretation is non-obvious.

## Kernel UAPI headers (authoritative wire format)

- **[`include/uapi/linux/netfilter/nf_tables.h`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/netfilter/nf_tables.h)**
  — every nf_tables message type (`enum nf_tables_msg_types`),
  attribute tag (`NFTA_*`), expression name, set/map type, chain
  type, hook number, verdict code. The single most-cited file in
  the codec.
- **[`include/uapi/linux/netfilter/nfnetlink.h`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/netfilter/nfnetlink.h)**
  — `struct nfgenmsg`, sub-subsystem ids, multicast groups
  (`NFNLGRP_*`), batch envelope types (`NFNL_MSG_BATCH_BEGIN/END`),
  batch attributes (`NFNL_BATCH_GENID`).
- **[`include/uapi/linux/netfilter/nfnetlink_log.h`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/netfilter/nfnetlink_log.h)**
  — NFLOG message types (`NFULNL_MSG_PACKET / CONFIG`), per-packet
  attributes (`NFULA_*`), config commands (`NFULNL_CFG_CMD_*`).
- **[`include/uapi/linux/netfilter/nfnetlink_queue.h`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/netfilter/nfnetlink_queue.h)**
  — NFQUEUE (deferred milestone; reference for completeness).
- **[`include/uapi/linux/netfilter/nfnetlink_conntrack.h`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/netfilter/nfnetlink_conntrack.h)**
  — ctnetlink (deferred milestone).
- **[`include/uapi/linux/netlink.h`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/netlink.h)**
  — `NETLINK_NETFILTER` protocol number (12), `NLMSGERR_ATTR_*`
  extended-ack attributes (`NLMSGERR_ATTR_MSG`, `_OFFS`, `_COOKIE`).

## Kernel documentation

- **[`Documentation/networking/netlink_spec/nftables`](https://docs.kernel.org/networking/netlink_spec/nftables.html)**
  — generated reference from the YAML netlink spec; the
  authoritative wire-format document for nf_tables messages.
  Updated per kernel release.
- **[`Documentation/networking/nf_flowtable`](https://docs.kernel.org/networking/nf_flowtable.html)**
  — flowtable fast-path architecture, hardware offload story.

## Man pages

- **[`nft(8)`](https://manpages.debian.org/testing/nftables/nft.8.en.html)**
  — userspace tool reference; the grammar `~NFT` parses is the
  one documented here.
- **[`libnftables(3)`](https://man.archlinux.org/man/extra/nftables/libnftables.3.en)**
  — official C library API; cross-reference for the JSON schema
  even though we don't use it.
- **[`libnftables-json(5)`](https://man.archlinux.org/man/libnftables-json.5.en)**
  — JSON schema documentation; useful as a structural
  cross-reference for the AST shape.

## Community references (wiki.nftables.org)

- **[Main Page](https://wiki.nftables.org/wiki-nftables/index.php/Main_Page)**
  — entry point.
- **[Quick reference — nftables in 10 minutes](https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes)**
  — the syntax tour everyone reads first.
- **[Configuring tables](https://wiki.nftables.org/wiki-nftables/index.php/Configuring_tables)**
- **[Configuring chains](https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains)**
- **[Performing NAT](https://wiki.nftables.org/wiki-nftables/index.php/Performing_Network_Address_Translation_(NAT))**
- **[Sets](https://wiki.nftables.org/wiki-nftables/index.php/Sets)** /
  **[Maps](https://wiki.nftables.org/wiki-nftables/index.php/Maps)** /
  **[Verdict Maps (vmaps)](https://wiki.nftables.org/wiki-nftables/index.php/Verdict_Maps_(vmaps))** /
  **[Concatenations](https://wiki.nftables.org/wiki-nftables/index.php/Concatenations)**
- **[Meters / dynamic sets](https://wiki.nftables.org/wiki-nftables/index.php/Meters)**
- **[Matching conntrack metainformation](https://wiki.nftables.org/wiki-nftables/index.php/Matching_connection_tracking_stateful_metainformation)**
- **[Setting conntrack metainformation](https://wiki.nftables.org/wiki-nftables/index.php/Setting_packet_connection_tracking_metainformation)**
- **[Conntrack helpers](https://wiki.nftables.org/wiki-nftables/index.php/Conntrack_helpers)**
- **[Logging traffic](https://wiki.nftables.org/wiki-nftables/index.php/Logging_traffic)**
- **[Flowtables](https://wiki.nftables.org/wiki-nftables/index.php/Flowtables)**
- **[Scripting](https://wiki.nftables.org/wiki-nftables/index.php/Scripting)**
  — `nftables.conf` file conventions; reference for the `~NFT` /
  `Linx.NFT.Conf` parser scope.
- **[List of updates since Linux kernel 3.13](https://wiki.nftables.org/wiki-nftables/index.php/List_of_updates_since_Linux_kernel_3.13)**
  — per-version feature additions; lookup table for kernel-floor
  decisions.
- **[Portal:DeveloperDocs/nftables internals](https://wiki.nftables.org/wiki-nftables/index.php/Portal:DeveloperDocs/nftables_internals)**
  — wire-format internals; the right reading list for codec
  implementers.

## nftables source (grammar reference for `~NFT`)

- **[`src/parser_bison.y`](https://git.netfilter.org/nftables/plain/src/parser_bison.y)**
  — full bison grammar, ~6,594 lines, ~471 left-hand-side
  non-terminals. The reference for what `~NFT` parses (subset)
  and emits.
- **[`src/scanner.l`](https://git.netfilter.org/nftables/plain/src/scanner.l)**
  — flex lexer with 50+ start conditions; reference for
  `Linx.NFT.Tokenizer`'s start-condition stack.
- **[`libnftnl`](https://git.netfilter.org/libnftnl/)** — readable
  netlink-message construction reference (we don't link it, but
  it's the canonical implementation of the wire format).

## HEEx implementation (model for `~NFT`)

- **[`phoenix_live_view/lib/phoenix_live_view/tag_engine/tokenizer.ex`](https://github.com/phoenixframework/phoenix_live_view/blob/main/lib/phoenix_live_view/tag_engine/tokenizer.ex)**
  (~773 LOC) — the char-by-char tokenizer pattern
  `Linx.NFT.Tokenizer` mirrors.
- **[`phoenix_live_view/lib/phoenix_live_view/tag_engine/parser.ex`](https://github.com/phoenixframework/phoenix_live_view/blob/main/lib/phoenix_live_view/tag_engine/parser.ex)**
  (~731 LOC) — the token-stream parser pattern.
- **[`phoenix_live_view/lib/phoenix_live_view/tag_engine/compiler.ex`](https://github.com/phoenixframework/phoenix_live_view/blob/main/lib/phoenix_live_view/tag_engine/compiler.ex)**
  (~1348 LOC) — the AST-to-compiled-Elixir pattern.
- **[`phoenix_live_view/lib/phoenix_live_view/html_formatter.ex`](https://github.com/phoenixframework/phoenix_live_view/blob/main/lib/phoenix_live_view/html_formatter.ex)**
  (~657 LOC) — `mix format` plugin reference for the formatter.

## Production-shape references

- **[Kubernetes blog — nftables kube-proxy mode (Feb 2025)](https://kubernetes.io/blog/2025/02/28/nftables-kube-proxy/)**
  — the canonical "scalable NAT via nftables" design: vmaps
  with concatenated keys for service dispatch. The shape
  Linx.Netfilter should make ergonomic.
- **[ulogd2 documentation](https://www.netfilter.org/projects/ulogd/)**
  — reference NFLOG consumer; useful for understanding per-group
  worker patterns and qthresh / timeout tuning.
- **[firewalld nftables backend (2019 post-mortem)](https://firewalld.org/2019/09/libnftables-JSON)**
  — large-scale nftables consumer; informative on edge cases of
  the JSON form (which Linx avoids).
- **[Hairpin NAT with nftables — chromic.org](https://chromic.org/blog/hairpin-nat-with-nftables/)**
  — the DNAT+SNAT pattern Linx.Netfilter examples will document.

## Adjacent userspace tooling

- **[`nft`](https://www.netfilter.org/projects/nftables/) (the CLI)**
  — userspace tool; everything Linx.Netfilter does could
  alternatively be done via `nft`. We don't shell to it; the
  point of Linx is to be the in-Elixir equivalent.
- **[`google/nftables`](https://pkg.go.dev/github.com/google/nftables)**
  (Go) — pure-Go reimplementation of libnftnl. Closest precedent
  for what we're building. ~15 kloc; informative for sizing the
  codec milestones.
- **[`nftnl-rs`](https://github.com/mullvad/nftnl-rs)** / **[`nftables-rs`](https://github.com/nftables-rs/nftables-rs)** (Rust)
  — low-level netlink and JSON-shim respectively.
- **[`nftables` on hex.pm](https://hex.pm/packages/nftables)** —
  pre-existing Elixir wrapper (libnftables JSON via a Zig port);
  different architecture from Linx, but useful prior art to know
  about.

## In-repo cross-references

- `Linx.Netlink` — `Linx.Netlink.Rtnl`'s codec DSL +
  socket plumbing; `Linx.Netlink.Nfnl` mirrors the family-specific
  parts for netfilter.
- `Linx.Seccomp` — the value-type-with-codec precedent
  (`%Linx.Seccomp.Filter{}` is the small-scale version of what
  `%Linx.Netfilter.Ruleset{}` is at large scale).
- `Linx.Process` — the checkpoint composition story;
  every cross-namespace verb (Mount, User, Capabilities, Seccomp,
  Sysctl, Netfilter) hooks in the same way.
- `Linx.Sysctl` — the most recent "build a subsystem from
  scratch" template; Netfilter's milestone shape borrows from it.
