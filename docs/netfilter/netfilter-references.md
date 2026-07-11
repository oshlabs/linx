# References

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
  — userspace tool reference.
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
  — `nftables.conf` file conventions.
- **[List of updates since Linux kernel 3.13](https://wiki.nftables.org/wiki-nftables/index.php/List_of_updates_since_Linux_kernel_3.13)**
  — per-version feature additions; lookup table for kernel-floor
  decisions.
- **[Portal:DeveloperDocs/nftables internals](https://wiki.nftables.org/wiki-nftables/index.php/Portal:DeveloperDocs/nftables_internals)**
  — wire-format internals; the right reading list for codec
  implementers.

## nftables source

- **[`libnftnl`](https://git.netfilter.org/libnftnl/)** — readable
  netlink-message construction reference (we don't link it, but
  it's the canonical implementation of the wire format).
