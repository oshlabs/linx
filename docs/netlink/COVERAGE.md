# Linx coverage

What of the Linux netlink surface Linx exposes today, what is deferred, and
what is most useful to add next.

This is a **prioritization document**, not an exhaustive `iproute2`
reimplementation checklist: not everything `iproute2` does belongs in Linx,
and the goal is a focused library, not parity for its own sake. The priority
columns are subjective starting points to argue with.

A living doc — update it as features ship.

## Legend

**Status:**

| | |
|---|---|
| ✅ | done — shipped and integration-tested |
| 🟡 | partial — some sub-features in, others not |
| ⬜ | todo — not yet |
| ⏳ | architected-for — the design accommodates it, no code yet |

**Priority** (rough effort-vs-value calls):

| | |
|---|---|
| **high** | common use case, small-to-moderate effort |
| **med** | useful but more work or narrower audience |
| **low** | niche or large effort |
| **defer** | explicitly out of scope for the foreseeable future |

Where a milestone shipped a feature, the `Notes` column points to it.

---

## NETLINK_ROUTE — rtnetlink

The networking-stack interface. Linx's primary focus.

### Links — `ip link` / `RTM_*LINK`

Status: **🟡 partial.** Core CRUD plus common virtual link kinds.

| Feature | Status | Priority | Notes |
|---|---|---|---|
| `list` / `get` | ✅ | — | M2 |
| `create_macvlan`, `create_ipvlan` | ✅ | — | M4 |
| `create_veth`, `create_vlan`, `create_bridge`, `create_dummy` | ✅ | — | M6 |
| create `bond` | ⬜ | med | uses `IFLA_INFO_DATA` like veth |
| create `vxlan` | ⬜ | med | overlay tunnels, growing use case |
| create `tun` / `tap` | ⬜ | med | userspace networking, qemu, OpenVPN |
| create `gre` / `ipip` / `sit` | ⬜ | low | legacy tunnels |
| create `geneve` | ⬜ | low | cloud overlays |
| create `vrf` | ⬜ | low | per-VRF routing |
| `set_up`/`set_down`/`set_mtu`/`set_name`/`set_address`/`set_master` | ✅ | — | M6 |
| set txqlen, group, arp, multicast, promisc, carrier | ⬜ | med | |
| set xdp | ⬜ | low | XDP program attach |
| `delete` | ✅ | — | M4 |
| `move_to_netns` | ✅ | — | M4 |
| stats (`RTM_GETSTATS`) | ✅ | — | M8 — `Rtnl.Stats` (link_64 counters) |

### Addresses — `ip addr` / `RTM_*ADDR`

Status: **🟡 partial.** Add/delete/list cover the basics.

| Feature | Status | Priority | Notes |
|---|---|---|---|
| `add` IPv4 / IPv6 | ✅ | — | M5 |
| `delete` | ✅ | — | M5 |
| `list` (all / per-link) | ✅ | — | M5 |
| `valid_lft` / `preferred_lft` | ⬜ | med | dynamic addresses |
| address flags (`IFA_FLAGS`) | ⬜ | med | tentative, deprecated, … |
| broadcast | ⬜ | low | |
| label | ⬜ | low | |
| peer (point-to-point) | ⬜ | low | |
| replace | ⬜ | low | |

### Routes — `ip route` / `RTM_*ROUTE`

Status: **🟡 partial.** Add/delete/list, IPv4 + IPv6. Missing get, multipath
and metrics.

| Feature | Status | Priority | Notes |
|---|---|---|---|
| `add` (dst/prefix/gateway), v4 + v6 | ✅ | — | M5 |
| `add_default` / `delete_default` | ✅ | — | M4 / M5 |
| `delete` | ✅ | — | M5 |
| `list` | ✅ | — | M5 |
| `get` (lookup a destination) | ✅ | — | M8 — `Route.get/2` |
| multipath / nexthop groups | ⬜ | med | container / cloud routing |
| route metrics (`RTAX_*`: mtu, hoplimit, rtt) | ⬜ | med | |
| route types (blackhole, prohibit, unreachable, throw) | ⬜ | med | |
| source-routing (`RTA_SRC`) | ⬜ | low | |
| tables beyond `main` | ⬜ | med | pairs with Rule |
| realm, cache | ⬜ | low | |

### Rules — `ip rule` / `RTM_*RULE`

Status: **🟡 partial.** Selectors: from, to, fwmark, table, priority.

| Feature | Status | Priority | Notes |
|---|---|---|---|
| `list` | ✅ | — | M7 |
| `add` / `delete` (from/to/fwmark/table/priority) | ✅ | — | M7 |
| iif / oif selectors | ⬜ | med | |
| tos | ⬜ | low | |
| uidrange | ⬜ | low | per-uid routing |
| ipproto, dport, sport | ⬜ | low | L4 selectors |
| suppress_prefixlength | ⬜ | low | |
| l3mdev (VRF-aware) | ⬜ | low | |
| actions other than `to_tbl` (goto, blackhole, prohibit, unreachable, nat) | ⬜ | low | |

### Neighbours — `ip neigh` / `RTM_*NEIGH`

Status: **🟡 partial.** Permanent entries, IPv4 + IPv6.

| Feature | Status | Priority | Notes |
|---|---|---|---|
| `list` / `list` per-link | ✅ | — | M7 |
| `add` permanent / `delete` | ✅ | — | M7 |
| other `NUD_*` states (REACHABLE, STALE, FAILED) | ⬜ | low | mostly kernel-managed |
| proxy entries | ⬜ | low | |
| flush | ⬜ | low | |
| replace | ⬜ | low | |

### Bridge — `bridge` / bridge-specific messages

Status: **🟡 partial.** Create + slave via `Link`; nothing bridge-specific.

| Feature | Status | Priority | Notes |
|---|---|---|---|
| `Link.create_bridge`, `Link.set_master` | ✅ | — | M6 (via Link) |
| bridge port settings (STP, learning, flood) | ⬜ | med | |
| VLAN filtering (`RTM_*VLAN`) | ⬜ | med | tagging / trunking |
| FDB entries (`RTM_*NEIGH` with `NTF_SELF`) | ⬜ | med | static MAC entries |
| MDB (multicast) | ⬜ | low | |

### Traffic control — `tc` / `RTM_*QDISC` / `*TCLASS` / `*TFILTER`

Status: **⬜ Not started.** The biggest single piece of rtnetlink — qdiscs
(scheduling), classes (hierarchies), filters (classification), actions. A
focused Linx slice — `fq_codel`, basic `htb` — would be useful without
becoming a full reimplementation.

| Feature | Status | Priority | Notes |
|---|---|---|---|
| `fq_codel` qdisc | ⬜ | med | sensible default qdisc |
| `htb` (Hierarchy Token Bucket) + classes | ⬜ | med | classical shaper |
| `tbf` (Token Bucket Filter) | ⬜ | low | simple shaper |
| `mq` / `mqprio` | ⬜ | low | multi-queue |
| `clsact` + filters | ⬜ | low | for XDP/BPF |
| full classful qdisc/class/filter ecosystem | ⬜ | defer | very large surface |

### Other rtnetlink

| Feature | Status | Priority | Notes |
|---|---|---|---|
| Nexthop objects (`RTM_*NEXTHOP`) | ⬜ | med | modern multipath |
| Network statistics (`RTM_GETSTATS`) | ✅ | — | M8 (see Links / stats) |
| netconf (`RTM_*NETCONF`) | ⬜ | low | per-iface IP config (forwarding, rp_filter) |
| addrlabel | ⬜ | low | IPv6 source selection |
| mroute (multicast routing) | ⬜ | low | |
| prefix (`RTM_NEWPREFIX`) | ⬜ | low | IPv6 RA prefixes |
| netns id (`RTM_*NSID`) | ⬜ | low | naming netns by id |

---

## NETLINK_GENERIC — genetlink

Status: **⏳ Architected-for.** The transport layer (`Linx.Netlink.Socket`
accepting any protocol number) exists; the genl-specific bits (family-name
→ numeric ID resolution via the `CTRL` family, `genlmsghdr`) are not built.

A `Linx.Netlink.Generic` foundation unlocks every subsystem below.

| Subsystem | What | Status | Priority | Notes |
|---|---|---|---|---|
| genl `CTRL` (resolve family id) | base layer | ⬜ | **high** | prerequisite for everything else |
| **WireGuard** | manage `wg` interfaces | ⬜ | **high** | modern VPN, common container use |
| **ethtool** | NIC info, link, offloads | ⬜ | **high** | observability + management |
| nl80211 | wireless | ⬜ | med | large surface; for clients/APs |
| devlink | device management | ⬜ | low | |
| TASKSTATS | per-task perf stats | ⬜ | low | |
| nfsd / lockd | NFS server control | ⬜ | low | |
| dpll / psp / ovpn / net_shaper / mptcp_pm | various | ⬜ | low | |

The kernel's YAML netlink specs cover most genl families well (unlike the
`netlink-raw` ones for rtnetlink, which lag). Once `Linx.Netlink.Generic`
exists, **YAML-driven codegen** becomes attractive: the same `Codec` DSL the
hand-written rtnetlink uses, fed by generated declarations from the kernel's
`Documentation/netlink/specs/` files. See cross-cutting below.

---

## NETLINK_NETFILTER

Status: **⬜ Not started.** Each is its own large subsystem.

| Subsystem | Priority | Notes |
|---|---|---|
| nftables | defer | huge surface; the modern firewall |
| conntrack | low | connection tracking |
| ipset | low | hashed sets |
| queue / log | low | NFQUEUE / NFLOG |

---

## NETLINK_INET_DIAG — `ss`

Status: **⬜ Not started.** Socket listing and inspection — observability
gold. Moderate scope; the listing + per-protocol diag info is the bulk.

| Feature | Priority | Notes |
|---|---|---|
| TCP socket dump | **high** | the most common `ss` use |
| UDP / Unix sockets | med | |
| inet info, BBR / `tcp_info` | med | for perf observability |

---

## Other netlink families

Mostly low-priority for a general library.

| Family | Priority | Notes |
|---|---|---|
| NETLINK_AUDIT | low | audit framework |
| NETLINK_XFRM | low | IPsec |
| NETLINK_KOBJECT_UEVENT | low | hotplug events |
| NETLINK_SOCK_DIAG | low | superset of INET_DIAG |

---

## Cross-cutting infrastructure

These are not netlink surface — they are library-level improvements that
unlock or polish what is already there.

| Feature | Status | Priority | Notes |
|---|---|---|---|
| `Linx.Netlink.Connection` (GenServer-owned socket) | ⏳ | **high** | seq correlation, concurrent requests |
| `Linx.Netlink.Monitor` (multicast events) | ⏳ | **high** | `ip monitor` equivalent; subscriptions |
| YAML-driven codegen for genetlink | ⬜ | **high** | broad genl coverage at low per-family cost |
| Property-based codec tests via `stream_data` | ⬜ | low | stronger round-trip guarantees |
| `Linx.IP.Range` (start/end pairs, enumeration) | ⬜ | low | |
| Telemetry / logging hooks | ⬜ | low | for instrumentation |

---

## Suggested Phase 3 shortlist

Filtered down from the matrix above — "useful, achievable in a milestone":

1. ✅ **Interface statistics** — `Rtnl.Stats` via `RTM_GETSTATS`. Shipped in M8.
2. ✅ **`Rtnl.Route.get/2`** — lookup a destination (`ip route get`
   equivalent). Shipped in M8.
3. **`Linx.Netlink.Connection` + `Linx.Netlink.Monitor`** — the multicast
   event story. Unblocks "watch this namespace for link/addr/route changes"
   and is what the synchronous `Request` engine was designed to accept.
4. **`Linx.Netlink.Generic` foundation + WireGuard** as the first genl
   customer.
5. **A few more link kinds** — `bond`, `vxlan`, `tun`/`tap` — and an
   **`ethtool`-via-genl** basic dump.

Items deliberately *not* on the shortlist — `tc`, `nftables`, `nl80211`,
`xfrm`, `devlink` — are each their own large effort and would each be a
phase of their own if they happen at all.
