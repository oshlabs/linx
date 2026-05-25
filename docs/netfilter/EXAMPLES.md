# Linx.Netfilter examples

Hands-on examples of `Linx.Netfilter` — the modern firewall surface
(nf_tables) via nfnetlink, plus live ruleset monitoring and NFLOG
packet events.

Most mutating operations need `CAP_NET_ADMIN` (root in practice).
Read-only operations against the kernel (`pull`, `get_gen`) also
need it on current kernels — `nf_tables_getgen` is gated on
`CAP_NET_ADMIN` for security reasons. Opening the netlink socket
itself is unprivileged.

> 🚧 **Skeleton.** Primitives are still in flight; sections fill
> in as milestones ship. See `PLAN.md` for the roadmap and
> `COVERAGE.md` for what's in / out per milestone.

## Detecting nfnetlink support

```elixir
iex> Linx.Netfilter.supported?()
true
```

`supported?/0` returns true iff a `NETLINK_NETFILTER` socket can
be opened in the current netns. Universal on any kernel built with
`CONFIG_NETFILTER_NETLINK=y` (the default on modern Linux). Doesn't
verify that the caller has `CAP_NET_ADMIN` — that surfaces from
the actual verb call (`{:error, %Linx.Netfilter.Error{errno: :eperm}}`).

## Opening the transport socket

```elixir
iex> {:ok, sock} = Linx.Netlink.Nfnl.open()
iex> sock.protocol
12  # NETLINK_NETFILTER
iex> sock.netns
:host
iex> :ok = Linx.Netlink.Socket.close(sock)
```

For another netns (typically a `Linx.Process`-spawned workload):

```elixir
iex> {:ok, sock} = Linx.Netlink.Nfnl.open({:pid, host_pid})
iex> sock.netns
{:pid, 12345}
```

The socket is pinned to that netns for its lifetime — operations
through it land in the target's nftables instance, not the host's.

## Reading the generation counter

The kernel maintains a monotonic 32-bit counter that bumps on every
successful ruleset commit. It's the key to optimistic concurrency
(N5's `:reconcile` mode threads it through batches) and to
exactly-once-from-snapshot monitoring (N6 buckets multicast events
by gen id).

```elixir
iex> {:ok, sock} = Linx.Netlink.Nfnl.open()
iex> Linx.Netlink.Nfnl.Codec.get_gen(sock)
{:ok, %{id: 1247, proc_pid: 4583, proc_name: "nft"}}
```

`:id` is the generation counter; `:proc_pid` + `:proc_name`
attribute the most recent committer (free observability — kernel
fills these in itself).

## Building a ruleset with the pipeline DSL

Every `Linx.Netfilter` value is plain data — a `%Ruleset{}` is what
you push to the kernel, what you pull back, and what you diff
against. N1 ships the value types and the validator-setter
pipeline DSL; the wire codec arrives in N2.

```elixir
alias Linx.Netfilter.{Expr, Rule, Ruleset, Set, Verdict, Vmap}

ruleset =
  Ruleset.new()
  |> Ruleset.add_table!(:inet, "myapp", flags: [:owner])
  |> Ruleset.add_chain!("myapp", "input",
       type: :filter, hook: :input, priority: 0, policy: :drop)
  |> Ruleset.add_chain!("myapp", "ssh_in")
  |> Ruleset.add_set!("myapp", Set.new!("blocklist", key_type: :ipv4_addr))
  |> Ruleset.add_map!("myapp",
       Vmap.new!("port_dispatch",
         key_type: :inet_service,
         elements: [{22, {:jump, "ssh_in"}}, {80, :accept}, {443, :accept}]))
  |> Ruleset.add_rule!("myapp", "input",
       [Expr.new(:counter), {:jump, "ssh_in"}],
       tag: :try_ssh)
  |> Ruleset.add_rule!("myapp", "ssh_in", [:accept])
```

Every mutator comes in two flavours — `add_table/4` returns
`{:ok, ruleset} | {:error, _}`, while `add_table!/4` returns the
ruleset or raises. Use the bang variant for inline pipeline
construction; the plain form composes through `with` blocks.

## Value validation

Validators reject malformed input at construction:

```elixir
iex> Linx.Netfilter.Chain.new("c", type: :nat, hook: :prerouting, priority: 0)
...> |> elem(1)
...> |> Linx.Netfilter.Chain.validate_for_family(:arp)
{:error, {:bad_chain, {:type_not_valid_for_family, %{type: :nat, family: :arp}}}}

iex> Linx.Netfilter.Vmap.new("dispatch",
...>   key_type: :inet_service,
...>   elements: [{22, :not_a_verdict}])
{:error, {:bad_map, {:bad_element, _, {:bad_verdict, :not_a_verdict}}}}

iex> Linx.Netfilter.Chain.new("c", type: :filter, hook: :ingress, priority: 0)
{:error, {:bad_chain, {:device_required_for_hook, :ingress}}}
```

Family-aware checks (chain-type/family, chain-hook/family,
type+hook compatibility) run when the chain is added to a table —
`Linx.Netfilter.Ruleset.add_chain/4` propagates the family from
the table.

## Tag-as-converged-identity

Rules carry a `:tag` (atom) and a `:handle` (kernel-assigned,
`nil` until pushed). N5's `:reconcile` mode uses the tag as the
stable identity across pushes:

```elixir
ruleset =
  Ruleset.new()
  |> Ruleset.add_table!(:inet, "myapp")
  |> Ruleset.add_chain!("myapp", "input", type: :filter, hook: :input, priority: 0)
  |> Ruleset.add_rule!("myapp", "input", [:accept], tag: :allow_all)

# Re-adding the same tag is rejected at the value-type layer:
Ruleset.add_rule(ruleset, "myapp", "input", [:drop], tag: :allow_all)
# => {:error, {:bad_rule, {:duplicate_tag, :allow_all}}}
```

## Creating a table (N2)

Owner-flag is the default: when the socket closes, the kernel
atomically destroys the table.

```elixir
{:ok, sock} = Linx.Netlink.Nfnl.open()
{:ok, ruleset} = Linx.Netfilter.create_table(sock, "myapp", family: :inet)

# The returned ruleset has just the one table — chains and rules
# can be added with the pipeline DSL, then `push/2`-ed back.
```

Opt out of owner cleanup with `persist: true`:

```elixir
{:ok, ruleset} = Linx.Netfilter.create_table(sock, "myapp", persist: true)
# Table survives socket close; clean up with `nft delete table` or
# (when N2 ships destroy verbs in Linx itself) a future helper.
```

## Pushing a complete ruleset (`push/2 :replace`)

Build the ruleset with the pipeline DSL (N1), then push it as one
atomic batch. The kernel sees `DESTROYTABLE` (silent if missing)
then `NEWTABLE` + all chains + all rules — old state for the named
table is replaced cleanly.

```elixir
alias Linx.Netfilter.{Expr, Rule, Ruleset, Verdict}

ruleset =
  Ruleset.new()
  |> Ruleset.add_table!(:inet, "myapp", flags: [:owner])
  |> Ruleset.add_chain!("myapp", "input",
       type: :filter, hook: :input, priority: 0, policy: :drop)
  |> Ruleset.add_chain!("myapp", "ssh_in")
  |> Ruleset.add_rule!("myapp", "input",
       Rule.build!([
         Expr.ct(:state),
         Expr.bitwise(<<6::big-32>>, <<0::big-32>>),  # mask: established | related
         Expr.cmp(:neq, <<0::big-32>>),
         Verdict.accept()
       ], tag: :ct_established))
  |> Ruleset.add_rule!("myapp", "input",
       Rule.build!([
         Expr.payload(:tcp_dport),
         Expr.cmp(:eq, <<22::big-16>>),
         Verdict.jump("ssh_in")
       ], tag: :try_ssh))
  |> Ruleset.add_rule!("myapp", "ssh_in", [Verdict.accept()])

:ok = Linx.Netfilter.push(sock, ruleset)
```

## Pulling a ruleset back

```elixir
# Pull the whole netns:
{:ok, %Ruleset{} = current} = Linx.Netfilter.pull(sock)
Ruleset.tables(current)
# => [{:inet, "myapp", %Table{...}}, ...]

# Pull just one table by {family, name}:
{:ok, %Ruleset{}} = Linx.Netfilter.pull(sock, {:inet, "myapp"})

# Nonexistent table:
{:error, %Linx.Netfilter.Error{errno: :enoent}} =
  Linx.Netfilter.pull(sock, {:inet, "ghost"})
```

Rules round-trip through `pull/2` with their expressions decoded
back into `%Expr{}` shape — `Expr.payload(:tcp_dport)` becomes
`%Expr{name: :payload, data: %{base: :transport, offset: 2, len: 2, dreg: 1}}`
after the wire trip. Kernel-assigned handles populate `:handle`.

## Owner-flag cleanup

```elixir
{:ok, sock} = Linx.Netlink.Nfnl.open()
{:ok, _} = Linx.Netfilter.create_table(sock, "ephemeral")
# … push chains and rules into it …

Linx.Netlink.Socket.close(sock)
# Kernel atomically destroys the table and everything inside it.
# No manual cleanup, no leaked rules.
```

Same shape as every Linx subsystem: BEAM owns the resource;
BEAM crash → kernel reaps it. The unique Linx shape that no other
firewall manager exposes naturally.

## DNAT port-forward (N3)

Forward incoming TCP/8080 to an internal host's TCP/80. The
`Expr.dnat_to/3` helper handles register allocation transparently
— it returns a list of `%Expr{}` (immediate-load of address,
immediate-load of port, the nat expression) which `Rule.build`
flattens into the rule's expression list.

```elixir
alias Linx.Netfilter.{Expr, Rule, Ruleset}

ruleset =
  Ruleset.new()
  |> Ruleset.add_table!(:inet, "fwd", flags: [:owner])
  |> Ruleset.add_chain!("fwd", "prerouting",
       type: :nat, hook: :prerouting, priority: :dstnat)
  |> Ruleset.add_rule!("fwd", "prerouting",
       Rule.build!([
         Expr.payload(:tcp_dport),
         Expr.cmp(:eq, <<8080::big-16>>),
         Expr.dnat_to({10, 0, 0, 5}, 80)
       ]))

:ok = Linx.Netfilter.push(sock, ruleset)
```

`dnat_to/3` accepts addresses as IPv4 4-tuples, IPv6 8-tuples,
raw binaries, strings (parsed via `Linx.IP.parse/1`), or
`%Linx.IP{}` structs.

## Masquerade (N3)

Source-NAT to the outgoing interface's primary address — the
right shape when the public IP isn't known at rule-write time
(DHCP-assigned WAN, PPP links). Only valid in postrouting chains.

```elixir
Ruleset.new()
|> Ruleset.add_table!(:inet, "nat", flags: [:owner])
|> Ruleset.add_chain!("nat", "postrouting",
     type: :nat, hook: :postrouting, priority: :srcnat)
|> Ruleset.add_rule!("nat", "postrouting",
     Rule.build!([Expr.masquerade()]))
```

Add `flags: [:random]` or `:fully_random` to randomize port
selection; `:persistent` to keep the same client on the same
outbound port for connection stability.

## Hairpin NAT (N3)

The DNAT-then-SNAT pattern for "talk to my public address from
inside the LAN and have it reach the internal service correctly".
Composes from primitives — two NAT rules in two chains:

```elixir
Ruleset.new()
|> Ruleset.add_table!(:inet, "hairpin", flags: [:owner])
|> Ruleset.add_chain!("hairpin", "prerouting",
     type: :nat, hook: :prerouting, priority: :dstnat)
|> Ruleset.add_chain!("hairpin", "postrouting",
     type: :nat, hook: :postrouting, priority: :srcnat)
|> Ruleset.add_rule!("hairpin", "prerouting",
     Rule.build!([
       Expr.payload(:tcp_dport),
       Expr.cmp(:eq, <<8080::big-16>>),
       Expr.dnat_to({10, 0, 0, 5}, 80)
     ]))
|> Ruleset.add_rule!("hairpin", "postrouting",
     Rule.build!([
       Expr.payload(:ip_daddr),
       Expr.cmp(:eq, <<10, 0, 0, 5>>),
       Expr.payload(:tcp_dport),
       Expr.cmp(:eq, <<80::big-16>>),
       Expr.snat_to({192, 168, 1, 1})
     ]))
```

## Redirect to local port (N3)

DNAT to the local machine on a different port — the right shape
for transparent proxies or port-shifting on a single host.

```elixir
Ruleset.new()
|> Ruleset.add_table!(:inet, "proxy", flags: [:owner])
|> Ruleset.add_chain!("proxy", "prerouting",
     type: :nat, hook: :prerouting, priority: :dstnat)
|> Ruleset.add_rule!("proxy", "prerouting",
     Rule.build!([
       Expr.payload(:tcp_dport),
       Expr.cmp(:eq, <<80::big-16>>),
       Expr.redirect(port: 8080)
     ]))
```

## Named sets (N4)

A named set declared on a table, then referenced from rules with
`Expr.lookup/2`. Elements round-trip through `push` and `pull/2`.

```elixir
alias Linx.Netfilter.{Expr, Rule, Ruleset, Set, Verdict}

Ruleset.new()
|> Ruleset.add_table!(:inet, "fw", flags: [:owner])
|> Ruleset.add_set!("fw",
     Set.new!("blocklist",
       key_type: :ipv4_addr,
       elements: [{10, 0, 0, 1}, {10, 0, 0, 2}, {192, 168, 1, 100}]))
|> Ruleset.add_chain!("fw", "input",
     type: :filter, hook: :input, priority: 0, policy: :accept)
|> Ruleset.add_rule!("fw", "input",
     Rule.build!([
       Expr.payload(:ip_saddr),
       Expr.lookup("blocklist"),
       Verdict.drop()
     ]))
```

Element types: `:ipv4_addr` (4-tuple or 4-byte binary),
`:ipv6_addr` (8-tuple or 16-byte), `:ether_addr`, `:inet_proto`,
`:inet_service` (port int), `:mark`, `:ifname`. The codec
normalises element shapes for you on encode and decode.

## Maps and vmaps (N4)

A typed map carries `key → value` associations. When the
`:data_type` is `:verdict`, the map is a **verdict map** (vmap) —
the kernel's rule-dispatch primitive (one lookup replaces N
individual rules).

```elixir
alias Linx.Netfilter.{Expr, Rule, Ruleset, Verdict, Vmap}

Ruleset.new()
|> Ruleset.add_table!(:inet, "fw", flags: [:owner])
|> Ruleset.add_chain!("fw", "ssh_in")
|> Ruleset.add_chain!("fw", "http_in")
|> Ruleset.add_map!("fw",
     Vmap.new!("services",
       key_type: :inet_service,
       elements: [
         {22, {:jump, "ssh_in"}},
         {80, {:jump, "http_in"}}
       ]))
|> Ruleset.add_chain!("fw", "input",
     type: :filter, hook: :input, priority: 0, policy: :drop)
|> Ruleset.add_rule!("fw", "input",
     Rule.build!([
       Expr.payload(:tcp_dport),
       Expr.lookup("services", dreg: 0)  # dreg: 0 loads into verdict register
     ]))
|> Ruleset.add_rule!("fw", "ssh_in", [Verdict.accept()])
|> Ruleset.add_rule!("fw", "http_in", [Verdict.accept()])
```

For plain (non-verdict) maps:

```elixir
alias Linx.Netfilter.Map, as: NMap

NMap.new!("dnat_pool",
  key_type: :inet_service,
  data_type: :ipv4_addr,
  elements: [{80, {10, 0, 0, 5}}, {443, {10, 0, 0, 6}}])
```

## Anonymous sets (N4)

Inline `{22, 80, 443}` literals in a rule — the encoder
auto-generates a `NFT_SET_F_ANONYMOUS | NFT_SET_F_CONSTANT` set
tied to the rule, no separate `add_set!` needed.

```elixir
Ruleset.new()
|> Ruleset.add_table!(:inet, "fw", flags: [:owner])
|> Ruleset.add_chain!("fw", "input",
     type: :filter, hook: :input, priority: 0, policy: :drop)
|> Ruleset.add_rule!("fw", "input",
     Rule.build!([
       Expr.payload(:tcp_dport),
       Expr.set_literal([22, 80, 443], :inet_service),
       Verdict.accept()
     ]))
```

The anonymous set lives and dies with the rule.

## Reconcile push (N5) — minimal-change updates

`mode: :reconcile` is the LiveView-of-firewalls form: instead of
rebuilding the entire table on every push, Linx pulls the
kernel's current state, computes the minimum patch, and sends
only the messages that change something.

```elixir
alias Linx.Netfilter.{Expr, Rule, Ruleset, Verdict}

# Build the desired state — same as :replace, but every rule that
# matters across pushes carries a stable :tag.
desired =
  Ruleset.new()
  |> Ruleset.add_table!(:inet, "fw", flags: [:owner])
  |> Ruleset.add_chain!("fw", "input",
       type: :filter, hook: :input, priority: 0, policy: :drop)
  |> Ruleset.add_rule!("fw", "input",
       Rule.build!([
         Expr.payload(:tcp_dport),
         Expr.cmp(:eq, <<22::big-16>>),
         Verdict.accept()
       ], tag: :allow_ssh))
  |> Ruleset.add_rule!("fw", "input",
       Rule.build!([
         Expr.payload(:tcp_dport),
         Expr.cmp(:eq, <<80::big-16>>),
         Verdict.accept()
       ], tag: :allow_http))

# First push — `:replace` is fine for the initial create.
:ok = Linx.Netfilter.push(sock, desired)

# Later: move ssh from port 22 to 2222. Rebuild the ruleset (the
# tag :allow_ssh marks the rule's identity across pushes), then
# reconcile.
desired_v2 = update_ssh_port(desired, 2222)

:ok = Linx.Netfilter.push(sock, desired_v2, mode: :reconcile)
# Wire payload: one BATCH_BEGIN with NFNL_BATCH_GENID, one NEWRULE
# with NLM_F_REPLACE for the :allow_ssh handle, one BATCH_END.
# The :allow_http rule is untouched — its connections survive.
```

The kernel's per-netns generation counter is read with `GETGEN`
and threaded through the batch via `NFNL_BATCH_GENID`. If another
writer (a separate `nft` invocation, firewalld, another Linx
process) commits between Linx's pull and Linx's push, the kernel
returns `-ERESTART` and Linx retries up to 3 times with
exponential backoff before surfacing the error.

Tables that exist in the kernel but aren't in `desired` are
**not deleted** — the reconcile diff is scoped to tables in
`desired`. This lets Linx coexist with Docker, firewalld, and
other ruleset writers in the same netns without stomping on them.

## Tag enforcement

Reconcile mode rejects rulesets where a multi-rule chain has any
untagged rule — without stable identity per rule, the diff has no
way to tell "what changed" from "what's still the same":

```elixir
Linx.Netfilter.push(sock, ruleset_with_untagged_rules, mode: :reconcile)
# => {:error, {:tag_required, {:inet, "fw", "input"}}}

# Single-rule chains are fine — there's nothing to be ambiguous about.
# Use `mode: :replace` (default) for chains you don't intend to tag.
```

## `dry_run/2`

`dry_run/2` is `diff/2` under a more readable name — get the
patch without sending it. Useful for "what would change?"
queries before a commit.

```elixir
{:ok, current} = Linx.Netfilter.pull(sock, {:inet, "fw"})
patch = Linx.Netfilter.dry_run(current, desired)
IO.inspect(patch)
# => #Linx.Netfilter.Patch<1 op: 1 replace>

case patch do
  %Linx.Netfilter.Patch{ops: []} -> IO.puts("Already up to date")
  _ -> Linx.Netfilter.push(sock, desired, mode: :reconcile)
end
```

## Monitor — live ruleset events (N6)

Subscribe to `NFNLGRP_NFTABLES` multicast events. The owner pid
receives `{:linx_netfilter, :event, %Event{}}` for every committed
change, with full provenance (`gen_id`, `proc_pid`, `proc_name`).

```elixir
alias Linx.Netfilter.{Event, Monitor}

{:ok, monitor} = Linx.Netfilter.subscribe(self())

# Now anyone (us, another nft client, firewalld, ...) committing
# to the netns triggers events:
receive do
  {:linx_netfilter, :event, %Event{op: :new_table, entity: t, proc_name: who}} ->
    IO.puts("#{who} created table #{t.family}/#{t.name}")
end

:ok = Linx.Netfilter.unsubscribe(monitor)
```

The kernel broadcasts entity events first, then a `NEW_GEN`
closing marker. The Monitor buffers entities until `NEW_GEN`
arrives and dispatches them all stamped with that gen — so each
`%Event{}` carries the full context of "who changed this and
when".

## Snapshot+tail (no race with the kernel)

The race-free "get current state, then watch for changes" pattern.
`subscribe_first:` captures the gen before pull and tells the
Monitor to drop events already in the snapshot:

```elixir
{:ok, monitor} = Linx.Netfilter.subscribe(self())
{:ok, snapshot} = Linx.Netfilter.pull(sock, subscribe_first: monitor)

# `snapshot` contains everything as of gen N.
# Subsequent {:linx_netfilter, :event, ...} messages cover gen > N.
# Apply them as deltas to `snapshot` for a perfectly-consistent
# live view.
```

## ENOBUFS recovery

If the multicast traffic outpaces the consumer, the kernel drops
messages and the Monitor emits a resync hint:

```elixir
receive do
  {:linx_netfilter, :resync_needed} ->
    # Drop the partial state; re-pull from scratch.
    {:ok, fresh} = Linx.Netfilter.pull(sock, subscribe_first: monitor)
    ...
end
```

Default `SO_RCVBUF` is 4 MiB; pass `:rcvbuf` to `subscribe/2` to
raise it further if your environment is heavily churned.

## NFLOG (N7) — per-packet observability

Subscribe to a NFLOG group via `log_listen/2`, then push rules
with `Expr.log/1` that route matching packets to that group. The
listener decodes each `NFULNL_MSG_PACKET` into a `%Log.Event{}`
with prefix, mark, timestamp, indev/outdev, hwaddr, payload, and
more.

```elixir
alias Linx.Netfilter.{Expr, Rule, Ruleset, Verdict}

# Open the listener. Linx convention: use group 5000 unless you
# have a reason to pick something else.
{:ok, listener} =
  Linx.Netfilter.log_listen(self(),
    group: 5000,
    copy_mode: {:packet, 256},
    flags: [:seq])

# A rule that logs and accepts every inbound packet.
ruleset =
  Ruleset.new()
  |> Ruleset.add_table!(:inet, "audit", flags: [:owner])
  |> Ruleset.add_chain!("audit", "input",
       type: :filter, hook: :input, priority: -200, policy: :accept)
  |> Ruleset.add_rule!("audit", "input",
       Rule.build!([
         Expr.log(group: 5000, prefix: "inbound"),
         Verdict.accept()
       ]))

:ok = Linx.Netfilter.push(sock, ruleset)

# Now any packet on the input chain triggers an event:
receive do
  {:linx_netfilter, :log, %{prefix: "inbound", payload: bytes, hwaddr: mac}} ->
    IO.puts("Saw #{byte_size(bytes)} bytes from #{inspect(mac)}")
end

:ok = Linx.Netfilter.unlog_listen(listener)
```

## Copy modes

  * `:none` — only the metadata attributes; no payload, no
    hwaddr. Cheapest.
  * `:meta` (default) — metadata including hwaddr but no packet
    payload.
  * `:packet` — full packet up to the kernel default snaplen.
  * `{:packet, snaplen}` — packet truncated to `snaplen` bytes.

For audit-only use cases, `:meta` is plenty and avoids the data
copy. For decoding the payload yourself (TCP headers, etc.),
`{:packet, snaplen}` lets you control the bandwidth.

## Multi-group routing

Each `log_listen/2` call binds one group. Multiple listeners on
different groups route disjoint event streams to different
owners:

```elixir
{:ok, audit} = Linx.Netfilter.log_listen(self(), group: 5001, copy_mode: :meta)
{:ok, debug} = Linx.Netfilter.log_listen(debug_pid, group: 5002, copy_mode: {:packet, 1500})
```

A rule with `Expr.log(group: 5001)` flows to `audit`; one with
`group: 5002` flows to `debug`.

## ENOBUFS

Same shape as the Monitor: if the multicast firehose outpaces
the consumer, the kernel drops events and the listener emits
`{:linx_netfilter, :resync_needed}` to the owner. Default
`SO_RCVBUF` is 4 MiB; tune with `:rcvbuf`.

## (Will land with N8 — `~NFT` sigil + Conf parser)

## (Will land with N9 — `mix format` plugin)
