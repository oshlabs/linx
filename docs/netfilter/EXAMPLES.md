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

## (Will land with N4 — sets, maps, vmaps, dynamic sets)

## (Will land with N5 — diff + :reconcile + BATCH_GENID CAS)

## (Will land with N6 — monitor: snapshot+tail)

## (Will land with N7 — NFLOG via NFNL_SUBSYS_ULOG)

## (Will land with N8 — `~NFT` sigil + Conf parser)

## (Will land with N9 — `mix format` plugin)
