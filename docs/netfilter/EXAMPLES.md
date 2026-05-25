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

## (Will land with N1 — value types + pipeline DSL)

## (Will land with N2 — minimal expressions + push :replace)

## (Will land with N3 — NAT chains + NAT expressions)

## (Will land with N4 — sets, maps, vmaps, dynamic sets)

## (Will land with N5 — diff + :reconcile + BATCH_GENID CAS)

## (Will land with N6 — monitor: snapshot+tail)

## (Will land with N7 — NFLOG via NFNL_SUBSYS_ULOG)

## (Will land with N8 — `~NFT` sigil + Conf parser)

## (Will land with N9 — `mix format` plugin)
