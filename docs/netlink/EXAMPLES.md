# Linx examples

Hands-on examples of using `Linx.Netlink` against the live Linux kernel.

Read-only operations work in a plain `iex -S mix` session. Anything that
*changes* network state — creating links, adding addresses or routes,
entering another network namespace — needs root: start with `./sudorun.sh`.

## Quick start

```elixir
iex> alias Linx.Netlink.{Rtnl, Socket}
iex> alias Linx.Netlink.Rtnl.Link

iex> {:ok, sock} = Rtnl.open()
{:ok, %Linx.Netlink.Socket{netns: :host, protocol: 0, ...}}

iex> {:ok, links} = Link.list(sock)
iex> links
[#Linx.Netlink.Rtnl.Link<"lo" (1) UP MTU=65536>,
 #Linx.Netlink.Rtnl.Link<"eth0" (2) UP MTU=1500>,
 #Linx.Netlink.Rtnl.Link<"wlan0" (3) DOWN MTU=1500>]

iex> Socket.close(sock)
:ok
```

Every verb takes a socket as its first argument; structs come back from
reads, `:ok` or `{:error, %Linx.Netlink.Error{}}` from mutations.

## Reading the network

### Links

```elixir
iex> {:ok, lo} = Link.get(sock, "lo")
{:ok, #Linx.Netlink.Rtnl.Link<"lo" (1) UP MTU=65536>}

iex> Link.up?(lo)
true
```

### Addresses

```elixir
iex> alias Linx.Netlink.Rtnl.Address

iex> {:ok, addresses} = Address.list(sock)
iex> addresses
[#Linx.Netlink.Rtnl.Address<127.0.0.1/8 ifindex=1>,
 #Linx.Netlink.Rtnl.Address<::1/128 ifindex=1>,
 #Linx.Netlink.Rtnl.Address<192.168.1.42/24 ifindex=2>, ...]

iex> {:ok, lo_addrs} = Address.list(sock, "lo")
iex> Enum.map(lo_addrs, & &1.address)
[~IP"127.0.0.1", ~IP"::1"]
```

### Routes

```elixir
iex> alias Linx.Netlink.Rtnl.Route

iex> {:ok, routes} = Route.list(sock)
iex> routes
[#Linx.Netlink.Rtnl.Route<default via 192.168.1.1 oif=2>,
 #Linx.Netlink.Rtnl.Route<192.168.1.0/24 oif=2>, ...]

# resolve a destination — what route would the kernel use?
iex> {:ok, route} = Route.get(sock, "1.1.1.1")
iex> route
#Linx.Netlink.Rtnl.Route<1.1.1.1/32 via 192.168.1.1 oif=2>
```

### Neighbours (ARP / NDP table)

```elixir
iex> alias Linx.Netlink.Rtnl.Neighbour

iex> {:ok, neighbours} = Neighbour.list(sock)
iex> neighbours
[#Linx.Netlink.Rtnl.Neighbour<192.168.1.1 -> aa:bb:cc:dd:ee:ff ifindex=2>, ...]
```

### Interface statistics

```elixir
iex> alias Linx.Netlink.Rtnl.Stats

iex> {:ok, stats} = Stats.get(sock, "eth0")
iex> stats
#Linx.Netlink.Rtnl.Stats<ifindex=2 rx=128431p/189204771B tx=85912p/12504331B>

iex> stats.link.rx_packets
128431
iex> stats.link.tx_dropped
0

iex> {:ok, all_stats} = Stats.list(sock)   # every interface's counters
```

The counters live on `%Stats{}.link` as a
`%Linx.Netlink.Rtnl.Stats.Link64{}` — the 25 fields of the kernel's
`struct rtnl_link_stats64` (`rx_packets`, `tx_bytes`, `multicast`,
`rx_dropped`, …; full list in the moduledoc).

### Policy-routing rules

```elixir
iex> alias Linx.Netlink.Rtnl.Rule

iex> {:ok, rules} = Rule.list(sock)
iex> rules
[#Linx.Netlink.Rtnl.Rule<table=255>,
 #Linx.Netlink.Rtnl.Rule<priority=32766 table=254>,
 #Linx.Netlink.Rtnl.Rule<priority=32767 table=253>]
```

## Creating virtual interfaces

These need `./sudorun.sh`.

### macvlan / ipvlan — a separate network identity riding a parent NIC

A macvlan is a first-class host on the LAN — its own MAC, its own IP, no
NAT. The other container-networking model.

```elixir
iex> Link.create_macvlan(sock, "web0", "eth0", :bridge)
:ok
iex> Link.create_ipvlan(sock, "app0", "eth0", :l3)
:ok
```

### veth — a connected pair

The other container-networking model — two interfaces wired back-to-back,
typically used with a bridge.

```elixir
iex> Link.create_veth(sock, "v0a", "v0b")
:ok
```

### vlan — 802.1Q tagging

```elixir
iex> Link.create_vlan(sock, "eth0.42", "eth0", 42)
:ok
```

### bridge — and enslaving links to it

```elixir
iex> Link.create_bridge(sock, "br0")
:ok
iex> Link.set_master(sock, "v0a", "br0")
:ok
iex> Link.set_master(sock, "v0b", "br0")
:ok
```

### dummy — a no-op interface

Useful as a stable address holder or test fixture.

```elixir
iex> Link.create_dummy(sock, "test0")
:ok
```

## Configuring an interface

```elixir
iex> Link.set_up(sock, "eth0.42")
:ok
iex> Link.set_mtu(sock, "eth0.42", 1400)
:ok
iex> Link.set_address(sock, "eth0.42", "02:aa:bb:cc:dd:ee")
:ok
iex> Link.set_name(sock, "eth0.42", "vlan42")
:ok
iex> Link.set_down(sock, "vlan42")
:ok
iex> Link.delete(sock, "vlan42")
:ok
```

## Addresses

IPv4 and IPv6 alike — the family is detected from the address string:

```elixir
iex> Address.add(sock, "vlan42", "10.0.42.5", 24)
:ok
iex> Address.add(sock, "vlan42", "fc00::42:5", 64)
:ok
iex> Address.delete(sock, "vlan42", "10.0.42.5", 24)
:ok
```

## Routes

```elixir
iex> Route.add(sock, "10.99.0.0", 24, "10.0.42.1")        # via a gateway
:ok
iex> Route.add_default(sock, "10.0.42.1")                 # the default route
:ok
iex> Route.delete(sock, "10.99.0.0", 24, "10.0.42.1")
:ok
iex> Route.delete_default(sock, "10.0.42.1")
:ok
```

IPv6 works through the same API — `Route.add(sock, "fd00::", 64, "fc00::1")`
or `Route.add_default(sock, "fc00::1")`; the family is taken from the
gateway and destination, which must agree.

### In-place updates and route options

`replace/5` is create-or-replace: install the route if absent, overwrite it
in place (e.g. a changed gateway) if present. It is idempotent, where `add/5`
is strict (`:eexist` on a duplicate).

```elixir
Route.add(sock, "10.99.0.0", 24, "10.0.42.1")       # strict; errors if present
Route.replace(sock, "10.99.0.0", 24, "10.0.42.9")   # upsert; new gateway in place
```

`add/5`, `replace/5` and `delete/5` take `:table`, `:protocol` and `:metric`.

```elixir
# A route in a custom table, tagged with a dedicated protocol, at a metric.
Route.add(sock, "10.50.0.0", 24, "10.0.42.1", table: 100, protocol: :static, metric: 50)
Route.delete(sock, "10.50.0.0", 24, "10.0.42.1", table: 100, metric: 50)
```

`:protocol` (an integer, or `:kernel`/`:boot`/`:static`/`:ra`/`:dhcp`) is the
ownership tag a reconciler uses to manage only its own routes; `:table`
accepts any value (tables above 255 ride `RTA_TABLE` automatically);
`:metric` is the route's `RTA_PRIORITY`.

## Neighbours

Static ARP (IPv4) or NDP (IPv6) entries — mapping an IP to a MAC on a
specific link:

```elixir
iex> Neighbour.add(sock, "eth0", "10.0.0.10", "02:aa:bb:cc:dd:ee")
:ok
iex> Neighbour.delete(sock, "eth0", "10.0.0.10")
:ok
```

## Policy-routing rules

FIB rules choose which routing table to consult based on selectors. `:table`
is required; the family is inferred from the address selectors (`:from` /
`:to`), defaulting to IPv4 when only non-address selectors are used:

```elixir
# route any packet from 10.0.0.0/24 via table 100
iex> Rule.add(sock, from: "10.0.0.0/24", table: 100)
:ok

# match a firewall mark, set the rule's own priority
iex> Rule.add(sock, fwmark: 0x1, table: 100, priority: 200)
:ok

iex> Rule.delete(sock, from: "10.0.0.0/24", table: 100)
:ok
```

## Reconciliation: diffing observed vs desired

`Linx.Netlink.Rtnl.Diff` computes the minimal create / update / delete ops
that converge observed kernel state onto a desired state — the diff half of
declarative reconciliation (applying them, and observing, come together in
the reconciler). The diff currency is the decoded structs themselves, so
desired and observed are the same type.

Routes own by `rtm_protocol` (two-way): tag desired routes with a protocol,
and the diff considers only observed routes carrying it — connected routes
and other writers are invisible to it. A changed gateway is an `:update`
(applied in place with `Route.replace/5`), not a delete+create.

```elixir
desired = [build_route("10.50.0.0", 24, "10.0.0.1", protocol: :static)]
{:ok, observed} = Route.list(sock)

Diff.routes(desired, observed, :static)
# => [{:create, %Route{...}}, {:update, %Route{...}}, {:delete, %Route{...}}]
```

Everything else (addresses, links, rules, neighbours) has no kernel ownership
field, so deletion is gated three-way by a `last_applied` key set — the keys
this reconciler installed before. Foreign state that merely appeared is left
alone; only keys you previously applied and no longer want are deleted.

```elixir
owned = MapSet.new(Enum.map(previously_applied, &Diff.address_key/1))
Diff.addresses(desired_addrs, observed_addrs, owned)
```

See the `Linx.Netlink.Rtnl.Diff` moduledoc for the full key/ownership table.

### Single-shot reconcile

`Linx.Netlink.Rtnl.Reconcile.reconcile/4` composes the diffs into one ordered,
converging pass for **addresses and routes** on existing interfaces. You author
the desired state by interface name; indices are resolved each pass. It applies
addresses before routes (so a gateway is reachable), is fail-fast, and returns
a report whose `:last_applied` you thread into the next pass.

```elixir
desired = %{
  addresses: [{"eth0", "10.0.0.2", 24}],
  routes: [{"10.50.0.0", 24, "10.0.0.1"}, {:default, "10.0.0.1"}]
}

{:ok, r} = Reconcile.reconcile(sock, desired)
r.converged?        # true once the kernel matches
r.applied           # the ops that ran this pass

# Idempotent — a second pass with the threaded ownership does nothing.
{:ok, r2} = Reconcile.reconcile(sock, desired, r.last_applied)
r2.applied == []
```

Run it on a timer and it self-heals: delete an address by hand and the next
pass restores it; drop one from `desired` and the next pass removes it — but
only addresses *it* installed, never a foreign one that merely appeared.
Routes are owned by `rtm_protocol` (default `76`, override with `:protocol`),
so a route written by anything else is invisible to the reconciler and never
touched. Link lifecycle, rules, and neighbours are out of this pass's scope.

## IP addresses, subnets, and MAC addresses

IP addresses, subnets and MAC addresses are first-class values — `Linx.IP`,
`Linx.IP.Subnet` and `Linx.MAC` structs. Decoded netlink fields carry them
directly, the `~IP` and `~MAC` sigils build literals at compile time, and
verbs accept either the struct or the equivalent string.

```elixir
iex> import Linx.IP
iex> import Linx.MAC

# build values
iex> ~IP"10.0.0.5"
~IP"10.0.0.5"
iex> ~IP"10.0.0.0/24"
~IP"10.0.0.0/24"
iex> ~MAC"02:aa:bb:cc:dd:ee"
~MAC"02:aa:bb:cc:dd:ee"

# subnet math
iex> alias Linx.IP.Subnet
iex> Subnet.contains?(~IP"10.0.0.0/8", ~IP"10.99.0.5")
true
iex> Subnet.network(~IP"10.0.42.5/24")
~IP"10.0.42.0"
iex> Subnet.broadcast(~IP"10.0.42.5/24")
~IP"10.0.42.255"

# verbs accept the structs directly (in addition to strings)
iex> Address.add(sock, "eth0", ~IP"10.0.0.5", 24)
:ok
iex> Link.set_address(sock, "eth0", ~MAC"02:aa:bb:cc:dd:ee")
:ok
```

## Network namespaces

`Rtnl.open/1` chooses the namespace the socket lives in:

```elixir
# the host's own netns (default)
{:ok, host} = Rtnl.open()
{:ok, host} = Rtnl.open(:host)

# inside the netns of process 4242 — e.g. a running container
{:ok, ns} = Rtnl.open({:pid, 4242})

# by file path — anything that names a netns
{:ok, ns} = Rtnl.open({:path, "/var/run/netns/myns"})
```

Every verb then operates in that namespace. To hand a link from one
namespace to another:

```elixir
# host-side: move "web0" into pid 4242's netns
Link.move_to_netns(host, "web0", 4242)

# inside-side: bring loopback up, configure web0, install a default route
Link.set_up(ns, "lo")
Address.add(ns, "web0", "192.168.1.50", 24)
Link.set_up(ns, "web0")
Route.add_default(ns, "192.168.1.1")
```

## Errors

Every netlink verb returns `{:ok, _} | {:error, %Linx.Netlink.Error{}}`:

```elixir
iex> Link.get(sock, "nope0")
{:error, %Linx.Netlink.Error{
   errno: :enodev, code: 19,
   message: "no such interface \"nope0\""
}}
```

`%Linx.Netlink.Error{}` is an `Exception`, so it can be matched, formatted
or raised:

```elixir
iex> {:error, err} = Link.get(sock, "nope0")
iex> err.errno
:enodev
iex> Exception.message(err)
"netlink ENODEV (19): no such interface \"nope0\""
iex> raise err
** (Linx.Netlink.Error) netlink ENODEV (19): no such interface "nope0"
```

When the kernel attaches a description through extended ack
(`NLMSGERR_ATTR_MSG`), it surfaces in `:message` automatically. When it
does not, the verb synthesizes a useful one — `create_macvlan` for example
sharpens "no such interface" into "no such parent interface" so the caller
knows which name was at fault.
