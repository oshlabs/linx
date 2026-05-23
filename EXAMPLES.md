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
```

### Neighbours (ARP / NDP table)

```elixir
iex> alias Linx.Netlink.Rtnl.Neighbour

iex> {:ok, neighbours} = Neighbour.list(sock)
iex> neighbours
[#Linx.Netlink.Rtnl.Neighbour<192.168.1.1 -> aa:bb:cc:dd:ee:ff ifindex=2>, ...]
```

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
